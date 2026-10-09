"""Policy model (validated with pydantic) and the evaluation engine.

Evaluation semantics, for one tool call (tool_id = "<server>.<tool>"):

1. A rule *matches* when one of its ``tools`` globs matches the tool id, one of
   its ``agents`` globs matches the agent id, and every ``when`` condition holds.
2. Among matching rules, **deny wins**: any matching ``action: deny`` denies.
3. Every matching rule's ``args`` constraints are checked; any violation denies.
4. Every matching rule's ``rate_limit`` / ``spend_limit`` is checked; exceeding denies.
5. Otherwise, if any matching rule says ``require_approval``, a human must approve.
6. Otherwise, if any matching rule says ``allow`` the call is allowed; if no rule
   gave a verdict, ``default_action`` applies.
"""

from __future__ import annotations

import difflib
import fnmatch
import math
import posixpath
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from agent_guard.limits import LimitTracker

Action = Literal["allow", "deny", "require_approval"]
PiiMode = Literal["redact", "block", "log_only", "off"]
PII_DETECTORS = ("email", "phone", "credit_card", "iban", "ssn")


class PolicyError(ValueError):
    """Invalid policy, with a human-readable message."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _as_list(v: Any) -> Any:
    return [v] if isinstance(v, str) else v


class ArgConstraint(_Strict):
    """Constraints on one argument. All given constraints must hold."""

    required: bool = Field(default=False, description="The argument must be present.")
    type: Literal["string", "number", "integer", "boolean", "array", "object"] | None = None
    min: float | None = Field(default=None, description="Numeric minimum (inclusive).")
    max: float | None = Field(default=None, description="Numeric maximum (inclusive).")
    min_length: int | None = Field(default=None, ge=0)
    max_length: int | None = Field(default=None, ge=0)
    regex: str | None = Field(default=None, description="The whole string value must match.")
    not_regex: str | None = Field(default=None, description="Denied if this pattern is found anywhere.")
    enum: list[Any] | None = Field(default=None, description="Value must be one of these.")
    path_under: list[str] | None = Field(
        default=None, description="Path (lexically normalized) must be inside one of these directories."
    )

    _path_under = field_validator("path_under", mode="before")(_as_list)

    @field_validator("regex", "not_regex")
    @classmethod
    def _compiles(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"invalid regular expression {v!r}: {e}") from e
        return v

    @model_validator(mode="after")
    def _ranges(self) -> ArgConstraint:
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError(f"min ({self.min}) is greater than max ({self.max})")
        if self.min_length is not None and self.max_length is not None and self.min_length > self.max_length:
            raise ValueError("min_length is greater than max_length")
        return self

    def violation(self, name: str, present: bool, value: Any) -> str | None:
        """Return a human-readable violation, or None if the value satisfies the constraint."""
        if not present:
            return f"argument '{name}' is required" if self.required else None
        if self.type is not None and not _type_ok(self.type, value):
            return f"argument '{name}' must be of type {self.type}"
        if self.min is not None or self.max is not None:
            num = _number(value)
            if num is None:
                return f"argument '{name}' must be a number"
            if self.min is not None and num < self.min:
                return f"argument '{name}'={_fmt(value)} is below the minimum of {_fmt(self.min)}"
            if self.max is not None and num > self.max:
                return f"argument '{name}'={_fmt(value)} exceeds the maximum of {_fmt(self.max)}"
        if self.min_length is not None or self.max_length is not None:
            try:
                n = len(value)
            except TypeError:
                return f"argument '{name}' has no length"
            if self.min_length is not None and n < self.min_length:
                return f"argument '{name}' is shorter than {self.min_length}"
            if self.max_length is not None and n > self.max_length:
                return f"argument '{name}' is longer than {self.max_length}"
        if self.regex is not None and (not isinstance(value, str) or re.fullmatch(self.regex, value) is None):
            return f"argument '{name}'={_fmt(value)} does not match the required pattern {self.regex!r}"
        if self.not_regex is not None and isinstance(value, str) and re.search(self.not_regex, value):
            return f"argument '{name}' contains a forbidden pattern {self.not_regex!r}"
        if self.enum is not None and value not in self.enum:
            return f"argument '{name}'={_fmt(value)} is not one of {self.enum}"
        if self.path_under is not None:
            if not isinstance(value, str):
                return f"argument '{name}' must be a path string"
            if not any(path_is_under(value, base) for base in self.path_under):
                return f"argument '{name}'={value!r} is outside the allowed directories {self.path_under}"
        return None


class RateLimit(_Strict):
    calls: int = Field(gt=0, description="Maximum forwarded calls per window.")
    per_seconds: float = Field(gt=0, description="Sliding window length in seconds.")
    scope: Literal["tool_agent", "tool", "agent", "global"] = "tool_agent"


class SpendLimit(_Strict):
    budget: float = Field(gt=0, description="Maximum total cost per window.")
    per_seconds: float = Field(gt=0, description="Sliding window length in seconds.")
    cost_arg: str | None = Field(default=None, description="Numeric argument holding the cost (e.g. 'amount').")
    cost_per_call: float | None = Field(default=None, ge=0, description="Fixed cost added to every call.")
    scope: Literal["tool_agent", "tool", "agent", "global"] = "agent"

    @model_validator(mode="after")
    def _needs_cost(self) -> SpendLimit:
        if self.cost_arg is None and self.cost_per_call is None:
            raise ValueError("spend_limit needs cost_arg and/or cost_per_call")
        return self

    def cost(self, args: dict[str, Any]) -> float | None:
        total = self.cost_per_call or 0.0
        if self.cost_arg is not None:
            present, value = get_arg(args, self.cost_arg)
            num = _number(value) if present else None
            if num is None or num < 0:
                return None
            total += num
        return total


class Rule(_Strict):
    name: str | None = None
    tools: list[str] = Field(min_length=1, description="Glob patterns matched against '<server>.<tool>'.")
    agents: list[str] = Field(default_factory=lambda: ["*"], description="Glob patterns matched against agent id.")
    when: dict[str, ArgConstraint] = Field(default_factory=dict, description="Rule applies only if all hold.")
    action: Action | None = Field(default=None, description="Verdict; omit for constraint/limit-only rules.")
    args: dict[str, ArgConstraint] = Field(default_factory=dict, description="Constraints; violation denies.")
    rate_limit: RateLimit | None = None
    spend_limit: SpendLimit | None = None
    reason: str | None = Field(default=None, description="Message shown to the agent when this rule denies.")
    approval_timeout_seconds: float | None = Field(default=None, gt=0)

    _lists = field_validator("tools", "agents", mode="before")(_as_list)

    def label(self, index: int) -> str:
        return self.name or f"rules[{index}]"

    def matches_tool_agent(self, tool_id: str, agent: str) -> bool:
        return any(fnmatch.fnmatchcase(tool_id, p) for p in self.tools) and any(
            fnmatch.fnmatchcase(agent, p) for p in self.agents
        )

    def matches(self, tool_id: str, agent: str, args: dict[str, Any]) -> bool:
        if not self.matches_tool_agent(tool_id, agent):
            return False
        for name, cond in self.when.items():
            present, value = get_arg(args, name)
            if not present or cond.violation(name, present, value) is not None:
                return False
        return True


class PiiRule(_Strict):
    """PII handling for matching tools. The first matching entry wins."""

    tools: list[str] = Field(default_factory=lambda: ["*"])
    detectors: list[Literal["email", "phone", "credit_card", "iban", "ssn"]] = Field(
        default_factory=lambda: list(PII_DETECTORS)
    )
    arguments: PiiMode = "off"
    results: PiiMode = "redact"

    _lists = field_validator("tools", mode="before")(_as_list)

    @field_validator("arguments", "results", mode="before")
    @classmethod
    def _yaml_off(cls, v: Any) -> Any:
        # YAML 1.1 parses a bare `off` as boolean false.
        return "off" if v is False else v


class Policy(_Strict):
    version: Literal[1] = 1
    default_action: Literal["allow", "deny"] = "allow"
    rules: list[Rule] = Field(default_factory=list)
    pii: list[PiiRule] = Field(default_factory=list)

    def pii_for(self, tool_id: str) -> PiiRule | None:
        for entry in self.pii:
            if any(fnmatch.fnmatchcase(tool_id, p) for p in entry.tools):
                return entry
        return None


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


@dataclass
class Decision:
    action: Action
    reason: str = ""
    rule: str | None = None
    matched: list[str] = field(default_factory=list)
    approval_timeout: float | None = None
    _limit_rules: list[tuple[int, Rule]] = field(default_factory=list, repr=False)

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


DENY_SUFFIX = " This is a policy decision by agent-guard; do not retry the same call."


class PolicyEngine:
    def __init__(self, policy: Policy | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        self.policy = policy or Policy()
        self.limits = LimitTracker(clock)

    def statically_denied(self, tool_id: str, agent: str) -> bool:
        """True if an unconditional deny rule always blocks this tool for this agent."""
        for rule in self.policy.rules:
            if rule.action == "deny" and not rule.when and rule.matches(tool_id, agent, {}):
                return True
        return self.policy.default_action == "deny" and not any(
            r.action in ("allow", "require_approval") and r.matches_tool_agent(tool_id, agent)
            for r in self.policy.rules
        )

    def evaluate(self, tool_id: str, agent: str, args: dict[str, Any]) -> Decision:
        matched = [(i, r) for i, r in enumerate(self.policy.rules) if r.matches(tool_id, agent, args)]
        labels = [r.label(i) for i, r in matched]

        def deny(reason: str, rule: str | None) -> Decision:
            return Decision("deny", f"agent-guard denied {tool_id}: {reason}.{DENY_SUFFIX}", rule, labels)

        for i, r in matched:
            if r.action == "deny":
                return deny(r.reason or "tool is not permitted by policy", r.label(i))
        for i, r in matched:
            for name, constraint in r.args.items():
                present, value = get_arg(args, name)
                problem = constraint.violation(name, present, value)
                if problem:
                    return deny(r.reason + f" ({problem})" if r.reason else problem, r.label(i))
        limit_rules = [(i, r) for i, r in matched if r.rate_limit or r.spend_limit]
        problem_rule = self.limits.check(limit_rules, tool_id, agent, args)
        if problem_rule:
            problem, label = problem_rule
            return deny(problem, label)

        approval = [(i, r) for i, r in matched if r.action == "require_approval"]
        if approval:
            i, r = approval[0]
            timeouts = [x.approval_timeout_seconds for _, x in approval if x.approval_timeout_seconds]
            return Decision(
                "require_approval",
                r.reason or "this call requires human approval",
                r.label(i),
                labels,
                approval_timeout=min(timeouts) if timeouts else None,
                _limit_rules=limit_rules,
            )
        allow = [(i, r) for i, r in matched if r.action == "allow"]
        if allow:
            return Decision("allow", "allowed by rule", allow[0][1].label(allow[0][0]), labels, _limit_rules=limit_rules)
        if self.policy.default_action == "deny":
            return deny("no rule allows this tool (default_action: deny)", None)
        return Decision("allow", "allowed by default", None, labels, _limit_rules=limit_rules)

    def acquire(self, decision: Decision, tool_id: str, agent: str, args: dict[str, Any]) -> str | None:
        """Atomically re-check and consume rate/spend budget. Returns a deny message or None."""
        problem = self.limits.check_and_record(decision._limit_rules, tool_id, agent, args)
        if problem:
            return f"agent-guard denied {tool_id}: {problem[0]}.{DENY_SUFFIX}"
        return None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def get_arg(args: dict[str, Any], name: str) -> tuple[bool, Any]:
    """Look up an argument; dotted names ('customer.email') descend into objects."""
    if name in args:
        return True, args[name]
    cur: Any = args
    for part in name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def path_is_under(value: str, base: str) -> bool:
    """Lexical check (no filesystem access): is ``value`` inside ``base`` after normalization?"""
    v = posixpath.normpath(value.replace("\\", "/"))
    b = posixpath.normpath(base.replace("\\", "/"))
    if v.startswith("../") or v == "..":
        return False
    if b in (".", ""):
        return not posixpath.isabs(v)
    return v == b or v.startswith(b.rstrip("/") + "/")


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return float(value)
    return None


def _type_ok(kind: str, value: Any) -> bool:
    return {
        "string": isinstance(value, str),
        "number": _number(value) is not None,
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }[kind]


def _fmt(value: Any) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    s = repr(value) if isinstance(value, str) else str(value)
    return s if len(s) <= 60 else s[:57] + "..."


_KNOWN_KEYS = sorted(
    set(ArgConstraint.model_fields)
    | set(RateLimit.model_fields)
    | set(SpendLimit.model_fields)
    | set(Rule.model_fields)
    | set(PiiRule.model_fields)
    | set(Policy.model_fields)
)


def format_policy_error(err: ValidationError, source: str) -> str:
    lines = [f"Invalid policy in {source}:"]
    for e in err.errors():
        loc = ".".join(str(x) for x in e["loc"]) or "<root>"
        msg = e["msg"]
        if e["type"] == "extra_forbidden":
            key = str(e["loc"][-1])
            close = difflib.get_close_matches(key, _KNOWN_KEYS, n=1)
            msg = f"unknown key {key!r}" + (f" (did you mean {close[0]!r}?)" if close else "")
        elif e["type"] == "literal_error":
            msg = f"{msg} (got {e.get('input')!r})"
        lines.append(f"  - {loc}: {msg}")
    return "\n".join(lines)


def load_policy_data(data: Any, source: str = "<policy>") -> Policy:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PolicyError(f"Invalid policy in {source}: top level must be a mapping")
    try:
        return Policy.model_validate(data)
    except ValidationError as e:
        raise PolicyError(format_policy_error(e, source)) from e


def load_policy_file(path: Path) -> Policy:
    if not path.is_file():
        raise PolicyError(f"Policy file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise PolicyError(f"Could not parse YAML in {path}: {e}") from e
    return load_policy_data(data, source=str(path))
