"""Proxy configuration (YAML) — which upstream servers to launch and where state lives."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agent_guard.policy import Policy, load_policy_data

DEFAULT_CONFIG_NAME = "agent-guard.yaml"
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


class ConfigError(Exception):
    """Raised for missing/invalid configuration, with a human-readable message."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UpstreamServer(_Strict):
    """An upstream MCP server launched over stdio."""

    command: str = Field(description="Executable to launch. 'python' means the interpreter running agent-guard.")
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict, description="Extra environment variables for the server.")
    cwd: str | None = Field(default=None, description="Working directory; defaults to the config file's directory.")
    enabled: bool = True


class AuditSettings(_Strict):
    path: str | None = Field(default=None, description="JSONL audit log path; default <state_dir>/audit.jsonl")
    log_arguments: bool = Field(default=True, description="Record (post-redaction) arguments in the log.")
    log_results: bool = Field(default=True, description="Record a truncated (post-redaction) result preview.")
    result_preview_chars: int = Field(default=500, ge=0)


class ApprovalSettings(_Strict):
    dir: str | None = Field(default=None, description="Pending-approval directory; default <state_dir>/approvals")
    timeout_seconds: float = Field(default=120.0, gt=0, description="Pending calls are denied after this long.")
    poll_interval_seconds: float = Field(default=0.25, gt=0)


class Config(_Strict):
    agent_id: str = Field(default="default", description="Identity of the agent using this proxy instance.")
    namespace: bool = Field(default=True, description="Expose tools as <server><sep><tool>.")
    namespace_separator: str = "__"
    hide_denied_tools: bool = Field(default=True, description="Omit tools that policy always denies from tools/list.")
    state_dir: str = ".agent-guard"
    servers: dict[str, UpstreamServer]
    policy: str | dict[str, Any] | None = Field(default=None, description="Policy file path or inline policy.")
    audit: AuditSettings = Field(default_factory=AuditSettings)
    approvals: ApprovalSettings = Field(default_factory=ApprovalSettings)

    # Set by load_config; not part of the YAML schema.
    base_dir: Path = Field(default_factory=Path.cwd, exclude=True)

    @field_validator("servers")
    @classmethod
    def _check_servers(cls, v: dict[str, UpstreamServer]) -> dict[str, UpstreamServer]:
        if not v:
            raise ValueError("at least one upstream server is required")
        for name in v:
            if not _NAME.match(name):
                raise ValueError(f"server name {name!r} may only contain letters, digits, '_' and '-'")
        return v

    # ---- resolved paths -------------------------------------------------
    def resolve(self, p: str | os.PathLike[str]) -> Path:
        path = Path(p).expanduser()
        return path if path.is_absolute() else (self.base_dir / path)

    @property
    def state_path(self) -> Path:
        return self.resolve(self.state_dir)

    @property
    def audit_path(self) -> Path:
        return self.resolve(self.audit.path) if self.audit.path else self.state_path / "audit.jsonl"

    @property
    def approvals_path(self) -> Path:
        return self.resolve(self.approvals.dir) if self.approvals.dir else self.state_path / "approvals"

    def load_policy(self) -> Policy:
        if self.policy is None:
            return Policy()
        if isinstance(self.policy, dict):
            return load_policy_data(self.policy, source="<inline policy>")
        path = self.resolve(self.policy)
        from agent_guard.policy import load_policy_file

        return load_policy_file(path)

    def server_command(self, name: str) -> tuple[str, list[str], dict[str, str], str]:
        """Return (command, args, env, cwd) for an upstream, with variables expanded."""
        srv = self.servers[name]
        command = _expand(srv.command, self.base_dir)
        if command in ("python", "python3", "py"):
            command = sys.executable
        args = [_expand(a, self.base_dir) for a in srv.args]
        env = {k: _expand(v, self.base_dir) for k, v in srv.env.items()}
        cwd = str(self.resolve(_expand(srv.cwd, self.base_dir))) if srv.cwd else str(self.base_dir)
        return command, args, env, cwd


def _expand(value: str, base_dir: Path) -> str:
    """Expand ${VAR} from the environment; ${CONFIG_DIR} is the config file's directory."""

    def repl(m: re.Match[str]) -> str:
        key = m.group(1)
        if key == "CONFIG_DIR":
            return str(base_dir)
        if key == "PYTHON":
            return sys.executable
        return os.environ.get(key, "")

    return _VAR.sub(repl, value)


def format_validation_error(err: ValidationError, source: str) -> str:
    lines = [f"Invalid configuration in {source}:"]
    for e in err.errors():
        loc = ".".join(str(x) for x in e["loc"]) or "<root>"
        lines.append(f"  - {loc}: {e['msg']}")
    return "\n".join(lines)


def find_config(path: str | os.PathLike[str] | None) -> Path:
    if path:
        return Path(path)
    env = os.environ.get("AGENT_GUARD_CONFIG")
    if env:
        return Path(env)
    return Path.cwd() / DEFAULT_CONFIG_NAME


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    cfg_path = find_config(path)
    if not cfg_path.is_file():
        raise ConfigError(
            f"Config file not found: {cfg_path}. Pass -c/--config or set AGENT_GUARD_CONFIG "
            f"(see agent-guard.yaml in the repository for an example)."
        )
    try:
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Could not parse YAML in {cfg_path}: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{cfg_path}: top level must be a mapping")
    try:
        cfg = Config.model_validate(data)
    except ValidationError as e:
        raise ConfigError(format_validation_error(e, str(cfg_path))) from e
    cfg.base_dir = cfg_path.resolve().parent
    return cfg
