from __future__ import annotations

from pathlib import Path

import pytest

from agent_guard.policy import PolicyEngine, PolicyError, load_policy_data, load_policy_file, path_is_under

ROOT = Path(__file__).resolve().parent.parent


def engine(policy: dict) -> PolicyEngine:
    return PolicyEngine(load_policy_data(policy))


def test_default_allow_when_no_rules() -> None:
    d = engine({}).evaluate("files.read_file", "a", {})
    assert d.action == "allow"


def test_default_deny() -> None:
    d = engine({"default_action": "deny"}).evaluate("files.read_file", "a", {})
    assert d.action == "deny"
    assert "default_action: deny" in d.reason


def test_glob_allow_deny_and_deny_wins() -> None:
    e = engine(
        {
            "rules": [
                {"tools": ["files.*"], "action": "allow"},
                {"name": "no-delete", "tools": "files.delete_*", "action": "deny", "reason": "nope"},
            ]
        }
    )
    assert e.evaluate("files.read_file", "a", {}).allowed
    d = e.evaluate("files.delete_file", "a", {"path": "x"})
    assert d.action == "deny" and d.rule == "no-delete"
    assert "nope" in d.reason and "do not retry" in d.reason


def test_agent_scoping() -> None:
    e = engine({"rules": [{"tools": "*", "agents": ["intern-*"], "action": "deny"}]})
    assert e.evaluate("payments.refund", "intern-bot", {}).action == "deny"
    assert e.evaluate("payments.refund", "senior-bot", {}).action == "allow"


@pytest.mark.parametrize(
    ("args", "ok", "fragment"),
    [
        ({"amount": 50, "customer_id": "cus_abc"}, True, ""),
        ({"amount": 900, "customer_id": "cus_abc"}, False, "exceeds the maximum of 500"),
        ({"amount": 0, "customer_id": "cus_abc"}, False, "below the minimum"),
        ({"amount": "50", "customer_id": "cus_abc"}, False, "must be of type number"),
        ({"amount": 50, "customer_id": "CUS-1"}, False, "does not match"),
        ({"customer_id": "cus_abc"}, False, "'amount' is required"),
        ({"amount": 50, "customer_id": "cus_abc", "currency": "XYZ"}, False, "not one of"),
    ],
)
def test_argument_constraints(args: dict, ok: bool, fragment: str) -> None:
    e = engine(
        {
            "rules": [
                {
                    "tools": "payments.refund",
                    "args": {
                        "amount": {"required": True, "type": "number", "min": 0.01, "max": 500},
                        "customer_id": {"regex": "cus_[a-z0-9]+"},
                        "currency": {"enum": ["USD", "EUR"]},
                    },
                }
            ]
        }
    )
    d = e.evaluate("payments.refund", "a", args)
    assert d.allowed is ok, d.reason
    assert fragment in d.reason


def test_not_regex_and_length() -> None:
    e = engine({"rules": [{"tools": "db.query", "args": {"sql": {"not_regex": "(?i)drop\\s+table", "max_length": 20}}}]})
    assert e.evaluate("db.query", "a", {"sql": "select 1"}).allowed
    assert "forbidden pattern" in e.evaluate("db.query", "a", {"sql": "DROP TABLE x"}).reason
    assert "longer than" in e.evaluate("db.query", "a", {"sql": "select " + "x" * 30}).reason


def test_nested_argument_lookup() -> None:
    e = engine({"rules": [{"tools": "*", "args": {"customer.tier": {"enum": ["gold"]}}}]})
    assert e.evaluate("t.x", "a", {"customer": {"tier": "gold"}}).allowed
    assert not e.evaluate("t.x", "a", {"customer": {"tier": "free"}}).allowed


@pytest.mark.parametrize(
    ("value", "base", "expected"),
    [
        ("notes/a.txt", "notes", True),
        ("notes", "notes", True),
        ("notes/../secret.txt", "notes", False),
        ("../notes/a.txt", "notes", False),
        ("notesX/a.txt", "notes", False),
        ("notes\\sub\\a.txt", "notes", True),
        ("/etc/passwd", "notes", False),
        ("/srv/data/x", "/srv/data", True),
        ("a.txt", ".", True),
        ("../a.txt", ".", False),
    ],
)
def test_path_is_under(value: str, base: str, expected: bool) -> None:
    assert path_is_under(value, base) is expected


def test_path_under_constraint() -> None:
    e = engine({"rules": [{"tools": "files.write_file", "args": {"path": {"path_under": "notes"}}}]})
    assert e.evaluate("files.write_file", "a", {"path": "notes/x.md"}).allowed
    d = e.evaluate("files.write_file", "a", {"path": "notes/../../etc/x"})
    assert not d.allowed and "outside the allowed directories" in d.reason


def test_when_conditions_and_require_approval() -> None:
    e = engine(
        {
            "rules": [
                {"tools": "payments.refund", "action": "allow"},
                {
                    "name": "big",
                    "tools": "payments.refund",
                    "when": {"amount": {"min": 100}},
                    "action": "require_approval",
                    "approval_timeout_seconds": 5,
                },
            ]
        }
    )
    assert e.evaluate("payments.refund", "a", {"amount": 20}).action == "allow"
    d = e.evaluate("payments.refund", "a", {"amount": 250})
    assert d.action == "require_approval" and d.rule == "big" and d.approval_timeout == 5
    # a condition on a missing argument does not match
    assert e.evaluate("payments.refund", "a", {}).action == "allow"


def test_statically_denied() -> None:
    e = engine(
        {
            "default_action": "deny",
            "rules": [
                {"tools": "files.read_file", "action": "allow"},
                {"tools": "files.delete_file", "action": "deny"},
                {"tools": "payments.refund", "when": {"amount": {"min": 1}}, "action": "deny"},
            ],
        }
    )
    assert e.statically_denied("files.delete_file", "a")
    assert e.statically_denied("files.write_file", "a")  # default deny and nothing allows it
    assert not e.statically_denied("files.read_file", "a")


@pytest.mark.parametrize(
    ("policy", "fragment"),
    [
        ({"rules": [{"tools": "x", "action": "maybe"}]}, "rules.0.action"),
        ({"rules": [{"tools": "x", "args": {"a": {"regex": "("}}}]}, "invalid regular expression"),
        ({"rules": [{"tools": "x", "args": {"a": {"min": 5, "max": 1}}}]}, "min (5.0) is greater than max"),
        ({"rules": [{"tools": "x", "rate_limt": {"calls": 1}}]}, "did you mean 'rate_limit'"),
        ({"rules": [{"tools": "x", "spend_limit": {"budget": 10, "per_seconds": 60}}]}, "cost_arg and/or cost_per_call"),
        ({"rules": [{"tools": []}]}, "rules.0.tools"),
        ({"version": 2}, "version"),
        (["not", "a", "mapping"], "top level must be a mapping"),
    ],
)
def test_validation_errors_are_helpful(policy: object, fragment: str) -> None:
    with pytest.raises(PolicyError) as exc:
        load_policy_data(policy, source="test.yaml")
    assert fragment in str(exc.value)
    assert "test.yaml" in str(exc.value)


@pytest.mark.parametrize("path", sorted((ROOT / "examples" / "policies").glob("*.yaml")), ids=lambda p: p.name)
def test_example_policies_are_valid(path: Path) -> None:
    load_policy_file(path)
