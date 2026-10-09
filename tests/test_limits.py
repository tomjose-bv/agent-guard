from __future__ import annotations

from agent_guard.policy import PolicyEngine, load_policy_data


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def make(policy: dict) -> tuple[PolicyEngine, FakeClock]:
    clock = FakeClock()
    return PolicyEngine(load_policy_data(policy), clock=clock), clock


def call(e: PolicyEngine, tool: str, agent: str, args: dict) -> str | None:
    """Evaluate + acquire like the proxy does; return the deny reason or None."""
    d = e.evaluate(tool, agent, args)
    if not d.allowed:
        return d.reason
    return e.acquire(d, tool, agent, args)


def test_rate_limit_sliding_window() -> None:
    e, clock = make({"rules": [{"tools": "p.lookup", "rate_limit": {"calls": 3, "per_seconds": 60}}]})
    for _ in range(3):
        assert call(e, "p.lookup", "a", {}) is None
    reason = call(e, "p.lookup", "a", {})
    assert reason and "rate limit exceeded (3 calls per 1 minute" in reason
    clock.t += 30
    assert call(e, "p.lookup", "a", {}) is not None
    clock.t += 31  # the first calls fall out of the window
    assert call(e, "p.lookup", "a", {}) is None


def test_rate_limit_scopes() -> None:
    e, _ = make({"rules": [{"tools": "p.*", "rate_limit": {"calls": 1, "per_seconds": 60, "scope": "tool_agent"}}]})
    assert call(e, "p.x", "a", {}) is None
    assert call(e, "p.x", "b", {}) is None  # other agent has its own bucket
    assert call(e, "p.y", "a", {}) is None  # other tool has its own bucket
    assert call(e, "p.x", "a", {}) is not None

    e, _ = make({"rules": [{"tools": "p.*", "rate_limit": {"calls": 1, "per_seconds": 60, "scope": "agent"}}]})
    assert call(e, "p.x", "a", {}) is None
    assert call(e, "p.y", "a", {}) is not None
    assert call(e, "p.y", "b", {}) is None

    e, _ = make({"rules": [{"tools": "p.*", "rate_limit": {"calls": 1, "per_seconds": 60, "scope": "global"}}]})
    assert call(e, "p.x", "a", {}) is None
    assert call(e, "p.y", "b", {}) is not None


def test_denied_calls_do_not_consume_rate_budget() -> None:
    e, _ = make(
        {"rules": [{"tools": "p.x", "rate_limit": {"calls": 1, "per_seconds": 60}, "args": {"n": {"max": 5}}}]}
    )
    assert call(e, "p.x", "a", {"n": 10}) is not None  # constraint violation
    assert call(e, "p.x", "a", {"n": 1}) is None  # budget still available


def test_spend_limit_from_argument() -> None:
    e, clock = make(
        {"rules": [{"tools": "pay.refund", "spend_limit": {"cost_arg": "amount", "budget": 100, "per_seconds": 3600}}]}
    )
    assert call(e, "pay.refund", "a", {"amount": 60}) is None
    reason = call(e, "pay.refund", "a", {"amount": 50})
    assert reason and "spend limit exceeded" in reason and "only 40" in reason
    assert call(e, "pay.refund", "a", {"amount": 40}) is None  # exactly the remaining budget
    clock.t += 3601
    assert call(e, "pay.refund", "a", {"amount": 100}) is None


def test_spend_limit_fixed_cost_and_bad_cost_arg() -> None:
    e, _ = make({"rules": [{"tools": "llm.*", "spend_limit": {"cost_per_call": 0.25, "budget": 1, "per_seconds": 60}}]})
    for _ in range(4):
        assert call(e, "llm.complete", "a", {}) is None
    assert call(e, "llm.complete", "a", {}) is not None

    e, _ = make({"rules": [{"tools": "pay.*", "spend_limit": {"cost_arg": "amount", "budget": 10, "per_seconds": 60}}]})
    reason = call(e, "pay.refund", "a", {"amount": "lots"})
    assert reason and "cannot determine cost" in reason
    assert call(e, "pay.refund", "a", {"amount": -5}) is not None


def test_acquire_rechecks_after_delay() -> None:
    """A decision taken earlier (e.g. while awaiting approval) is re-checked on acquire."""
    e, _ = make({"rules": [{"tools": "p.x", "rate_limit": {"calls": 1, "per_seconds": 60}}]})
    d1 = e.evaluate("p.x", "a", {})
    d2 = e.evaluate("p.x", "a", {})
    assert d1.allowed and d2.allowed
    assert e.acquire(d1, "p.x", "a", {}) is None
    assert e.acquire(d2, "p.x", "a", {}) is not None
