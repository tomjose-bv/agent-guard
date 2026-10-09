"""Sliding-window rate and spend limits (in-memory, per proxy process)."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_guard.policy import Rule


def _scope_key(scope: str, tool_id: str, agent: str) -> str:
    return {"tool_agent": f"{tool_id}|{agent}", "tool": tool_id, "agent": agent, "global": "*"}[scope]


class SlidingWindow:
    """Events (timestamp, amount) within the last ``window`` seconds."""

    def __init__(self, window: float) -> None:
        self.window = window
        self.events: deque[tuple[float, float]] = deque()
        self.total = 0.0

    def _expire(self, now: float) -> None:
        while self.events and self.events[0][0] <= now - self.window:
            _, amount = self.events.popleft()
            self.total -= amount
        if not self.events:
            self.total = 0.0  # avoid float drift

    def count(self, now: float) -> int:
        self._expire(now)
        return len(self.events)

    def sum(self, now: float) -> float:
        self._expire(now)
        return self.total

    def retry_after(self, now: float) -> float:
        return max(0.0, self.events[0][0] + self.window - now) if self.events else 0.0

    def add(self, now: float, amount: float) -> None:
        self.events.append((now, amount))
        self.total += amount


class LimitTracker:
    def __init__(self, clock: Callable[[], float]) -> None:
        self.clock = clock
        self._windows: dict[tuple[str, int, str], SlidingWindow] = {}

    def _window(self, kind: str, index: int, key: str, length: float) -> SlidingWindow:
        k = (kind, index, key)
        w = self._windows.get(k)
        if w is None:
            w = self._windows[k] = SlidingWindow(length)
        return w

    def _evaluate(
        self, rules: Sequence[tuple[int, Rule]], tool_id: str, agent: str, args: dict[str, Any], record: bool
    ) -> tuple[str, str] | None:
        now = self.clock()
        pending: list[tuple[SlidingWindow, float]] = []
        for index, rule in rules:
            label = rule.label(index)
            if rule.rate_limit:
                rl = rule.rate_limit
                w = self._window("rate", index, _scope_key(rl.scope, tool_id, agent), rl.per_seconds)
                if w.count(now) >= rl.calls:
                    return (
                        f"rate limit exceeded ({rl.calls} calls per {_secs(rl.per_seconds)}, scope {rl.scope}); "
                        f"retry in {w.retry_after(now):.0f}s",
                        label,
                    )
                pending.append((w, 1.0))
            if rule.spend_limit:
                sl = rule.spend_limit
                cost = sl.cost(args)
                if cost is None:
                    return (f"cannot determine cost: argument '{sl.cost_arg}' must be a non-negative number", label)
                w = self._window("spend", index, _scope_key(sl.scope, tool_id, agent), sl.per_seconds)
                spent = w.sum(now)
                if spent + cost > sl.budget + 1e-9:
                    return (
                        f"spend limit exceeded: this call costs {cost:g} but only {max(0.0, sl.budget - spent):g} "
                        f"of the {sl.budget:g} budget per {_secs(sl.per_seconds)} remains",
                        label,
                    )
                pending.append((w, cost))
        if record:
            for w, amount in pending:
                w.add(now, amount)
        return None

    def check(self, rules: Sequence[tuple[int, Rule]], tool_id: str, agent: str, args: dict[str, Any]) -> tuple[str, str] | None:
        return self._evaluate(rules, tool_id, agent, args, record=False)

    def check_and_record(
        self, rules: Sequence[tuple[int, Rule]], tool_id: str, agent: str, args: dict[str, Any]
    ) -> tuple[str, str] | None:
        return self._evaluate(rules, tool_id, agent, args, record=True)


def _secs(s: float) -> str:
    for unit, n in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if s >= n and s % n == 0:
            k = int(s // n)
            return f"{k} {unit}{'s' if k != 1 else ''}"
    return f"{s:g}s"
