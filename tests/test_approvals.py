from __future__ import annotations

import sys
from pathlib import Path

import anyio
import pytest
from mcp import Client, StdioServerParameters

from agent_guard.approvals import ApprovalError, ApprovalStore
from agent_guard.cli import main as cli_main
from conftest import write_config


def make_req(store: ApprovalStore, timeout: float = 30):
    return store.create("payments.refund", "bot", {"amount": 250}, "needs a human", "big", timeout)


async def test_approve_flow(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    req = make_req(store)
    assert [r.id for r in store.list()] == [req.id]

    async def approve_soon() -> None:
        await anyio.sleep(0.2)
        store.decide(req.id, True, by="alice", note="ok")

    async with anyio.create_task_group() as tg:
        tg.start_soon(approve_soon)
        outcome, decision = await store.wait(req, poll_interval=0.05)
    assert outcome == "approved"
    assert decision and decision.by == "alice"
    assert store.list() == []
    assert store.get(req.id).status == "approved"  # type: ignore[union-attr]


async def test_deny_flow(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    req = make_req(store)
    store.decide(req.id, False, by="bob", note="too large")
    outcome, decision = await store.wait(req, poll_interval=0.05)
    assert outcome == "denied" and decision and decision.note == "too large"


async def test_timeout_means_deny(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    req = make_req(store, timeout=0.3)
    ticks: list[float] = []

    async def on_tick(remaining: float) -> None:
        ticks.append(remaining)

    outcome, decision = await store.wait(req, poll_interval=0.05, on_tick=on_tick, tick_every=0.1)
    assert outcome == "timeout" and decision is None
    assert ticks
    with pytest.raises(ApprovalError, match="already timeout"):
        store.decide(req.id, True, by="late")


def test_decide_errors(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    with pytest.raises(ApprovalError, match="no approval request"):
        store.decide("deadbeef", True, by="x")
    with pytest.raises(ApprovalError, match="invalid approval id"):
        store.decide("../etc", True, by="x")
    req = make_req(store)
    store.decide(req.id, True, by="x")
    with pytest.raises(ApprovalError, match="already has a decision"):
        store.decide(req.id, False, by="y")


def test_cli_pending_and_approve(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = write_config(tmp_path)
    store = ApprovalStore(tmp_path / "state" / "approvals")
    req = make_req(store)
    assert cli_main(["pending", "-c", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert req.id in out and "payments.refund" in out
    assert cli_main(["approve", req.id, "-c", str(cfg), "--by", "tester"]) == 0
    assert store.decision(req.id).approved  # type: ignore[union-attr]
    assert cli_main(["deny", req.id, "-c", str(cfg)]) == 1  # already decided


POLICY = {
    "rules": [
        {"tools": "payments.refund", "when": {"amount": {"min": 100}}, "action": "require_approval",
         "reason": "big refund"},
    ]
}  # fmt: skip


def proxy(cfg: Path) -> Client:
    return Client(StdioServerParameters(command=sys.executable, args=["-m", "agent_guard", "run", "-c", str(cfg)]))


async def _approve_when_pending(store: ApprovalStore, approved: bool) -> str:
    with anyio.fail_after(20):
        while not store.list():
            await anyio.sleep(0.05)
    req = store.list()[0]
    store.decide(req.id, approved, by="e2e", note=None if approved else "not today")
    return req.id


@pytest.mark.parametrize("approved", [True, False])
async def test_e2e_approval(tmp_path: Path, approved: bool) -> None:
    cfg = write_config(tmp_path, policy=POLICY)
    store = ApprovalStore(tmp_path / "state" / "approvals")
    async with proxy(cfg) as client:
        small = await client.call_tool("payments__refund", {"amount": 5, "customer_id": "cus_ada001"})
        assert not small.is_error  # below threshold: no approval needed
        result = {}

        async def call() -> None:
            result["r"] = await client.call_tool("payments__refund", {"amount": 250, "customer_id": "cus_ada001"})

        async with anyio.create_task_group() as tg:
            tg.start_soon(call)
            await _approve_when_pending(store, approved)
        r = result["r"]
        text = "".join(getattr(c, "text", "") for c in r.content)
        if approved:
            assert not r.is_error, text
            assert r.structured_content and r.structured_content["amount"] == 250
        else:
            assert r.is_error and "rejected this call: not today" in text


async def test_e2e_approval_timeout(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, policy=POLICY, approvals={"timeout_seconds": 0.5, "poll_interval_seconds": 0.05})
    async with proxy(cfg) as client:
        r = await client.call_tool("payments__refund", {"amount": 250, "customer_id": "cus_ada001"})
        text = "".join(getattr(c, "text", "") for c in r.content)
        assert r.is_error and "timeout means deny" in text
