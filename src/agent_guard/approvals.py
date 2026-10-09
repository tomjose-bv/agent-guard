"""File-based human-in-the-loop approval queue.

The proxy (one process per agent) writes ``<id>.json`` for each call that needs
approval and polls for ``<id>.decision.json``. The CLI (`agent-guard approve`)
and the local web viewer write decisions. Using plain files means the proxy,
the CLI and the viewer need no shared server and work across processes.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import anyio

Outcome = Literal["approved", "denied", "timeout"]


class ApprovalError(Exception):
    pass


@dataclass
class ApprovalRequest:
    id: str
    tool_id: str
    agent: str
    arguments: dict[str, Any]
    reason: str
    rule: str | None
    created_at: float
    expires_at: float
    status: str = "pending"  # pending | approved | denied | timeout
    decided_by: str | None = None
    note: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


@dataclass
class ApprovalDecision:
    approved: bool
    by: str
    note: str | None
    decided_at: float


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _read(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


class ApprovalStore:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)

    def _req(self, approval_id: str) -> Path:
        if not approval_id.isalnum():
            raise ApprovalError(f"invalid approval id {approval_id!r}")
        return self.dir / f"{approval_id}.json"

    def _dec(self, approval_id: str) -> Path:
        return self.dir / f"{approval_id}.decision.json"

    # ---- proxy side -------------------------------------------------------
    def create(
        self, tool_id: str, agent: str, arguments: dict[str, Any], reason: str, rule: str | None, timeout: float
    ) -> ApprovalRequest:
        now = time.time()
        req = ApprovalRequest(
            id=secrets.token_hex(4), tool_id=tool_id, agent=agent, arguments=arguments,
            reason=reason, rule=rule, created_at=now, expires_at=now + timeout,
        )  # fmt: skip
        _atomic_write(self._req(req.id), asdict(req))
        return req

    def decision(self, approval_id: str) -> ApprovalDecision | None:
        data = _read(self._dec(approval_id))
        if data is None:
            return None
        return ApprovalDecision(bool(data.get("approved")), str(data.get("by", "?")), data.get("note"), float(data.get("decided_at", 0)))

    def finalize(self, req: ApprovalRequest, status: Outcome, decision: ApprovalDecision | None) -> None:
        req.status = status
        if decision:
            req.decided_by, req.note = decision.by, decision.note
        _atomic_write(self._req(req.id), asdict(req))

    async def wait(
        self,
        req: ApprovalRequest,
        poll_interval: float = 0.25,
        on_tick: Callable[[float], Awaitable[None]] | None = None,
        tick_every: float = 5.0,
    ) -> tuple[Outcome, ApprovalDecision | None]:
        """Wait for a decision or the timeout. Timeout means deny (fail closed)."""
        last_tick = time.monotonic()
        while True:
            d = self.decision(req.id)
            if d is not None:
                outcome: Outcome = "approved" if d.approved else "denied"
                self.finalize(req, outcome, d)
                return outcome, d
            if req.expired:
                self.finalize(req, "timeout", None)
                return "timeout", None
            if on_tick and time.monotonic() - last_tick >= tick_every:
                last_tick = time.monotonic()
                await on_tick(req.expires_at - time.time())
            await anyio.sleep(poll_interval)

    # ---- reviewer side (CLI / web viewer) ---------------------------------
    def get(self, approval_id: str) -> ApprovalRequest | None:
        data = _read(self._req(approval_id))
        if data is None:
            return None
        known = {k: data[k] for k in ApprovalRequest.__dataclass_fields__ if k in data}
        return ApprovalRequest(**known)

    def list(self, include_resolved: bool = False) -> list[ApprovalRequest]:
        if not self.dir.is_dir():
            return []
        out = []
        for p in self.dir.glob("*.json"):
            if p.name.endswith(".decision.json") or p.name.startswith(".tmp-"):
                continue
            req = self.get(p.stem)
            if req is None:
                continue
            if req.status == "pending" and self._dec(req.id).exists():
                req.status = "decided"  # decision written, proxy has not picked it up yet
            if include_resolved or (req.status == "pending" and not req.expired):
                out.append(req)
        return sorted(out, key=lambda r: r.created_at)

    def decide(self, approval_id: str, approved: bool, by: str, note: str | None = None) -> ApprovalRequest:
        req = self.get(approval_id)
        if req is None:
            raise ApprovalError(f"no approval request with id {approval_id!r} in {self.dir}")
        if req.status != "pending":
            raise ApprovalError(f"approval {approval_id} is already {req.status}")
        if req.expired:
            raise ApprovalError(f"approval {approval_id} has expired (the call was denied)")
        payload = json.dumps({"approved": approved, "by": by, "note": note, "decided_at": time.time()})
        try:
            # Exclusive create: the first reviewer wins; readers retry on a partial file.
            with open(self._dec(approval_id), "x", encoding="utf-8") as f:
                f.write(payload)
        except FileExistsError:
            raise ApprovalError(f"approval {approval_id} already has a decision") from None
        return req
