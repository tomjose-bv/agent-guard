"""Scripted demo agent: drives agent-guard through allowed, denied, redacted,
rate-limited and approval-gated tool calls. No LLM needed.

    python examples/demo_agent.py                  # auto-approves the approval step after 2s
    python examples/demo_agent.py --approve manual # you approve via CLI or `agent-guard ui`
    python examples/demo_agent.py --approve deny   # simulated reviewer rejects it

It talks to agent-guard exactly like any MCP client would: it launches
`agent-guard run -c agent-guard.yaml` as a stdio subprocess.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path
from typing import Any

import anyio
from mcp import Client, StdioServerParameters

from agent_guard.approvals import ApprovalStore
from agent_guard.audit import verify
from agent_guard.config import load_config

ROOT = Path(__file__).resolve().parent.parent


def show(step: str, tool: str, args: dict[str, Any], result: Any) -> None:
    body = "".join(getattr(c, "text", "") for c in result.content)
    if result.is_error:
        tag = "DENIED " if "denied" in body or "withheld" in body else "ERROR  "
    else:
        tag = "REDACTED" if "[REDACTED:" in body else "ALLOWED "
    print(f"\n[{tag}] {step}")
    print(f"    call   {tool}({json.dumps(args)})")
    print(textwrap.indent(textwrap.shorten(body.replace("\n", " "), 300), "    -> "))


async def simulated_reviewer(store: ApprovalStore, mode: str) -> None:
    """Stands in for a human: approves/denies the first pending request."""
    with anyio.fail_after(60):
        while not store.list():
            await anyio.sleep(0.1)
    req = store.list()[0]
    print(f"\n    ... approval {req.id} pending for {req.tool_id} {json.dumps(req.arguments)}")
    if mode == "manual":
        print(f"    ... approve with:  agent-guard approve {req.id}   (or deny {req.id}, or use `agent-guard ui`)")
        return
    await anyio.sleep(2)
    store.decide(req.id, mode == "auto", by="demo-reviewer", note=None if mode == "auto" else "not authorised today")
    print(f"    ... simulated reviewer {'approved' if mode == 'auto' else 'denied'} {req.id}")


async def main(config: Path, approve: str) -> int:
    cfg = load_config(config)
    store = ApprovalStore(cfg.approvals_path)
    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_guard", "run", "-c", str(config)])
    print(f"agent-guard demo  (config: {config})")
    async with Client(params) as client:
        tools = [t.name for t in (await client.list_tools()).tools]
        print(f"\nTools visible to the agent ({len(tools)}): {', '.join(tools)}")
        print("(files__delete_file is hidden because policy always denies it)")

        async def call(step: str, tool: str, args: dict[str, Any]) -> Any:
            r = await client.call_tool(tool, args)
            show(step, tool, args, r)
            return r

        await call("Write a note inside the allowed folder", "files__write_file",
                   {"path": "notes/todo.md", "content": "- refund ada\n- call grace"})
        await call("Read it back", "files__read_file", {"path": "notes/todo.md"})
        await call("Try to write outside notes/ (path constraint)", "files__write_file",
                   {"path": "../escape.txt", "content": "x"})
        await call("Try a tool that is always denied", "files__delete_file", {"path": "notes/todo.md"})
        await call("Write a file containing a card number (arguments are redacted)", "files__write_file",
                   {"path": "notes/customer.md", "content": "Ada paid with 4111 1111 1111 1111"})
        await call("...what actually landed on disk", "files__read_file", {"path": "notes/customer.md"})
        await call("Look up a customer (phone/card/email redacted in the result)", "payments__lookup_customer",
                   {"email": "ada@example.com"})
        for i in range(3):
            await call(f"Lookup #{i + 2} (limit is 3 per minute)", "payments__lookup_customer",
                       {"email": "grace@example.org"})
        await call("Refund above the hard maximum of 500", "payments__refund",
                   {"amount": 900, "customer_id": "cus_ada001"})
        await call("Refund with a malformed customer id", "payments__refund",
                   {"amount": 20, "customer_id": "DROP TABLE"})
        await call("Small refund (allowed, counts toward the daily budget)", "payments__refund",
                   {"amount": 25, "customer_id": "cus_ada001"})

        async with anyio.create_task_group() as tg:
            tg.start_soon(simulated_reviewer, store, approve)
            await call("Refund of 250 needs a human", "payments__refund", {"amount": 250, "customer_id": "cus_ada001"})  # fmt: skip

    res = verify(cfg.audit_path)
    print(f"\nAudit log: {cfg.audit_path}")
    print(f"  hash chain {'intact' if res.ok else 'BROKEN: ' + str(res.error)} ({res.entries} entries)")
    print("  browse it:  agent-guard ui      verify it:  agent-guard verify-log")
    return 0 if res.ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", default=str(ROOT / "agent-guard.yaml"))
    ap.add_argument("--approve", choices=["auto", "deny", "manual"], default="auto")
    a = ap.parse_args()
    raise SystemExit(anyio.run(main, Path(a.config), a.approve))
