"""The proxy writes a verifiable audit log that never contains raw PII."""

from __future__ import annotations

import sys
from pathlib import Path

from mcp import Client, StdioServerParameters

from agent_guard.audit import read_entries, verify
from conftest import write_config


async def test_proxy_writes_hash_chained_audit_log(tmp_path: Path) -> None:
    policy = {
        "rules": [{"tools": "files.delete_*", "action": "deny"}],
        "pii": [{"tools": "*", "arguments": "log_only", "results": "redact"}],
    }
    cfg = write_config(tmp_path, policy=policy)
    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_guard", "run", "-c", str(cfg)])
    async with Client(params) as client:
        await client.call_tool("payments__lookup_customer", {"email": "ada@example.com"})
        await client.call_tool("files__delete_file", {"path": "x"})

    log_path = tmp_path / "state" / "audit.jsonl"
    assert verify(log_path).ok
    entries = read_entries(log_path)
    assert entries[0]["event"] == "proxy_start" and len(entries[0]["policy_sha256"]) == 64
    calls = [e for e in entries if e["event"] == "tool_call"]
    assert [c["decision"] for c in calls] == ["allowed", "denied"]
    lookup = calls[0]
    assert lookup["tool_id"] == "payments.lookup_customer"
    assert lookup["pii"]["arguments"] == {"mode": "log_only", "found": {"email": 1}}
    assert lookup["pii"]["results"]["mode"] == "redact"
    assert lookup["duration_ms"] > 0 and "upstream_ms" in lookup
    raw = log_path.read_text(encoding="utf-8")
    assert "ada@example.com" not in raw and "4111" not in raw
