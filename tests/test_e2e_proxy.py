"""End-to-end: a real MCP client -> agent-guard (stdio subprocess) -> example upstream servers."""

from __future__ import annotations

import sys
from pathlib import Path

from mcp import Client, StdioServerParameters

from conftest import write_config


def proxy_params(config: Path) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "agent_guard", "run", "-c", str(config)])


def text(result) -> str:  # type: ignore[no-untyped-def]
    return "".join(getattr(c, "text", "") for c in result.content)


async def test_passthrough_lists_and_calls_tools(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    async with Client(proxy_params(cfg)) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"files__write_file", "files__read_file", "payments__refund", "payments__lookup_customer"} <= names

        r = await client.call_tool("files__write_file", {"path": "notes/hello.txt", "content": "hi there"})
        assert not r.is_error, text(r)
        r = await client.call_tool("files__read_file", {"path": "notes/hello.txt"})
        assert text(r) == "hi there"
        assert (tmp_path / "sandbox" / "notes" / "hello.txt").read_text() == "hi there"

        r = await client.call_tool("payments__refund", {"amount": 12.5, "customer_id": "cus_ada001"})
        assert not r.is_error
        assert r.structured_content and r.structured_content["status"] == "succeeded"


async def test_unknown_tool_is_an_error(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    async with Client(proxy_params(cfg)) as client:
        r = await client.call_tool("nope__nothing", {})
        assert r.is_error
        assert "unknown tool" in text(r)


async def test_without_namespace(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, namespace=False)
    async with Client(proxy_params(cfg)) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert "refund" in names and "read_file" in names


async def test_policy_denials_reach_the_agent_as_tool_errors(tmp_path: Path) -> None:
    policy = {
        "rules": [
            {"tools": "files.delete_*", "action": "deny", "reason": "no deleting"},
            {"tools": "payments.refund", "args": {"amount": {"max": 500}}},
        ]
    }
    cfg = write_config(tmp_path, policy=policy)
    async with Client(proxy_params(cfg)) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert "files__delete_file" not in names  # hidden: always denied
        r = await client.call_tool("files__delete_file", {"path": "x"})
        assert r.is_error and "no deleting" in text(r)
        r = await client.call_tool("payments__refund", {"amount": 900, "customer_id": "cus_ada001"})
        assert r.is_error and "exceeds the maximum of 500" in text(r)
        r = await client.call_tool("payments__refund", {"amount": 9, "customer_id": "cus_ada001"})
        assert not r.is_error


async def test_pii_redaction_and_blocking(tmp_path: Path) -> None:
    policy = {
        "pii": [
            {"tools": "payments.lookup_customer", "arguments": "off", "results": "redact"},
            {"tools": "files.write_file", "arguments": "redact", "results": "off"},
            {"tools": "payments.ping", "arguments": "block", "results": "off"},
        ]
    }
    cfg = write_config(tmp_path, policy=policy)
    async with Client(proxy_params(cfg)) as client:
        r = await client.call_tool("payments__lookup_customer", {"email": "ada@example.com"})
        assert not r.is_error
        body = text(r)
        assert "4111" not in body and "415 555" not in body and "ada@example.com" not in body
        assert "[REDACTED:CREDIT_CARD]" in body and "[REDACTED:PHONE]" in body
        assert r.structured_content and r.structured_content["customer_id"] == "cus_ada001"

        r = await client.call_tool("files__write_file", {"path": "n.txt", "content": "card 4111 1111 1111 1111"})
        assert not r.is_error
        assert (tmp_path / "sandbox" / "n.txt").read_text() == "card [REDACTED:CREDIT_CARD]"

        r = await client.call_tool("payments__ping", {"message": "my ssn is 123-45-6789"})
        assert r.is_error and "contain PII (ssn x1)" in text(r)
