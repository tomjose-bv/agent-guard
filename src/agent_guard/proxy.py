"""The MCP proxy: an MCP server that fronts one or more upstream MCP servers."""

from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any

import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from agent_guard import __version__
from agent_guard.config import Config
from agent_guard import pii
from agent_guard.approvals import ApprovalStore
from agent_guard.audit import AuditLog
from agent_guard.policy import DENY_SUFFIX, Decision, PolicyEngine

log = logging.getLogger("agent_guard.proxy")


ProgressFn = Callable[[str], Awaitable[None]]


@dataclass(frozen=True)
class ToolRoute:
    exposed: str  # name the agent sees
    tool_id: str  # canonical "<server>.<tool>", used by policies and the audit log
    server: str
    upstream_name: str
    tool: types.Tool


def error_result(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=True)


def redact_result(result: types.CallToolResult, detectors: list[str]) -> tuple[types.CallToolResult, Counter[str]]:
    """Redact PII in text content, embedded text resources and structured content."""
    counts: Counter[str] = Counter()
    content: list[Any] = []
    for block in result.content:
        if isinstance(block, types.TextContent):
            text, c = pii.redact_text(block.text, detectors)
            counts.update(c)
            block = block.model_copy(update={"text": text}) if c else block
        elif isinstance(block, types.EmbeddedResource) and isinstance(block.resource, types.TextResourceContents):
            text, c = pii.redact_text(block.resource.text, detectors)
            counts.update(c)
            if c:
                block = block.model_copy(update={"resource": block.resource.model_copy(update={"text": text})})
        content.append(block)
    structured = result.structured_content
    if structured is not None:
        structured, c = pii.redact_value(structured, detectors)
        counts |= c  # structured content usually mirrors the text content; don't double count
    if not counts:
        return result, counts
    return result.model_copy(update={"content": content, "structured_content": structured}), counts


class GuardedProxy:
    """Connects to upstream servers and forwards tool listing / calls."""

    def __init__(self, config: Config, engine: PolicyEngine | None = None) -> None:
        self.config = config
        self.engine = engine or PolicyEngine(config.load_policy())
        self.agent_id = os.environ.get("AGENT_GUARD_AGENT_ID") or config.agent_id
        self.approvals = ApprovalStore(config.approvals_path)
        self.audit_log: AuditLog | None = (
            AuditLog(config.audit_path, fsync=config.audit.fsync) if config.audit.enabled else None
        )
        self.clients: dict[str, Client] = {}
        self.routes: dict[str, ToolRoute] = {}

    # ---- upstream management -------------------------------------------
    async def connect(self, stack: AsyncExitStack) -> None:
        for name, srv in self.config.servers.items():
            if not srv.enabled:
                continue
            command, args, env, cwd = self.config.server_command(name)
            params = StdioServerParameters(command=command, args=args, env={**os.environ, **env}, cwd=cwd)
            log.info("starting upstream %s: %s %s", name, command, " ".join(args))
            client = await stack.enter_async_context(Client(params))
            self.clients[name] = client
        await self.refresh_tools()
        policy_json = self.engine.policy.model_dump_json().encode()
        self.audit({"event": "proxy_start", "agent": self.agent_id, "servers": sorted(self.clients),
                    "tools": len(self.routes), "policy_sha256": hashlib.sha256(policy_json).hexdigest()})  # fmt: skip

    async def refresh_tools(self) -> None:
        routes: dict[str, ToolRoute] = {}
        for server, client in self.clients.items():
            cursor: str | None = None
            while True:
                page = await client.list_tools(cursor=cursor)
                for tool in page.tools:
                    exposed = self.exposed_name(server, tool.name)
                    if exposed in routes:
                        log.warning("tool name collision for %r; keeping the first (set namespace: true)", exposed)
                        continue
                    routes[exposed] = ToolRoute(exposed, f"{server}.{tool.name}", server, tool.name, tool)
                cursor = page.next_cursor
                if not cursor:
                    break
        self.routes = routes

    def exposed_name(self, server: str, tool: str) -> str:
        return f"{server}{self.config.namespace_separator}{tool}" if self.config.namespace else tool

    # ---- MCP-facing operations -----------------------------------------
    def list_tools(self) -> list[types.Tool]:
        return [
            route.tool.model_copy(update={"name": route.exposed})
            for route in self.routes.values()
            if not (self.config.hide_denied_tools and self.engine.statically_denied(route.tool_id, self.agent_id))
        ]

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None, progress: ProgressFn | None = None
    ) -> types.CallToolResult:
        started = time.perf_counter()
        rec: dict[str, Any] = {"event": "tool_call", "call_id": uuid.uuid4().hex[:12], "agent": self.agent_id, "tool": name}
        try:
            result = await self._guarded_call(name, dict(arguments or {}), progress, rec)
        except Exception as e:  # never let a guard bug crash the proxy; fail closed
            log.exception("internal error")
            rec.update(decision="error", reason=f"internal error: {e}")
            result = error_result(f"agent-guard: internal error, call not executed ({type(e).__name__})")
        rec["is_error"] = bool(result.is_error)
        rec["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
        if self.config.audit.log_results and self.config.audit.result_preview_chars:
            preview = "".join(getattr(c, "text", "") for c in result.content)
            preview, _ = pii.redact_text(preview)  # the log never stores raw PII from results
            rec["result_preview"] = preview[: self.config.audit.result_preview_chars]
        self.audit(rec)
        return result

    def audit(self, rec: dict[str, Any]) -> None:
        if self.audit_log is None:
            return
        try:
            self.audit_log.append(rec)
        except Exception:
            log.exception("could not write audit log entry")

    async def _guarded_call(
        self, name: str, args: dict[str, Any], progress: ProgressFn | None, rec: dict[str, Any]
    ) -> types.CallToolResult:
        route = self.routes.get(name)
        if self.config.audit.log_arguments:
            rec["arguments"], _ = pii.redact_value(args)  # the log never stores raw PII from arguments
        if route is None:
            rec.update(decision="denied", reason="unknown tool")
            return error_result(f"agent-guard: unknown tool {name!r}")
        tool_id = route.tool_id
        rec["tool_id"] = tool_id

        decision = self.engine.evaluate(tool_id, self.agent_id, args)
        rec.update(rule=decision.rule, matched_rules=decision.matched)
        if decision.action == "deny":
            rec.update(decision="denied", reason=decision.reason)
            return error_result(decision.reason)
        if decision.action == "require_approval":
            denial = await self.await_approval(tool_id, args, decision, progress, rec)
            if denial:
                rec.update(reason=denial)
                return error_result(denial)

        pii_rule = self.engine.policy.pii_for(tool_id)
        pii_info: dict[str, Any] = {}
        if pii_rule and pii_rule.arguments != "off":
            redacted, counts = pii.redact_value(args, pii_rule.detectors)
            if counts:
                pii_info["arguments"] = {"mode": pii_rule.arguments, "found": dict(counts)}
                rec["pii"] = pii_info
                if pii_rule.arguments == "block":
                    msg = f"agent-guard denied {tool_id}: arguments contain PII ({pii.summarize(counts)}).{DENY_SUFFIX}"
                    rec.update(decision="denied", reason=msg)
                    return error_result(msg)
                if pii_rule.arguments == "redact":
                    args = redacted

        problem = self.engine.acquire(decision, tool_id, self.agent_id, args)
        if problem:
            rec.update(decision="denied", reason=problem)
            return error_result(problem)
        rec.setdefault("decision", "allowed")
        rec.setdefault("reason", decision.reason)

        upstream_started = time.perf_counter()
        result = await self.forward(route, args)
        rec["upstream_ms"] = round((time.perf_counter() - upstream_started) * 1000, 3)

        if pii_rule and pii_rule.results != "off":
            redacted_result, counts = redact_result(result, pii_rule.detectors)
            if counts:
                pii_info["results"] = {"mode": pii_rule.results, "found": dict(counts)}
                rec["pii"] = pii_info
                if pii_rule.results == "block":
                    rec["result_withheld"] = True
                    return error_result(
                        f"agent-guard withheld the result of {tool_id}: it contained PII ({pii.summarize(counts)})."
                    )
                if pii_rule.results == "redact":
                    result = redacted_result
        return result

    async def await_approval(
        self,
        tool_id: str,
        args: dict[str, Any],
        decision: Decision,
        progress: ProgressFn | None,
        rec: dict[str, Any] | None = None,
    ) -> str | None:
        """Hold the call until a human approves it. Returns a deny message, or None if approved."""
        timeout = decision.approval_timeout or self.config.approvals.timeout_seconds
        shown_args, _ = pii.redact_value(args)  # reviewers see arguments with PII masked
        req = self.approvals.create(tool_id, self.agent_id, shown_args, decision.reason, decision.rule, timeout)
        if rec is not None:
            rec["approval_id"] = req.id
            self.audit({"event": "approval_requested", "call_id": rec["call_id"], "approval_id": req.id,
                        "agent": self.agent_id, "tool_id": tool_id, "arguments": shown_args,
                        "reason": decision.reason, "rule": decision.rule, "timeout_seconds": timeout})  # fmt: skip
        log.warning(
            "approval required for %s (%s). Approve: agent-guard approve %s | Deny: agent-guard deny %s",
            tool_id, decision.reason, req.id, req.id,
        )  # fmt: skip

        async def tick(remaining: float) -> None:
            if progress:
                await progress(f"waiting for human approval {req.id} ({remaining:.0f}s left)")

        if progress:
            await progress(f"waiting for human approval {req.id}: {decision.reason}")
        outcome, d = await self.approvals.wait(req, self.config.approvals.poll_interval_seconds, tick)
        if rec is not None:
            rec["decision"] = {"approved": "approved", "denied": "approval_denied", "timeout": "approval_timeout"}[outcome]
            rec["approved_by"] = d.by if d else None
        if outcome == "approved":
            return None
        if outcome == "denied":
            note = f": {d.note}" if d and d.note else ""
            by = f" ({d.by})" if d else ""
            return f"agent-guard denied {tool_id}: a human reviewer{by} rejected this call{note}.{DENY_SUFFIX}"
        return (
            f"agent-guard denied {tool_id}: approval {req.id} was not granted within {timeout:g}s "
            f"(timeout means deny).{DENY_SUFFIX}"
        )

    async def forward(self, route: ToolRoute, arguments: dict[str, Any]) -> types.CallToolResult:
        client = self.clients[route.server]
        try:
            return await client.call_tool(route.upstream_name, arguments)
        except Exception as e:  # upstream crashed / protocol error
            log.exception("upstream call failed")
            return error_result(f"agent-guard: upstream server {route.server!r} failed: {e}")

    # ---- server wiring ---------------------------------------------------
    def build_server(self) -> Server[Any]:
        proxy = self

        @asynccontextmanager
        async def lifespan(_: Server[Any]) -> AsyncIterator[dict[str, Any]]:
            async with AsyncExitStack() as stack:
                await proxy.connect(stack)
                yield {}

        async def on_list_tools(
            ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
        ) -> types.ListToolsResult:
            return types.ListToolsResult(tools=proxy.list_tools())

        async def on_call_tool(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> types.CallToolResult:
            step = 0

            async def progress(message: str) -> None:
                nonlocal step
                step += 1
                try:
                    await ctx.session.report_progress(step, None, message)
                except Exception:  # progress is best-effort
                    log.debug("could not send progress", exc_info=True)

            return await proxy.call_tool(params.name, params.arguments, progress)

        return Server(
            "agent-guard",
            version=__version__,
            instructions="Tool calls pass through agent-guard, which enforces policy and may deny, redact or hold calls for approval.",
            lifespan=lifespan,
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
        )


async def serve_stdio(config: Config) -> None:
    proxy = GuardedProxy(config)
    server = proxy.build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
