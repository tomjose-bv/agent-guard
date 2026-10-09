"""The MCP proxy: an MCP server that fronts one or more upstream MCP servers."""

from __future__ import annotations

import logging
import os
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
        route = self.routes.get(name)
        if route is None:
            return error_result(f"agent-guard: unknown tool {name!r}")
        args = dict(arguments or {})
        tool_id = route.tool_id

        decision = self.engine.evaluate(tool_id, self.agent_id, args)
        if decision.action == "deny":
            return error_result(decision.reason)
        if decision.action == "require_approval":
            denial = await self.await_approval(tool_id, args, decision, progress)
            if denial:
                return error_result(denial)

        pii_rule = self.engine.policy.pii_for(tool_id)
        if pii_rule and pii_rule.arguments != "off":
            redacted, counts = pii.redact_value(args, pii_rule.detectors)
            if counts:
                if pii_rule.arguments == "block":
                    return error_result(
                        f"agent-guard denied {tool_id}: arguments contain PII ({pii.summarize(counts)}).{DENY_SUFFIX}"
                    )
                if pii_rule.arguments == "redact":
                    args = redacted
                log.info("PII in arguments of %s: %s (%s)", tool_id, pii.summarize(counts), pii_rule.arguments)

        problem = self.engine.acquire(decision, tool_id, self.agent_id, args)
        if problem:
            return error_result(problem)

        result = await self.forward(route, args)

        if pii_rule and pii_rule.results != "off":
            redacted_result, counts = redact_result(result, pii_rule.detectors)
            if counts:
                if pii_rule.results == "block":
                    return error_result(
                        f"agent-guard withheld the result of {tool_id}: it contained PII ({pii.summarize(counts)})."
                    )
                if pii_rule.results == "redact":
                    result = redacted_result
                log.info("PII in result of %s: %s (%s)", tool_id, pii.summarize(counts), pii_rule.results)
        return result

    async def await_approval(
        self, tool_id: str, args: dict[str, Any], decision: Decision, progress: ProgressFn | None
    ) -> str | None:
        """Hold the call until a human approves it. Returns a deny message, or None if approved."""
        timeout = decision.approval_timeout or self.config.approvals.timeout_seconds
        shown_args, _ = pii.redact_value(args)  # reviewers see arguments with PII masked
        req = self.approvals.create(tool_id, self.agent_id, shown_args, decision.reason, decision.rule, timeout)
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
