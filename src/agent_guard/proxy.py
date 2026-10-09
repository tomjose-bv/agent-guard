"""The MCP proxy: an MCP server that fronts one or more upstream MCP servers."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
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

log = logging.getLogger("agent_guard.proxy")


@dataclass(frozen=True)
class ToolRoute:
    exposed: str  # name the agent sees
    tool_id: str  # canonical "<server>.<tool>", used by policies and the audit log
    server: str
    upstream_name: str
    tool: types.Tool


def error_result(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=True)


class GuardedProxy:
    """Connects to upstream servers and forwards tool listing / calls."""

    def __init__(self, config: Config) -> None:
        self.config = config
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
        return [route.tool.model_copy(update={"name": route.exposed}) for route in self.routes.values()]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        route = self.routes.get(name)
        if route is None:
            return error_result(f"agent-guard: unknown tool {name!r}")
        return await self.forward(route, arguments or {})

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
            return await proxy.call_tool(params.name, params.arguments)

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
