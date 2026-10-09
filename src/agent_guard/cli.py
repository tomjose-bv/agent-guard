"""Command-line interface: `agent-guard <command>`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence
from contextlib import AsyncExitStack

from agent_guard import __version__
from agent_guard.config import Config, ConfigError, load_config
from agent_guard.policy import PolicyError


def _load(args: argparse.Namespace) -> Config:
    return load_config(args.config)


def cmd_run(args: argparse.Namespace) -> int:
    from agent_guard.proxy import serve_stdio

    cfg = _load(args)
    cfg.load_policy()  # fail fast on a bad policy before any upstream starts
    asyncio.run(serve_stdio(cfg))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    cfg = _load(args)
    cfg.load_policy()
    print(f"OK: {len(cfg.servers)} upstream server(s); config and policy are valid.")
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    from agent_guard.proxy import GuardedProxy

    cfg = _load(args)

    async def go() -> None:
        proxy = GuardedProxy(cfg)
        async with AsyncExitStack() as stack:
            await proxy.connect(stack)
            for route in proxy.routes.values():
                desc = (route.tool.description or "").strip().splitlines()[0:1]
                print(f"{route.exposed:32} {route.tool_id:32} {desc[0] if desc else ''}")

    asyncio.run(go())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent-guard", description="Policy-enforcing MCP proxy for AI agent tool calls.")
    p.add_argument("--version", action="version", version=f"agent-guard {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging (to stderr)")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name: str, func, help_: str) -> argparse.ArgumentParser:  # type: ignore[no-untyped-def]
        sp = sub.add_parser(name, help=help_, description=help_)
        sp.add_argument("-c", "--config", help="config file (default: $AGENT_GUARD_CONFIG or ./agent-guard.yaml)")
        sp.set_defaults(func=func)
        return sp

    add("run", cmd_run, "Serve the proxy over stdio (point your MCP client at this command).")
    add("validate", cmd_validate, "Validate the config and policy files.")
    add("tools", cmd_tools, "Start upstream servers and list the tools agent-guard exposes.")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        stream=sys.stderr,
        format="agent-guard %(levelname)s %(name)s: %(message)s",
    )
    try:
        return int(args.func(args) or 0)
    except (ConfigError, PolicyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
