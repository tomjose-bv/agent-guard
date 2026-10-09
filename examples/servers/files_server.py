"""Sample upstream MCP server: file operations confined to a sandbox directory.

Tools: read_file, write_file, delete_file, list_files.

The sandbox directory is taken from the FILES_SANDBOX environment variable
(default: ./sandbox next to the current working directory). The server itself
refuses paths that escape the sandbox, so it is safe to play with; agent-guard
policies add a second, independent layer on top.

Run directly (stdio):  python examples/servers/files_server.py
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

SANDBOX = Path(os.environ.get("FILES_SANDBOX", "sandbox")).resolve()
SANDBOX.mkdir(parents=True, exist_ok=True)

server = MCPServer("files")


def _resolve(path: str) -> Path:
    candidate = (SANDBOX / path).resolve()
    if not candidate.is_relative_to(SANDBOX):
        raise ToolError(f"path escapes sandbox: {path}")
    return candidate


@server.tool()
def read_file(path: str) -> str:
    """Read a UTF-8 text file from the sandbox."""
    return _resolve(path).read_text(encoding="utf-8")


@server.tool()
def write_file(path: str, content: str) -> str:
    """Write a UTF-8 text file into the sandbox (creates parent dirs)."""
    target = _resolve(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} chars to {path}"


@server.tool()
def delete_file(path: str) -> str:
    """Delete a file from the sandbox."""
    _resolve(path).unlink()
    return f"deleted {path}"


@server.tool()
def list_files() -> list[str]:
    """List all files in the sandbox (relative paths)."""
    return sorted(str(p.relative_to(SANDBOX)).replace("\\", "/") for p in SANDBOX.rglob("*") if p.is_file())


if __name__ == "__main__":
    server.run()
