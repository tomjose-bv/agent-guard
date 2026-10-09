"""Optional LLM-driven demo agent (OpenAI-compatible chat completions API).

The model gets agent-guard's tools and a task; every tool call it makes goes
through agent-guard. Configure via .env (see .env.example):

    AGENT_GUARD_LLM_BASE_URL  default http://localhost:11434/v1 (Ollama)
    AGENT_GUARD_LLM_MODEL     default llama3.1
    AGENT_GUARD_LLM_API_KEY   optional; sent as a Bearer token

    python examples/llm_agent.py "Refund ada@example.com 250 USD and note it in notes/refunds.md"

No extra dependencies: uses urllib from the standard library. The scripted
demo (examples/demo_agent.py) needs no LLM at all.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import anyio
from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TASK = (
    "Look up the customer ada@example.com, refund them 40 USD, then write a one-line summary "
    "to notes/refunds.md. After that, try to refund 900 USD and report what happened."
)


def load_dotenv(path: Path) -> None:
    """Minimal .env reader (KEY=VALUE lines); existing environment variables win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def chat(base_url: str, model: str, api_key: str | None, messages: list[dict], tools: list[dict]) -> dict[str, Any]:
    body = json.dumps({"model": model, "messages": messages, "tools": tools, "temperature": 0}).encode()
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


async def main(task: str, config: Path, max_turns: int) -> int:
    load_dotenv(ROOT / ".env")
    base_url = os.environ.get("AGENT_GUARD_LLM_BASE_URL", "http://localhost:11434/v1")
    model = os.environ.get("AGENT_GUARD_LLM_MODEL", "llama3.1")
    api_key = os.environ.get("AGENT_GUARD_LLM_API_KEY") or None

    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_guard", "run", "-c", str(config)])
    async with Client(params) as client:
        mcp_tools = (await client.list_tools()).tools
        tools = [
            {"type": "function", "function": {"name": t.name, "description": t.description or "", "parameters": t.input_schema}}
            for t in mcp_tools
        ]
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "You are an operations agent. Use the tools. If a tool call is denied, do not retry it; explain."},
            {"role": "user", "content": task},
        ]
        for _ in range(max_turns):
            try:
                resp = await anyio.to_thread.run_sync(chat, base_url, model, api_key, messages, tools)
            except (urllib.error.URLError, TimeoutError) as e:
                print(f"Could not reach the LLM at {base_url} ({e}).")
                print("Set AGENT_GUARD_LLM_BASE_URL/MODEL in .env, or run the scripted demo: python examples/demo_agent.py")
                return 2
            msg = resp["choices"][0]["message"]
            messages.append(msg)
            calls = msg.get("tool_calls") or []
            if not calls:
                print(f"\nagent: {msg.get('content')}")
                return 0
            for tc in calls:
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = await client.call_tool(name, args)
                text = "".join(getattr(c, "text", "") for c in result.content)
                print(f"\n{'DENIED/ERROR' if result.is_error else 'ok'}  {name}({json.dumps(args)})\n  -> {text[:300]}")
                messages.append({"role": "tool", "tool_call_id": tc.get("id", name), "content": text})
        print("\n(max turns reached)")
        return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("task", nargs="?", default=DEFAULT_TASK)
    ap.add_argument("-c", "--config", default=str(ROOT / "agent-guard.yaml"))
    ap.add_argument("--max-turns", type=int, default=8)
    a = ap.parse_args()
    raise SystemExit(anyio.run(main, a.task, Path(a.config), a.max_turns))
