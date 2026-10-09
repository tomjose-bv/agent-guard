"""Measure tool-call latency: direct to the upstream server vs through agent-guard.

Both paths use the official MCP client over stdio. The proxied path has a
policy with allow rules, argument constraints, a rate limit and a spend limit,
PII scanning (redact) on arguments and results, and the hash-chained audit log
enabled (default settings, no fsync).

    python benchmarks/bench_latency.py            # N=500 per scenario
    python benchmarks/bench_latency.py -n 1000 --json out.json
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anyio
import yaml
from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent
PAYMENTS = ROOT / "examples" / "servers" / "payments_server.py"

POLICY: dict[str, Any] = {
    "version": 1,
    "default_action": "deny",
    "rules": [
        {"name": "ping", "tools": "payments.ping", "action": "allow",
         "args": {"message": {"max_length": 1000, "not_regex": "(?i)drop\\s+table"}},
         "rate_limit": {"calls": 1_000_000, "per_seconds": 60}},
        {"name": "lookup", "tools": "payments.lookup_customer", "action": "allow",
         "args": {"email": {"regex": "[^@]+@[^@]+"}},
         "spend_limit": {"cost_per_call": 0.001, "budget": 1_000_000, "per_seconds": 86400}},
    ],
    "pii": [
        # arguments are still scanned for lookups, but not rewritten (the email is the lookup key)
        {"tools": "payments.lookup_customer", "arguments": "log_only", "results": "redact"},
        {"tools": "*", "arguments": "redact", "results": "redact"},
    ],
}  # fmt: skip

SCENARIOS = [
    ("ping", "payments__ping", {"message": "hello from the benchmark, order 12345"}),
    ("lookup_customer", "payments__lookup_customer", {"email": "ada@example.com"}),
]


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


async def measure(client: Any, tool: str, args: dict[str, Any], n: int, warmup: int) -> list[float]:
    for _ in range(warmup):
        await client.call_tool(tool, args)
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = await client.call_tool(tool, args)
        out.append((time.perf_counter() - t0) * 1000)
        if r.is_error:
            raise RuntimeError(f"{tool} failed: {r.content}")
    return out


class _InProc:
    """Adapter so measure() can call GuardedProxy.call_tool directly."""

    def __init__(self, proxy: Any) -> None:
        self.proxy = proxy

    async def call_tool(self, name: str, args: dict[str, Any]) -> Any:
        return await self.proxy.call_tool(name, args)


def summarize(samples: list[float]) -> dict[str, float]:
    return {"n": len(samples), "p50": pct(samples, 0.5), "p95": pct(samples, 0.95), "p99": pct(samples, 0.99),
            "mean": statistics.fmean(samples)}  # fmt: skip


async def run(n: int, warmup: int) -> dict[str, Any]:
    results: dict[str, Any] = {}
    direct = StdioServerParameters(command=sys.executable, args=[str(PAYMENTS)])
    async with Client(direct) as client:
        for label, tool, args in SCENARIOS:
            results[f"{label}/direct"] = summarize(await measure(client, tool.split("__", 1)[1], args, n, warmup))

    with tempfile.TemporaryDirectory() as tmp:
        cfg = {
            "agent_id": "bench",
            "servers": {"payments": {"command": "python", "args": [str(PAYMENTS)]}},
            "policy": POLICY,
            "state_dir": str(Path(tmp) / "state"),
        }
        cfg_path = Path(tmp) / "agent-guard.yaml"
        cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        proxied = StdioServerParameters(command=sys.executable, args=["-m", "agent_guard", "run", "-c", str(cfg_path)])
        async with Client(proxied) as client:
            for label, tool, args in SCENARIOS:
                results[f"{label}/agent-guard"] = summarize(await measure(client, tool, args, n, warmup))

        # Same pipeline in-process (no client<->proxy stdio hop): isolates the guard's own cost.
        from contextlib import AsyncExitStack

        from agent_guard.config import load_config
        from agent_guard.proxy import GuardedProxy

        proxy = GuardedProxy(load_config(cfg_path))
        async with AsyncExitStack() as stack:
            await proxy.connect(stack)
            for label, tool, args in SCENARIOS:
                results[f"{label}/in-process"] = summarize(await measure(_InProc(proxy), tool, args, n, warmup))
            if proxy.audit_log:
                proxy.audit_log.close()
        from agent_guard.audit import verify

        results["audit_entries"] = verify(Path(tmp) / "state" / "audit.jsonl").entries
    return results


def machine() -> str:
    cpu = platform.processor() or platform.machine()
    try:
        import ctypes

        class MEM(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + [
                (f, ctypes.c_ulonglong) for f in ("total", "avail", "tp", "ap", "tv", "av", "ae")
            ]

        m = MEM()
        m.dwLength = ctypes.sizeof(MEM)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))  # type: ignore[attr-defined]
        ram = f", {m.total / 2**30:.0f} GB RAM"
    except Exception:
        ram = ""
    return f"{platform.system()} {platform.release()} ({platform.version()}), {cpu}{ram}, Python {platform.python_version()}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", type=int, default=500, help="measured calls per scenario (default 500)")
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--json", help="also write raw results to this file")
    a = ap.parse_args()
    res = anyio.run(run, a.n, a.warmup)
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"Machine: {machine()}\nDate: {when}\nN = {a.n} measured calls per row (after {a.warmup} warm-up calls)\n")
    print("| Tool | Path | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) |")
    print("|---|---|---:|---:|---:|---:|")
    for label, _, _ in SCENARIOS:
        for path in ("direct", "agent-guard", "in-process"):
            r = res[f"{label}/{path}"]
            name = {"direct": "direct (client -> upstream)", "agent-guard": "via agent-guard (client -> proxy -> upstream)",
                    "in-process": "guard pipeline in-process (-> upstream)"}[path]
            print(f"| {label} | {name} | {r['p50']:.2f} | {r['p95']:.2f} | {r['p99']:.2f} | {r['mean']:.2f} |")
    print()
    for label, _, _ in SCENARIOS:
        d, g = res[f"{label}/direct"], res[f"{label}/agent-guard"]
        print(f"{label}: added latency p50 +{g['p50'] - d['p50']:.2f} ms, p95 +{g['p95'] - d['p95']:.2f} ms")
    print("In-process rows call GuardedProxy.call_tool directly (policy + PII + audit + upstream stdio call),")
    print("so in-process minus direct approximates the guard's own work; the rest is the extra stdio/JSON-RPC hop.")
    print(f"audit entries written during the proxied run: {res['audit_entries']}")
    if a.json:
        Path(a.json).write_text(json.dumps({"machine": machine(), "date": when, "n": a.n, **res}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
