"""Smoke test: the scripted demo runs end to end against the demo policy."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from conftest import ROOT, write_config


def test_scripted_demo_runs(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, policy=None)
    text = cfg.read_text(encoding="utf-8") + f"policy: {(ROOT / 'examples' / 'policies' / 'demo.yaml').as_posix()}\n"
    cfg.write_text(text, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "demo_agent.py"), "-c", str(cfg), "--approve", "auto"],
        capture_output=True, text=True, timeout=120,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert out.count("[DENIED ]") == 5
    assert "rate limit exceeded" in out
    assert "[REDACTED:CREDIT_CARD]" in out
    assert "simulated reviewer approved" in out
    assert "hash chain intact" in out
