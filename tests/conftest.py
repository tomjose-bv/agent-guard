from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SERVERS = ROOT / "examples" / "servers"


def write_config(tmp_path: Path, policy: dict[str, Any] | None = None, **overrides: Any) -> Path:
    """Write a proxy config in tmp_path that fronts the example servers."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(exist_ok=True)
    cfg: dict[str, Any] = {
        "agent_id": "test-agent",
        "servers": {
            "files": {
                "command": "python",
                "args": [str(SERVERS / "files_server.py")],
                "env": {"FILES_SANDBOX": str(sandbox)},
            },
            "payments": {"command": "python", "args": [str(SERVERS / "payments_server.py")]},
        },
        "state_dir": str(tmp_path / "state"),
    }
    if policy is not None:
        cfg["policy"] = policy
    cfg.update(overrides)
    path = tmp_path / "agent-guard.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path


@pytest.fixture
def python() -> str:
    return sys.executable
