"""Policy model and engine (placeholder: allow everything)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


class Policy(BaseModel):
    """Empty policy: every call is allowed."""


def load_policy_data(data: dict[str, Any], source: str = "<policy>") -> Policy:
    return Policy.model_validate(data)


def load_policy_file(path: Path) -> Policy:
    return load_policy_data(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, source=str(path))
