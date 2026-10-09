"""Append-only JSONL audit log with SHA-256 hash chaining.

Each line is a JSON object. ``prev_hash`` is the ``hash`` of the previous line
(64 zeros for the first), and ``hash`` is the SHA-256 of the line's canonical
JSON *without* the ``hash`` field. Editing, deleting, inserting or reordering
lines breaks the chain and is reported by ``agent-guard verify-log``.

Not detected without an external anchor: truncating the newest lines (the
remaining prefix is still a valid chain) or rewriting the whole file from some
point on. Record the head hash (``verify-log`` prints it) somewhere else if you
need to detect that.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

GENESIS = "0" * 64


def canonical(entry: dict[str, Any]) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(canonical(body)).hexdigest()


@contextmanager
def _locked(f: IO[bytes]) -> Iterator[None]:
    """Cross-process exclusive lock on an open file (byte 0)."""
    if sys.platform == "win32":
        import msvcrt

        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)  # retries for ~10s, then raises
        try:
            yield
        finally:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _last_line(f: IO[bytes]) -> bytes | None:
    f.seek(0, os.SEEK_END)
    end = f.tell()
    if end == 0:
        return None
    pos, chunk, buf = end, 8192, b""
    while pos > 0:
        step = min(chunk, pos)
        pos -= step
        f.seek(pos)
        buf = f.read(step) + buf
        stripped = buf.rstrip(b"\r\n")
        nl = stripped.rfind(b"\n")
        if nl != -1:
            return stripped[nl + 1 :]
    return buf.rstrip(b"\r\n") or None


class AuditLog:
    """Thread- and process-safe appender."""

    def __init__(self, path: Path, fsync: bool = False) -> None:
        self.path = Path(path)
        self.fsync = fsync
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lockfile = open(self.path.with_name(self.path.name + ".lock"), "a+b")  # noqa: SIM115
        # Kept open: reopening per entry is slow on Windows (and triggers AV rescans).
        self._file = open(self.path, "a+b")  # noqa: SIM115
        self._known: tuple[int, str, int] | None = None  # (file size, last hash, last seq) after our last write

    def close(self) -> None:
        self._file.close()
        self._lockfile.close()

    def _head(self) -> tuple[str, int]:
        size = self._file.seek(0, os.SEEK_END)
        if self._known and self._known[0] == size:
            return self._known[1], self._known[2]  # nobody else appended since our last write
        last = _last_line(self._file)
        if not last:
            return GENESIS, 0
        prev = json.loads(last)
        return prev["hash"], int(prev["seq"])

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock, _locked(self._lockfile):
            prev_hash, last_seq = self._head()
            entry = {"seq": last_seq + 1, "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **event}
            entry["prev_hash"] = prev_hash
            entry["hash"] = entry_hash(entry)
            self._file.seek(0, os.SEEK_END)
            self._file.write(canonical(entry) + b"\n")
            self._file.flush()
            if self.fsync:
                os.fsync(self._file.fileno())
            self._known = (self._file.tell(), entry["hash"], entry["seq"])
        return entry


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    head_hash: str
    error: str | None = None
    line: int | None = None


def verify(path: Path) -> VerifyResult:
    path = Path(path)
    if not path.is_file():
        return VerifyResult(False, 0, GENESIS, f"audit log not found: {path}")
    prev_hash, count, expected_seq = GENESIS, 0, 1
    with open(path, "rb") as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.rstrip(b"\r\n")
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError as e:
                return VerifyResult(False, count, prev_hash, f"line {lineno} is not valid JSON ({e.msg})", lineno)
            if not isinstance(entry, dict) or "hash" not in entry:
                return VerifyResult(False, count, prev_hash, f"line {lineno} has no hash field", lineno)
            if entry.get("prev_hash") != prev_hash:
                return VerifyResult(
                    False, count, prev_hash,
                    f"line {lineno} (seq {entry.get('seq')}): prev_hash does not match the previous entry "
                    "- an entry was removed, inserted or reordered", lineno,
                )  # fmt: skip
            if entry_hash(entry) != entry["hash"]:
                return VerifyResult(
                    False, count, prev_hash, f"line {lineno} (seq {entry.get('seq')}): content was modified", lineno
                )
            if entry.get("seq") != expected_seq:
                return VerifyResult(False, count, prev_hash, f"line {lineno}: expected seq {expected_seq}", lineno)
            prev_hash, count, expected_seq = entry["hash"], count + 1, expected_seq + 1
    return VerifyResult(True, count, prev_hash)


def read_entries(path: Path, limit: int | None = None) -> list[dict[str, Any]]:
    """Read entries (oldest first); with ``limit``, only the newest ``limit``."""
    path = Path(path)
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    with open(path, "rb") as f:
        for raw in f:
            raw = raw.strip()
            if raw:
                try:
                    out.append(json.loads(raw))
                except json.JSONDecodeError:
                    out.append({"event": "corrupt_line", "raw": raw[:200].decode("utf-8", "replace")})
    return out[-limit:] if limit else out
