from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from agent_guard.audit import GENESIS, AuditLog, entry_hash, read_entries, verify
from agent_guard.cli import main as cli_main


def write_log(path: Path, n: int = 5) -> AuditLog:
    log = AuditLog(path)
    for i in range(n):
        log.append({"event": "tool_call", "tool_id": f"t.{i}", "decision": "allowed", "arguments": {"i": i}})
    return log


def lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_chain_is_valid(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path).close()
    entries = read_entries(path)
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5]
    assert entries[0]["prev_hash"] == GENESIS
    for prev, cur in zip(entries, entries[1:]):
        assert cur["prev_hash"] == prev["hash"]
    assert all(entry_hash(e) == e["hash"] for e in entries)
    res = verify(path)
    assert res.ok and res.entries == 5 and res.head_hash == entries[-1]["hash"]


def test_reopen_continues_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path, 2).close()
    write_log(path, 2).close()
    assert verify(path).ok
    assert [e["seq"] for e in read_entries(path)] == [1, 2, 3, 4]


def _rewrite(path: Path, new_lines: list[str]) -> None:
    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def test_detects_modified_entry(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path).close()
    ls = lines(path)
    e = json.loads(ls[2])
    e["decision"] = "denied"  # attacker edits a decision
    ls[2] = json.dumps(e)
    _rewrite(path, ls)
    res = verify(path)
    assert not res.ok and res.line == 3 and "modified" in (res.error or "")


def test_detects_modified_entry_with_recomputed_hash(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path).close()
    ls = lines(path)
    e = json.loads(ls[1])
    e["arguments"] = {"i": 999}
    e["hash"] = entry_hash(e)  # attacker recomputes this entry's hash...
    ls[1] = json.dumps(e)
    _rewrite(path, ls)
    res = verify(path)  # ...but the next entry's prev_hash no longer matches
    assert not res.ok and res.line == 3 and "prev_hash" in (res.error or "")


def test_detects_deleted_and_reordered_entries(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path).close()
    ls = lines(path)
    _rewrite(path, ls[:2] + ls[3:])
    assert not verify(path).ok
    _rewrite(path, [ls[1], ls[0], *ls[2:]])
    assert not verify(path).ok


def test_detects_garbage_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path).close()
    ls = lines(path)
    _rewrite(path, ls[:3] + ["not json"] + ls[3:])
    res = verify(path)
    assert not res.ok and "not valid JSON" in (res.error or "")


def test_missing_log(tmp_path: Path) -> None:
    assert not verify(tmp_path / "nope.jsonl").ok


def test_concurrent_appends_keep_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    logs = [AuditLog(path) for _ in range(3)]  # separate instances, like separate processes

    def worker(log: AuditLog) -> None:
        for i in range(30):
            log.append({"event": "tool_call", "i": i})

    threads = [threading.Thread(target=worker, args=(log,)) for log in logs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for log in logs:
        log.close()
    res = verify(path)
    assert res.ok, res.error
    assert res.entries == 90


def test_cli_verify_log(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path).close()
    assert cli_main(["verify-log", str(path)]) == 0
    assert "hash chain intact" in capsys.readouterr().out
    ls = lines(path)
    _rewrite(path, ls[:-2] + ls[-1:])
    assert cli_main(["verify-log", str(path)]) == 1
    assert "TAMPERED" in capsys.readouterr().err
