from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from agent_guard.approvals import ApprovalStore
from agent_guard.audit import AuditLog
from agent_guard.config import load_config
from agent_guard.viewer import ViewerApp, make_server
from conftest import write_config


@pytest.fixture
def viewer(tmp_path: Path) -> Iterator[tuple[str, ViewerApp, Path]]:
    cfg = load_config(write_config(tmp_path))
    log = AuditLog(cfg.audit_path)
    log.append({"event": "tool_call", "tool_id": "files.read_file", "decision": "allowed", "agent": "a"})
    log.close()
    httpd, app = make_server(cfg, port=0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", app, cfg.approvals_path
    httpd.shutdown()
    httpd.server_close()


def get(url: str) -> tuple[int, bytes]:
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read()


def post(url: str, body: dict, token: str | None) -> int:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Agent-Guard-Token"] = token
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_page_and_entries(viewer: tuple[str, ViewerApp, Path]) -> None:
    base, app, _ = viewer
    status, page = get(base + "/")
    assert status == 200 and app.token.encode() in page
    status, js = get(base + "/viewer.js")
    assert status == 200 and b"api/entries" in js
    data = json.loads(get(base + "/api/entries")[1])
    assert data["chain"]["ok"] is True
    assert data["entries"][0]["tool_id"] == "files.read_file"


def test_approve_via_web_requires_token(viewer: tuple[str, ViewerApp, Path]) -> None:
    base, app, approvals = viewer
    store = ApprovalStore(approvals)
    req = store.create("payments.refund", "a", {"amount": 250}, "big", None, 30)
    pending = json.loads(get(base + "/api/pending")[1])["pending"]
    assert [p["id"] for p in pending] == [req.id]

    assert post(f"{base}/api/approvals/{req.id}", {"approved": True}, token=None) == 403
    assert post(f"{base}/api/approvals/{req.id}", {"approved": True}, token="wrong") == 403
    assert store.decision(req.id) is None
    assert post(f"{base}/api/approvals/{req.id}", {"approved": True, "note": "fine"}, token=app.token) == 200
    d = store.decision(req.id)
    assert d and d.approved and d.note == "fine" and d.by.endswith("(web)")
    assert post(f"{base}/api/approvals/{req.id}", {"approved": False}, token=app.token) == 400  # already decided


def test_rejects_foreign_host_header(viewer: tuple[str, ViewerApp, Path]) -> None:
    base, _, _ = viewer
    req = urllib.request.Request(base + "/api/entries", headers={"Host": "evil.example:80"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 403
