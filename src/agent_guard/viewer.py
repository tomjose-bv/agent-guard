"""Local web viewer: browse the audit log and approve/deny pending calls.

Standard library only (http.server). Binds to 127.0.0.1 by default.
State-changing requests require a per-run token embedded in the page and a
matching Host header, which blocks cross-site requests and DNS rebinding.
"""

from __future__ import annotations

import json
import os
import secrets
import webbrowser
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import parse_qs, urlparse

from agent_guard.approvals import ApprovalError, ApprovalStore
from agent_guard.audit import read_entries, verify
from agent_guard.config import Config


class ViewerApp:
    def __init__(self, config: Config, token: str | None = None) -> None:
        self.config = config
        self.store = ApprovalStore(config.approvals_path)
        self.token = token or secrets.token_urlsafe(24)
        self.allowed_hosts: set[str] = set()

    def page(self) -> bytes:
        html = resources.files("agent_guard").joinpath("static/viewer.html").read_text(encoding="utf-8")
        return html.replace("__AGENT_GUARD_TOKEN__", self.token).encode("utf-8")

    def entries(self, limit: int) -> dict[str, Any]:
        path = self.config.audit_path
        res = verify(path) if path.exists() else None
        return {
            "path": str(path),
            "entries": list(reversed(read_entries(path, limit=limit))),
            "chain": None if res is None else {"ok": res.ok, "entries": res.entries, "error": res.error, "head": res.head_hash},
        }

    def pending(self) -> dict[str, Any]:
        return {"pending": [asdict(r) for r in self.store.list()]}

    def decide(self, approval_id: str, body: dict[str, Any]) -> dict[str, Any]:
        reviewer = str(body.get("by") or os.environ.get("USERNAME") or os.environ.get("USER") or "web")
        req = self.store.decide(approval_id, bool(body.get("approved")), by=f"{reviewer} (web)", note=body.get("note") or None)
        return {"ok": True, "id": req.id}


def make_handler(app: ViewerApp) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "agent-guard-viewer"

        def log_message(self, format: str, *args: Any) -> None:  # quiet
            pass

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, data: Any) -> None:
            self._send(status, json.dumps(data, default=str).encode("utf-8"), "application/json")

        def _host_ok(self) -> bool:
            return not app.allowed_hosts or self.headers.get("Host", "") in app.allowed_hosts

        def do_GET(self) -> None:
            if not self._host_ok():
                return self._json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                return self._send(HTTPStatus.OK, app.page(), "text/html; charset=utf-8")
            if url.path == "/viewer.js":
                js = resources.files("agent_guard").joinpath("static/viewer.js").read_bytes()
                return self._send(HTTPStatus.OK, js, "text/javascript; charset=utf-8")
            if url.path == "/api/entries":
                limit = int(parse_qs(url.query).get("limit", ["500"])[0])
                return self._json(HTTPStatus.OK, app.entries(max(1, min(limit, 5000))))
            if url.path == "/api/pending":
                return self._json(HTTPStatus.OK, app.pending())
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            url = urlparse(self.path)
            if not self._host_ok() or not secrets.compare_digest(self.headers.get("X-Agent-Guard-Token", ""), app.token):
                return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            if not url.path.startswith("/api/approvals/"):
                return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            length = min(int(self.headers.get("Content-Length") or 0), 64_000)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                return self._json(HTTPStatus.OK, app.decide(url.path.rsplit("/", 1)[-1], body))
            except (ApprovalError, ValueError) as e:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(e)})

    return Handler


def make_server(config: Config, host: str = "127.0.0.1", port: int = 8765) -> tuple[ThreadingHTTPServer, ViewerApp]:
    app = ViewerApp(config)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    real_port = httpd.server_address[1]
    app.allowed_hosts = {f"{h}:{real_port}" for h in ("127.0.0.1", "localhost", host)}
    return httpd, app


def serve(config: Config, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    httpd, _ = make_server(config, host, port)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{httpd.server_address[1]}/"
    print(f"agent-guard viewer on {url}  (Ctrl+C to stop)")
    if host not in ("127.0.0.1", "localhost"):
        print("warning: the viewer has no login; anyone who can reach this address can approve calls.")
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
