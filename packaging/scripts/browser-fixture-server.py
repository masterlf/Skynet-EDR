#!/usr/bin/env python3
"""Bounded producer-owned status fixture server for the disposable browser lane."""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_STATUS_BYTES = 262_144
RISK_PAGE = {
    "schema_version": "skynet.risk.v1", "read_only": True, "items": [],
    "page": {"limit": 50, "offset": 0, "returned": 0, "total": 0, "has_more": False},
}


class FixtureHandler(BaseHTTPRequestHandler):
    status_document: dict[str, object]

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._json(200, {"status": "ok"})
        elif self.path == "/api/status":
            self._json(200, self.status_document)
        elif self.path.startswith("/api/v1/risks"):
            self._json(200, RISK_PAGE)
        else:
            self._json(404, {"error": "not_found"})

    def _json(self, status: int, document: object) -> None:
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--status", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port is out of range")
    raw = args.status.read_bytes()
    if len(raw) > MAX_STATUS_BYTES:
        parser.error("status fixture is too large")
    status = json.loads(raw.decode())
    if not isinstance(status, dict):
        parser.error("status fixture must be an object")
    FixtureHandler.status_document = status
    ThreadingHTTPServer(("127.0.0.1", args.port), FixtureHandler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
