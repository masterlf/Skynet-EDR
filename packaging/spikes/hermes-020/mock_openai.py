#!/usr/bin/env python3
"""Loopback-only OpenAI-compatible fixture for the Hermes 0.20 spike.

This server never performs inference and never accepts remote connections. It
returns a fixed benign response so a real Hermes gateway dispatcher path can be
exercised without credentials or network egress.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

MODEL = "spike-model"
SPIKE_REPLY = "SPIKE_OK"
ENROLLMENT_REPLY = "SKYNET_EDR_ENROLLMENT_OK"
ALLOWED_REPLIES = frozenset({SPIKE_REPLY, ENROLLMENT_REPLY})
FIXED_REPLY = SPIKE_REPLY
MAX_REQUEST_BYTES = 1_048_576
REQUEST_TIMEOUT_SECONDS = 5.0


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _models_response() -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {
                "id": MODEL,
                "object": "model",
                "created": 0,
                "owned_by": "skynet-edr-spike",
            }
        ],
    }


def _completion_response() -> dict[str, Any]:
    return {
        "id": "chatcmpl-skynet-edr-spike",
        "object": "chat.completion",
        "created": 0,
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": FIXED_REPLY},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def _stream_response() -> bytes:
    chunks = [
        {
            "id": "chatcmpl-skynet-edr-spike",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": MODEL,
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant", "content": FIXED_REPLY},
                    "finish_reason": None,
                }
            ],
        },
        {
            "id": "chatcmpl-skynet-edr-spike",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": MODEL,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 1,
                "completion_tokens": 1,
                "total_tokens": 2,
            },
        },
    ]
    frames = [b"data: " + _json_bytes(chunk) + b"\n\n" for chunk in chunks]
    return b"".join(frames) + b"data: [DONE]\n\n"


class FixtureHandler(BaseHTTPRequestHandler):
    """Minimal model listing and Chat Completions surface."""

    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.request.settimeout(REQUEST_TIMEOUT_SECONDS)

    def log_message(self, format: str, *args: object) -> None:
        # This fixture does not log request targets or headers. Even loopback
        # input is untrusted and may contain terminal control characters.
        return

    def _send_json(self, value: Any, status: int = 200) -> None:
        payload = _json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_error(self, status: int, message: str) -> None:
        self.close_connection = True
        self._send_json({"error": message}, status=status)

    def _read_json_object(self) -> dict[str, Any] | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._send_error(411, "content length required")
            return None
        try:
            content_length = int(raw_length)
        except ValueError:
            self._send_error(400, "invalid content length")
            return None
        if content_length < 0:
            self._send_error(400, "invalid content length")
            return None
        if content_length > MAX_REQUEST_BYTES:
            self._send_error(413, "request too large")
            return None

        try:
            request = json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_error(400, "invalid JSON")
            return None
        if not isinstance(request, dict):
            self._send_error(400, "JSON object required")
            return None
        return request

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path in {"/v1/models", "/api/v1/models"}:
            self._send_json(_models_response())
            return
        if self.path == f"/v1/models/{MODEL}":
            self._send_json(_models_response()["data"][0])
            return
        self._send_error(404, "not found")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path not in {"/api/show", "/v1/chat/completions"}:
            self._send_error(404, "not found")
            return
        request = self._read_json_object()
        if request is None:
            return

        if self.path == "/api/show":
            self._send_json({"model": MODEL, "capabilities": ["completion"]})
            return
        if request.get("model") != MODEL:
            self._send_error(400, "unsupported model")
            return
        if not request.get("stream", False):
            self._send_json(_completion_response())
            return

        payload = _stream_response()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    global FIXED_REPLY
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=19000)
    parser.add_argument(
        "--reply", choices=sorted(ALLOWED_REPLIES), default=SPIKE_REPLY,
        help="fixed benign reply contract",
    )
    args = parser.parse_args()
    FIXED_REPLY = args.reply
    server = HTTPServer(("127.0.0.1", args.port), FixtureHandler)
    print(f"fixture listening on 127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
