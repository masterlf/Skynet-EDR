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
SAFE_DETECTION_REPLY = "SKYNET_EDR_SAFE_DETECTION_OK"
SAFE_DETECTION_TOOL = "skynet_edr_safe_detection_simulation"
ALLOWED_REPLIES = frozenset({SPIKE_REPLY, ENROLLMENT_REPLY})
FIXED_REPLY = SPIKE_REPLY
FIXTURE_MODE = "fixed"
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


def _tool_result_count(request: dict[str, Any]) -> int:
    messages = request.get("messages")
    if not isinstance(messages, list):
        return 0
    return sum(
        1
        for message in messages
        if isinstance(message, dict) and message.get("role") == "tool"
    )


def _safe_detection_call(request: dict[str, Any]) -> tuple[str, dict[str, Any], str] | None:
    calls = (
        (
            "tool_search",
            {"query": "skynet edr safe detection simulation", "limit": 5},
            "call_skynet_edr_tool_search",
        ),
        (
            "tool_describe",
            {"name": SAFE_DETECTION_TOOL},
            "call_skynet_edr_tool_describe",
        ),
        (
            "tool_call",
            {"name": SAFE_DETECTION_TOOL, "arguments": {"scenario": "malware-marker"}},
            "call_skynet_edr_safe_detection",
        ),
    )
    index = _tool_result_count(request)
    return calls[index] if index < len(calls) else None


def _tool_call_message(request: dict[str, Any]) -> dict[str, Any]:
    call = _safe_detection_call(request)
    if call is None:
        raise ValueError("safe detection sequence is complete")
    name, arguments, call_id = call
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(arguments, separators=(",", ":"), sort_keys=True),
                },
            }
        ],
    }


def _completion_response(request: dict[str, Any]) -> dict[str, Any]:
    safe_detection_pending = FIXTURE_MODE == "safe-detection" and _safe_detection_call(request) is not None
    message = _tool_call_message(request) if safe_detection_pending else {
        "role": "assistant",
        "content": SAFE_DETECTION_REPLY if FIXTURE_MODE == "safe-detection" else FIXED_REPLY,
    }
    return {
        "id": "chatcmpl-skynet-edr-spike",
        "object": "chat.completion",
        "created": 0,
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if safe_detection_pending else "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def _stream_response(request: dict[str, Any]) -> bytes:
    call = _safe_detection_call(request) if FIXTURE_MODE == "safe-detection" else None
    safe_detection_pending = call is not None
    if call is not None:
        name, arguments, call_id = call
        delta = {
            "role": "assistant",
            "tool_calls": [
                {
                    "index": 0,
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": json.dumps(arguments, separators=(",", ":"), sort_keys=True),
                    },
                }
            ],
        }
        finish_reason = "tool_calls"
    else:
        delta = {
            "role": "assistant",
            "content": SAFE_DETECTION_REPLY if FIXTURE_MODE == "safe-detection" else FIXED_REPLY,
        }
        finish_reason = "stop"
    chunks = [
        {
            "id": "chatcmpl-skynet-edr-spike",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": MODEL,
            "choices": [
                {
                    "index": 0,
                    "delta": delta,
                    "finish_reason": None,
                }
            ],
        },
        {
            "id": "chatcmpl-skynet-edr-spike",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": MODEL,
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
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
            self._send_json(_completion_response(request))
            return

        payload = _stream_response(request)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    global FIXED_REPLY, FIXTURE_MODE
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=19000)
    parser.add_argument(
        "--reply", choices=sorted(ALLOWED_REPLIES), default=SPIKE_REPLY,
        help="fixed benign reply contract",
    )
    parser.add_argument(
        "--mode", choices=("fixed", "safe-detection"), default="fixed",
        help="fixed reply or deterministic safe tool-dispatch sequence",
    )
    args = parser.parse_args()
    FIXED_REPLY = args.reply
    FIXTURE_MODE = args.mode
    server = HTTPServer(("127.0.0.1", args.port), FixtureHandler)
    print(f"fixture listening on 127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
