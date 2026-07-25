"""Read-only Hermes dashboard backend proxy for Skynet-EDR risk data."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

try:  # Hermes provides FastAPI in the plugin backend process.
    from fastapi import APIRouter, HTTPException, Query
except ImportError:  # pragma: no cover - allows py_compile in minimal build envs.
    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str) -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class APIRouter:  # type: ignore[no-redef]
        def get(self, _path: str):
            def decorator(func):
                return func
            return decorator

    def Query(default: int, ge: int | None = None, le: int | None = None):  # noqa: N802
        return default


router = APIRouter()
_DEFAULT_PORT = 8787
_TIMEOUT_SECONDS = 2.0
_MAX_RESPONSE_BYTES = 1_048_576


def _port() -> int:
    raw = os.environ.get("SKYNET_EDR_API_PORT")
    if raw is None:
        return _DEFAULT_PORT
    if not raw.isdecimal():
        return _DEFAULT_PORT
    port = int(raw)
    if 1 <= port <= 65535:
        return port
    return _DEFAULT_PORT


def _upstream(path: str, query: dict[str, int] | None = None) -> Any:
    if not path.startswith("/api/") or ".." in path:
        raise HTTPException(status_code=400, detail="bad_request")
    url = f"http://127.0.0.1:{_port()}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed loopback URL only
            content_type = response.headers.get("Content-Type", "")
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        raise HTTPException(status_code=502, detail="upstream_unavailable") from exc
    if len(body) > _MAX_RESPONSE_BYTES:
        raise HTTPException(status_code=502, detail="upstream_response_too_large")
    if "application/json" not in content_type.lower():
        raise HTTPException(status_code=502, detail="invalid_upstream_content_type")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=502, detail="invalid_upstream_json") from exc


@router.get("/risks")
def risks(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=10000)) -> Any:
    return _upstream("/api/v1/risks", {"limit": int(limit), "offset": int(offset)})


@router.get("/risks/{risk_id}")
def risk_detail(risk_id: str) -> Any:
    quoted = urllib.parse.quote(risk_id, safe="")
    return _upstream(f"/api/v1/risks/{quoted}")


@router.get("/status")
def status() -> Any:
    return _upstream("/api/status")
