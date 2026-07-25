"""Read-only Hermes dashboard backend proxy for Skynet-EDR risk data."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()
_DEFAULT_PORT = 8787
_TIMEOUT_SECONDS = 2.0
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_OFFSET = 9_007_199_254_740_991
_MAX_RISK_ID_CODEPOINTS = 256
_MAX_RISK_ID_ENCODED_CHARS = 3_072


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(req.full_url, code, "redirect denied", headers, fp)


_opener = urllib.request.build_opener(_NoRedirect)


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


def _bounded_page(limit: int, offset: int) -> dict[str, int]:
    try:
        bounded_limit = int(limit)
        bounded_offset = int(offset)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="bad_request") from exc
    if not 1 <= bounded_limit <= 100 or not 0 <= bounded_offset <= _MAX_OFFSET:
        raise HTTPException(status_code=400, detail="bad_request")
    return {"limit": bounded_limit, "offset": bounded_offset}


def _valid_upstream_path(path: str) -> bool:
    if path in {"/api/status", "/api/v1/risks"}:
        return True
    prefix = "/api/v1/risks/"
    if not path.startswith(prefix):
        return False
    opaque_id = path[len(prefix) :]
    if not opaque_id or "/" in opaque_id:
        return False
    decoded = urllib.parse.unquote(opaque_id)
    if decoded in {".", ".."} and opaque_id == decoded:
        return False
    return True


def _valid_risk_id(risk_id: str) -> bool:
    if not risk_id or len(risk_id) > _MAX_RISK_ID_CODEPOINTS:
        return False
    try:
        quoted = urllib.parse.quote(risk_id, safe="")
    except UnicodeError:
        return False
    return len(quoted) <= _MAX_RISK_ID_ENCODED_CHARS


def _upstream(path: str, query: dict[str, int] | None = None) -> Any:
    if not _valid_upstream_path(path):
        raise HTTPException(status_code=400, detail="bad_request")
    url = f"http://127.0.0.1:{_port()}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with _opener.open(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed loopback URL only
            content_type = response.headers.get("Content-Type", "")
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and path.startswith("/api/v1/risks/"):
            raise HTTPException(status_code=404, detail="risk_not_found") from exc
        raise HTTPException(status_code=502, detail="upstream_unavailable") from exc
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


def _quote_risk_id(risk_id: str) -> str:
    if risk_id == ".":
        return "%2E"
    if risk_id == "..":
        return "%2E%2E"
    return urllib.parse.quote(risk_id, safe="")


@router.get("/risks")
def risks(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=_MAX_OFFSET)) -> Any:
    return _upstream("/api/v1/risks", _bounded_page(limit, offset))


@router.get("/risks/{risk_id:path}")
def risk_detail(risk_id: str) -> Any:
    if not _valid_risk_id(risk_id):
        raise HTTPException(status_code=400, detail="bad_request")
    quoted = _quote_risk_id(risk_id)
    return _upstream(f"/api/v1/risks/{quoted}")


@router.get("/status")
def status() -> Any:
    return _upstream("/api/status")
