#!/usr/bin/env python3
"""Bounded, read-only evidence checks for the disposable public live journey."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote

MAX_BYTES = 4 * 1024 * 1024
MAX_ROWS = 256
FORBIDDEN_MARKER = "FAKE_SKYNET_EDR_ALPHA2_SECRET_DO_NOT_EXPOSE"
SAFE_REPLY = "SKYNET_EDR_SAFE_DETECTION_OK"
RULE = "EDR-MALWARE-001"
TOOL = "skynet_edr_safe_detection_simulation"
DB = Path("/var/lib/skynet-edr/skynet.sqlite")


class EvidenceError(ValueError):
    """A failed check identified by a fixed string from this verifier."""


def require(condition: bool, category: str) -> None:
    if not condition:
        raise EvidenceError(category)


def enrollment_diagnostic(value: dict) -> dict:
    """Expose only fixed enrollment codes, never private paths or payloads."""
    states = {
        "ABSENT",
        "DRIFTED",
        "ENROLLED",
        "DEGRADED",
        "RELOAD_REQUIRED",
        "ROLLBACK_REQUIRED",
        "MANUAL_RECOVERY_REQUIRED",
    }
    categories = {
        "invalid_input",
        "identity",
        "root_denied",
        "ownership",
        "untrusted_ancestor",
        "untrusted_path",
        "unsupported_contract",
        "authorization",
        "payload_identity",
        "invalid_target",
        "untrusted_runtime",
        "internal_failure",
        "enrollment_state",
        "adapter_failure",
        "unsupported_layout",
        "observation_failure",
        "installed_state",
        "enablement",
        "reload_boundary",
        "producer_health",
        "active_transaction",
    }
    return {
        "state": value.get("state") if value.get("state") in states else "unknown",
        "category": value.get("category")
        if value.get("category") in categories
        else "unknown",
    }


def reject_duplicate_keys(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode_json(data: bytes | str) -> dict | list:
    require(len(data) <= MAX_BYTES, "JSON size limit")

    def reject_constant(_value: str) -> None:
        raise ValueError("nonstandard JSON constant")

    value = json.loads(
        data, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_constant
    )
    require(type(value) in (dict, list), "JSON object or array required")
    return value


def redaction_check(value: object) -> None:
    require(FORBIDDEN_MARKER not in json.dumps(value), "redaction check")


def read_json(path: Path) -> dict | list:
    with path.open("rb") as stream:
        return decode_json(stream.read(MAX_BYTES + 1))


def source_fingerprint(source_id: str) -> str:
    material = ("skynet-edr-authenticated-source-v1\0" + source_id).encode()
    return "source-sha256-" + hashlib.sha256(material).hexdigest()


def read_snapshot(path: Path = DB) -> dict:
    connection = sqlite3.connect(
        path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5
    )
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        events = connection.execute(
            "SELECT payload_json, ingest_source_id FROM events ORDER BY id LIMIT ?",
            (MAX_ROWS + 1,),
        ).fetchall()
        incidents = connection.execute(
            "SELECT payload_json FROM incidents ORDER BY id LIMIT ?", (MAX_ROWS + 1,)
        ).fetchall()
        receipts = connection.execute(
            "SELECT event_id, source_id FROM ingest_receipts ORDER BY event_id LIMIT ?",
            (MAX_ROWS + 1,),
        ).fetchall()
        require(
            max(map(len, (events, incidents, receipts))) <= MAX_ROWS, "store row limit"
        )
        result = {
            "events": [
                {"event": decode_json(row[0]), "source": row[1]} for row in events
            ],
            "incidents": [decode_json(row[0]) for row in incidents],
            "receipts": [{"event_id": row[0], "source_id": row[1]} for row in receipts],
        }
        redaction_check(result)
        return result
    finally:
        connection.close()


def get_api(path: str) -> dict:
    # No proxy, DNS lookup, redirects, or caller-selected destination.
    connection = http.client.HTTPConnection("127.0.0.1", 8787, timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        require(response.status == 200, "API HTTP status")
        value = decode_json(response.read(MAX_BYTES + 1))
        require(type(value) is dict, "API object required")
        redaction_check(value)
        return value
    finally:
        connection.close()


def verify_dispatch(value: dict) -> None:
    redaction_check(value)
    require(
        value.get("jsonrpc") == "2.0"
        and value.get("id") == "public-journey"
        and value.get("error") is None,
        "dispatch envelope",
    )
    result = value.get("result", {})
    require(
        result.get("status", {}).get("state") == "TASK_STATE_COMPLETED",
        "dispatch completion",
    )
    artifacts = result.get("artifacts", [])
    require(
        len(artifacts) == 1
        and artifacts[0].get("parts")
        and [part.get("text") for part in artifacts[0]["parts"]] == [SAFE_REPLY],
        "dispatch reply",
    )


def verify_chain(
    before: dict,
    after: dict,
    status: dict,
    listing: dict,
    detail: dict,
    uid: int,
    generation: str,
    gateway_pid: int,
) -> dict:
    for value in (before, after, status, listing, detail):
        redaction_check(value)
    require(before["incidents"] == [], "baseline must contain no incidents")
    baseline_ids = {row["event"]["id"] for row in before["events"]}
    completed = [
        row
        for row in after["events"]
        if row["event"]["id"] not in baseline_ids
        and row["event"].get("attributes", {}).get("event_type")
        == "agent.tool.completed"
        and row["event"]["attributes"].get("tool_name") == TOOL
    ]
    require(len(completed) == 1, "one fresh simulation event required")
    event = completed[0]["event"]
    attrs = event["attributes"]
    require(
        attrs.get("rule_id") == RULE
        and attrs.get("malware_indicator") is True
        and attrs.get("result_omitted") is True,
        "simulation classification",
    )
    ingestion = status.get("ingestion", {})
    require(
        ingestion.get("state") == "healthy" and ingestion.get("listener_live") is True,
        "ingestion health",
    )
    sources = [
        source
        for source in ingestion.get("sources", [])
        if type(source.get("authenticated_uid")) is int
        and source["authenticated_uid"] == uid
        and source.get("runtime_role") == "gateway"
        and source.get("plugin_generation") == generation
        and source.get("kernel_peer_pid") == gateway_pid
        and source.get("protocol_version") == 3
        and source.get("s3_eligible") is True
        and source.get("transport_state") == "available"
        and all(
            source.get(key) == 0
            for key in (
                "backlog_bytes",
                "events_dropped_total",
                "events_malformed_total",
            )
        )
    ]
    require(len(sources) == 1, "one healthy authenticated gateway source required")
    source_id = source_fingerprint(sources[0]["source_id"])
    require(completed[0]["source"] == source_id, "event source binding")
    receipts = [
        receipt for receipt in after["receipts"] if receipt["event_id"] == event["id"]
    ]
    require(
        len(receipts) == 1 and receipts[0]["source_id"] == source_id,
        "receipt source binding",
    )
    require(len(after["incidents"]) == 1, "exactly one incident required")
    incident = after["incidents"][0]
    require(
        incident.get("severity") == "high"
        and [item["id"] for item in incident.get("events", [])] == [event["id"]],
        "incident event binding",
    )
    require(
        listing.get("page", {}).get("has_more") is False
        and [item.get("id") for item in listing.get("items", [])] == [incident["id"]],
        "API list binding",
    )
    require(
        detail.get("schema_version") == "skynet.risk.v1"
        and detail.get("id") == incident["id"]
        and detail.get("rule_id") == RULE
        and detail.get("severity") == "high",
        "API incident binding",
    )
    require(
        [item.get("event_id") for item in detail.get("evidence", [])] == [event["id"]],
        "API evidence binding",
    )
    return {"incident_id": incident["id"], "event_id": event["id"], "rule_id": RULE}


def verify_session(path: Path) -> None:
    connection = sqlite3.connect(
        path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5
    )
    try:
        rows = connection.execute(
            "SELECT role, tool_calls, content FROM messages ORDER BY id LIMIT ?",
            (MAX_ROWS + 1,),
        ).fetchall()
    finally:
        connection.close()
    require(len(rows) <= MAX_ROWS, "session row limit")
    called = []
    results = []
    for role, calls, content in rows:
        redaction_check((calls, content))
        if calls:
            called.extend(
                call.get("function", {}).get("name") for call in decode_json(calls)
            )
        if role == "tool" and content and '"detection_signal"' in content:
            result = decode_json(content)
            results.append(result)
    require(
        called == ["tool_search", "tool_describe", "tool_call"],
        "real deferred dispatch sequence",
    )
    require(
        len(results) == 1
        and results[0].get("delivery_status") == "persisted"
        and results[0].get("detection_signal") == "submitted",
        "live accepting ACK required",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("snapshot", "verify", "enrollment-diagnostic"))
    parser.add_argument("--enrollment-result", type=Path)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--dispatch", type=Path)
    parser.add_argument("--session-db", type=Path)
    parser.add_argument("--uid", type=int)
    parser.add_argument("--generation")
    parser.add_argument("--gateway-pid", type=int)
    args = parser.parse_args()
    try:
        if args.mode == "enrollment-diagnostic":
            print(
                json.dumps(
                    enrollment_diagnostic(read_json(args.enrollment_result)),
                    sort_keys=True,
                )
            )
            return 0
        after = read_snapshot()
        if args.mode == "snapshot":
            require(after["incidents"] == [], "baseline must contain no incidents")
            result = after
        else:
            require(
                all(
                    value is not None
                    for value in (
                        args.before,
                        args.dispatch,
                        args.session_db,
                        args.uid,
                        args.generation,
                        args.gateway_pid,
                    )
                ),
                "missing verification input",
            )
            verify_dispatch(read_json(args.dispatch))
            verify_session(args.session_db)
            require(len(after["incidents"]) == 1, "exactly one incident required")
            incident_id = after["incidents"][0]["id"]
            result = verify_chain(
                read_json(args.before),
                after,
                get_api("/api/status"),
                get_api("/api/v1/risks"),
                get_api("/api/v1/risks/" + quote(incident_id, safe="")),
                args.uid,
                args.generation,
                args.gateway_pid,
            )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        OSError,
        sqlite3.Error,
        http.client.HTTPException,
        RecursionError,
    ) as error:
        # Only our fixed check labels may be exposed; parser/I/O text stays private.
        check = (
            str(error)
            if isinstance(error, EvidenceError)
            else "unavailable or malformed evidence"
        )
        print(
            json.dumps({"status": "FAIL", "stage": "evidence", "check": check}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
