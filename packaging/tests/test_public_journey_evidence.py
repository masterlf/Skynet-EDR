from __future__ import annotations

import copy
import importlib.util
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "journey", ROOT / "packaging/scripts/public_journey_evidence.py"
)
journey = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(journey)


class PublicJourneyEvidenceTests(unittest.TestCase):
    def test_cli_reports_failed_check_but_never_parser_exception_text(self):
        for error, expected in (
            (journey.EvidenceError("ingestion health"), "ingestion health"),
            (ValueError(journey.FORBIDDEN_MARKER), "unavailable or malformed evidence"),
        ):
            output = io.StringIO()
            with (
                patch("sys.argv", ["journey", "snapshot"]),
                patch.object(journey, "read_snapshot", side_effect=error),
                patch("sys.stderr", output),
            ):
                self.assertEqual(journey.main(), 1)
            value = json.loads(output.getvalue())
            self.assertEqual(value["check"], expected)
            self.assertNotIn(journey.FORBIDDEN_MARKER, output.getvalue())

    def test_enrollment_diagnostics_only_report_known_public_codes(self):
        self.assertEqual(
            journey.enrollment_diagnostic(
                {"state": "DRIFTED", "category": "ownership"}
            ),
            {"state": "DRIFTED", "category": "ownership"},
        )
        self.assertEqual(
            journey.enrollment_diagnostic(
                {
                    "state": journey.FORBIDDEN_MARKER,
                    "category": "private_value",
                    "raw": "hidden",
                }
            ),
            {"state": "unknown", "category": "unknown"},
        )

    def setUp(self):
        self.source = {
            "source_id": "uid:1234:gateway:" + "a" * 64 + ":" + "b" * 64,
            "authenticated_uid": 1234,
            "runtime_role": "gateway",
            "protocol_version": 3,
            "s3_eligible": True,
            "plugin_generation": "a" * 64,
            "kernel_peer_pid": 5678,
            "transport_state": "available",
            "backlog_bytes": 0,
            "events_dropped_total": 0,
            "events_malformed_total": 0,
        }
        self.event = {
            "id": "evt_journey_test",
            "severity": "high",
            "attributes": {
                "event_type": "agent.tool.completed",
                "tool_name": "skynet_edr_safe_detection_simulation",
                "rule_id": "EDR-MALWARE-001",
                "malware_indicator": True,
                "result_omitted": True,
            },
        }
        self.incident = {
            "id": "inc:EDR-MALWARE-001:test",
            "severity": "high",
            "events": [self.event],
        }
        self.after = {
            "events": [
                {
                    "event": self.event,
                    "source": journey.source_fingerprint(self.source["source_id"]),
                }
            ],
            "incidents": [self.incident],
            "receipts": [
                {
                    "event_id": self.event["id"],
                    "source_id": journey.source_fingerprint(self.source["source_id"]),
                }
            ],
        }
        self.before = {"events": [], "incidents": [], "receipts": []}
        self.status = {
            "ingestion": {
                "state": "healthy",
                "listener_live": True,
                "sources": [self.source],
            }
        }
        self.detail = {
            "schema_version": "skynet.risk.v1",
            "id": self.incident["id"],
            "rule_id": "EDR-MALWARE-001",
            "severity": "high",
            "evidence": [{"event_id": self.event["id"], "rule_id": "EDR-MALWARE-001"}],
        }
        self.listing = {"items": [dict(self.detail)], "page": {"has_more": False}}

    def verify(self):
        return journey.verify_chain(
            self.before,
            self.after,
            self.status,
            self.listing,
            self.detail,
            1234,
            "a" * 64,
            5678,
        )

    def test_same_event_is_bound_across_receipt_incident_and_api(self):
        result = self.verify()
        self.assertEqual(result["event_id"], self.event["id"])
        self.assertEqual(result["incident_id"], self.incident["id"])

    def test_old_incident_cannot_satisfy_new_dispatch(self):
        self.before = copy.deepcopy(self.after)
        with self.assertRaisesRegex(ValueError, "baseline"):
            self.verify()

    def test_missing_receipt_cannot_pass_even_when_incident_exists(self):
        self.after["receipts"] = []
        with self.assertRaisesRegex(ValueError, "receipt"):
            self.verify()

    def test_receipt_from_different_producer_is_rejected(self):
        self.after["receipts"][0]["source_id"] = "source-sha256-" + "c" * 64
        with self.assertRaisesRegex(ValueError, "receipt"):
            self.verify()

    def test_wrong_gateway_uid_pid_generation_or_protocol_is_rejected(self):
        for field, value in (
            ("authenticated_uid", 9),
            ("kernel_peer_pid", 9),
            ("plugin_generation", "c" * 64),
            ("protocol_version", 2),
            ("s3_eligible", False),
            ("events_dropped_total", 1),
        ):
            with self.subTest(field=field):
                previous = self.source[field]
                self.source[field] = value
                with self.assertRaises(ValueError):
                    self.verify()
                self.source[field] = previous

    def test_different_api_evidence_cannot_substitute_for_stored_event(self):
        self.detail["evidence"][0]["event_id"] = "evt_unrelated"
        with self.assertRaisesRegex(ValueError, "API evidence"):
            self.verify()

    def test_duplicate_incidents_fail(self):
        self.after["incidents"].append(copy.deepcopy(self.incident))
        with self.assertRaisesRegex(ValueError, "one incident"):
            self.verify()

    def test_secret_marker_fails_without_echoing_input(self):
        self.detail["unexpected"] = journey.FORBIDDEN_MARKER
        with self.assertRaisesRegex(ValueError, "redaction") as raised:
            self.verify()
        self.assertNotIn(journey.FORBIDDEN_MARKER, str(raised.exception))

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            journey.decode_json(b'{"state":"healthy","state":"degraded"}')

    def test_bounded_json_rejects_oversized_input(self):
        with self.assertRaises(ValueError):
            journey.decode_json(b" " * (journey.MAX_BYTES + 1))

    def test_nonstandard_json_constants_are_rejected(self):
        with self.assertRaises(ValueError):
            journey.decode_json(b'{"value":NaN}')

    def test_snapshot_never_creates_missing_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing.sqlite"
            with self.assertRaises(sqlite3.OperationalError):
                journey.read_snapshot(path)
            self.assertFalse(path.exists())

    def test_snapshot_reads_real_sqlite_rows_without_mutating_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "store.sqlite"
            connection = sqlite3.connect(path)
            connection.executescript(
                "CREATE TABLE events (id TEXT, payload_json TEXT, ingest_source_id TEXT);"
                "CREATE TABLE incidents (id TEXT, payload_json TEXT);"
                "CREATE TABLE ingest_receipts (event_id TEXT, source_id TEXT);"
            )
            source = self.after["events"][0]["source"]
            connection.execute(
                "INSERT INTO events VALUES (?, ?, ?)",
                (self.event["id"], json.dumps(self.event), source),
            )
            connection.execute(
                "INSERT INTO incidents VALUES (?, ?)",
                (self.incident["id"], json.dumps(self.incident)),
            )
            connection.execute(
                "INSERT INTO ingest_receipts VALUES (?, ?)", (self.event["id"], source)
            )
            connection.commit()
            connection.close()
            original = path.read_bytes()
            self.assertEqual(journey.read_snapshot(path), self.after)
            self.assertEqual(path.read_bytes(), original)

    def test_fallback_submission_cannot_pass_live_ack_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "session.sqlite"
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE messages (id INTEGER, role TEXT, tool_calls TEXT, content TEXT)"
            )
            calls = [
                {"function": {"name": name}}
                for name in ("tool_search", "tool_describe", "tool_call")
            ]
            connection.execute(
                "INSERT INTO messages VALUES (1, 'assistant', ?, NULL)",
                (json.dumps(calls),),
            )
            connection.execute(
                "INSERT INTO messages VALUES (2, 'tool', NULL, ?)",
                (
                    json.dumps(
                        {"delivery_status": "spooled", "detection_signal": "submitted"}
                    ),
                ),
            )
            connection.commit()
            with self.assertRaisesRegex(ValueError, "live accepting ACK"):
                journey.verify_session(path)
            connection.execute(
                "UPDATE messages SET content=? WHERE id=2",
                (
                    json.dumps(
                        {
                            "delivery_status": "persisted",
                            "detection_signal": "submitted",
                        }
                    ),
                ),
            )
            connection.commit()
            connection.close()
            journey.verify_session(path)

    def test_dispatch_requires_completed_task_with_exact_reply(self):
        reply = {
            "jsonrpc": "2.0",
            "id": "public-journey",
            "result": {
                "status": {"state": "TASK_STATE_COMPLETED"},
                "artifacts": [{"parts": [{"text": journey.SAFE_REPLY}]}],
            },
        }
        journey.verify_dispatch(reply)
        reply["result"]["status"]["state"] = "TASK_STATE_FAILED"
        with self.assertRaises(ValueError):
            journey.verify_dispatch(reply)


if __name__ == "__main__":
    unittest.main()
