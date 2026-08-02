import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
PLUGIN = ROOT / "integrations/hermes/skynet-edr/__init__.py"
CORPUS = ROOT / "crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json"


class Context:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, callback):
        self.hooks[name] = callback


def load_plugin():
    spec = importlib.util.spec_from_file_location("skynet_edr_s2_producer", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def has_live_shape(rule_id, events):
    def attrs(event):
        return event.get("attributes", {})

    attack = any(
        event["event_type"] == "agent.content.ingested"
        and attrs(event).get("contains_instructional_attack") is True
        for event in events
    )
    if rule_id == "EDR-MCP-001":
        return attack and any(event["event_type"] == "agent.mcp.tool.requested" and attrs(event).get("network_indicator") is True for event in events)
    if rule_id == "EDR-PI-001":
        return attack and any(event["event_type"] == "agent.tool.requested" and attrs(event).get("network_indicator") is True and attrs(event).get("sensitive_access") is True for event in events)
    if rule_id == "EDR-MSG-001":
        return attack and any(attrs(event).get("delivery_indicator") is True and attrs(event).get("sensitive_access") is True for event in events)
    if rule_id == "EDR-NET-001":
        return attack and any(event["event_type"] == "agent.network.egress" and attrs(event).get("direct_ip") is True for event in events)
    if rule_id == "EDR-CRON-001":
        return attack and any(event["event_type"] == "agent.automation.scheduled" and attrs(event).get("persistence_indicator") is True for event in events)
    if rule_id == "EDR-EXFIL-001":
        return any(attrs(event).get("sensitive_access") is True for event in events) and any(attrs(event).get("network_indicator") is True or attrs(event).get("delivery_indicator") is True for event in events)
    if rule_id == "EDR-MALWARE-001":
        return any(
            event["event_type"] == "agent.tool.completed"
            and attrs(event).get("malware_indicator") is True
            and attrs(event).get("malware_signature")
            in {"eicar_test_string", "skynet_fake_malware_test_string"}
            for event in events
        )
    return False


class DetectionCorpusProducerConformance(unittest.TestCase):
    def test_real_registered_hooks_conform_to_versioned_live_corpus(self):
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertEqual(len(corpus["live_rules"]), 7)
        for case in corpus["cases"]:
            if not case["producer_calls"]:
                continue
            with self.subTest(case=case["case_id"]), tempfile.TemporaryDirectory() as state:
                os.environ["SKYNET_EDR_STATE_DIR"] = state
                os.environ["SKYNET_EDR_INGEST_SOCKET"] = str(Path(state) / "ingest.sock")
                plugin = load_plugin()
                plugin._session_trace_id = "s2-producer-" + case["case_id"]
                sent = []

                def capture(line):
                    sent.append(json.loads(line))
                    return "persisted"

                ctx = Context()
                with patch.object(plugin, "_send_health_report", return_value=True), patch.object(plugin, "_send_frame", side_effect=capture):
                    plugin.register(ctx)
                    self.assertEqual(set(ctx.hooks), {"on_session_start", "on_session_end", "pre_llm_call", "pre_tool_call", "post_tool_call"})
                    for invocation in case["producer_calls"]:
                        started = time.monotonic()
                        ctx.hooks[invocation["hook"]](*invocation["args"], **invocation["kwargs"])
                        self.assertLess(time.monotonic() - started, 0.05)
                    plugin._event_queue.join()

                plugin._worker_stop.set()
                if plugin._worker_thread is not None:
                    plugin._worker_thread.join(timeout=2)
                serialized = json.dumps(sent, sort_keys=True)
                for marker in case["forbidden_markers"]:
                    self.assertNotIn(marker, serialized)
                self.assertTrue(sent)
                for event in sent:
                    self.assertEqual(event["schema_version"], "skynet.event.v0")
                    self.assertEqual(event["source"]["sensor"], "skynet-edr-hermes-plugin")
                    self.assertNotIn("params", event)
                    self.assertNotIn("result", event)
                matched = has_live_shape(case["rule_id"], sent)
                self.assertEqual(matched, case["expected_match"], case["case_id"])

    def test_dark_and_unsupported_rules_are_not_live_producer_cases(self):
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertEqual(
            {case["rule_id"] for case in corpus["cases"] if case["category"] == "producer_dark"},
            {"EDR-CONFIG-001", "EDR-SCOPE-001", "EDR-PERSIST-001"},
        )
        self.assertNotIn("EDR-SECRET-001", corpus["live_rules"])

    def test_hostile_classifier_is_bounded_without_stringifying_objects(self):
        plugin = load_plugin()

        class Hostile:
            def __str__(self):
                raise AssertionError("hostile object was stringified")

        cyclic = {"command": ["curl http://192.0.2.1", Hostile()]}
        cyclic["cycle"] = cyclic
        result = plugin._bounded_selected_text(cyclic, plugin._PARAM_CLASSIFICATION_KEYS)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(result["examined_chars"], plugin._CLASSIFICATION_MAX_TOTAL_BYTES)


if __name__ == "__main__":
    unittest.main()
