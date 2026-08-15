# Skynet-EDR v0.6.0 protection matrix

Generated from `docs/coverage/v0.6.0.json`; direct edits fail the suite contract check.

Passive detection and evidence only. No prevention, blocking, containment, quarantine, approval, or guard mode is provided.

| Surface | Status | Scenario evidence | Evidence | Limitation |
|---|---|---|---|---|
| EDR-CRON-001 | DETECTED_AND_TESTED | [`malicious_cron`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`near_miss_cron`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | offline engine replay plus shipped Hermes producer fixture | Only authoritative successful built-in cronjob create/update results. |
| EDR-EXFIL-001 | DETECTED_AND_TESTED | [`malicious_exfil`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`near_miss_exfil`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`secret_exfil_redaction`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | offline bounded correlator replay plus shipped Hermes producer fixture | Reviewed narrow shapes, same source/join, ordering, and 60-second window only. |
| EDR-MALWARE-001 | DETECTED_AND_TESTED | [`malicious_malware`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`near_miss_malware`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | offline bounded correlator replay plus shipped Hermes producer fixture | Exact allowlisted safe marker and reviewed omitted-output shape only. |
| EDR-MCP-001 | DETECTED_AND_TESTED | [`malicious_mcp`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`near_miss_mcp`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | offline canonical sequence replay plus shipped Hermes producer fixture | Recognized network-capable MCP request in the same trace only. |
| EDR-MSG-001 | DETECTED_AND_TESTED | [`malicious_msg`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`near_miss_msg`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`secret_message_redaction`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | offline canonical sequence replay plus shipped Hermes producer fixture | Recognized sensitive delivery request shape only. |
| EDR-NET-001 | DETECTED_AND_TESTED | [`malicious_net`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`near_miss_net`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | offline canonical sequence replay plus shipped Hermes producer fixture | Recognized explicit IPv4 destination with direct_ip=true only. |
| EDR-PI-001 | DETECTED_AND_TESTED | [`malicious_pi`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`near_miss_pi`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | offline canonical sequence replay plus shipped Hermes producer fixture | Typed instructional attack followed by sensitive network tool request only. |
| EDR-CONFIG-001 | NOT_COVERED | [`dark_edr_config_001`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | documented skipped scenario | Shipped Hermes producer has no authoritative post-save event. |
| EDR-PERSIST-001 | NOT_COVERED | [`dark_edr_persist_001`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | documented skipped scenario | Shipped Hermes producer has no authoritative persistence mutation event. |
| EDR-SCOPE-001 | NOT_COVERED | [`dark_edr_scope_001`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | documented skipped scenario | Shipped Hermes hook precedes persisted scope expansion. |
| EDR-SECRET-001 | NOT_COVERED | — | no shipped standalone correlator | Roadmap candidate only. |
| EXTERNAL-CANONICAL-PRODUCER | PARTIAL | — | engine unit fixtures only | Requires an external conforming redacted producer; no shipped live adapter. |
| HOSTILE-MALFORMED | DETECTED_AND_TESTED | [`hostile_bounded_recursive`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`hostile_malformed_json`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`hostile_truncated_frame`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json), [`hostile_unknown_type`](../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json) | offline strict canonical parser rejection fixtures | Bounded representative malformed inputs; not an exhaustive parser proof. |
| REAL-HERMES-DISPATCHER-ABI | NOT_TESTED | — | callbacks are invoked directly by fixtures | This suite does not exercise real Hermes discovery or dispatcher ABI. |

`DETECTED_AND_TESTED` is bounded fixture evidence, not a universal security guarantee. `PARTIAL`, `NOT_TESTED`, and `NOT_COVERED` must not be presented as shipped protection.

Generate deterministic evidence with `python3 packaging/scripts/threat-validation.py`; the default output is `target/threat-validation/evidence.json`.
