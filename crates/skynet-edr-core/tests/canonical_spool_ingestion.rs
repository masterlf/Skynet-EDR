//! Live canonical JSONL spool ingestion regression tests.

use std::{fs, path::PathBuf};

use skynet_edr_core::{ingest_canonical_jsonl_spool, LocalStore, Severity};

const CANONICAL_EVENT: &str = include_str!("fixtures/canonical_event_v0.json");

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "skynet-edr-core-spool-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

fn variant_event(id: &str, title: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(CANONICAL_EVENT).expect("fixture JSON");
    value["event_id"] = serde_json::json!(id);
    value["title"] = serde_json::json!(title);
    serde_json::to_string(&value).expect("variant serializes")
}

fn plugin_sequence_event(
    id: &str,
    event_type: &str,
    observed_at_unix_ms: u64,
    trust_level: &str,
    severity: &str,
    trace_id: &str,
    attributes: &serde_json::Value,
) -> String {
    serde_json::json!({
        "schema_version": "skynet.event.v0",
        "event_id": id,
        "event_type": event_type,
        "observed_at_unix_ms": observed_at_unix_ms,
        "received_at_unix_ms": observed_at_unix_ms,
        "severity": severity,
        "source": {"kind": "sensor", "sensor": "skynet-edr-hermes-plugin", "integration": "hermes"},
        "provenance": {
            "producer": "hermes-agent",
            "collector": "skynet-edr-hermes-plugin",
            "tenant": "local-hermes",
            "source_event_id": id,
            "trace_id": trace_id,
            "span_id": id,
            "parent_span_id": null
        },
        "trust_level": trust_level,
        "title": "plugin-shaped canonical event",
        "details": null,
        "attributes": attributes,
        "redaction": {"contains_sensitive_data": false, "redacted_fields": []}
    })
    .to_string()
}

#[test]
fn live_spool_ingestion_skips_malformed_lines_and_counts_dropped_events() {
    let db_path = temp_path("malformed.sqlite");
    let spool_path = temp_path("malformed.jsonl");
    let checkpoint_path = temp_path("malformed.offset");
    let good_event = variant_event("evt_spool_good", "Spool accepted canonical event");
    fs::write(&spool_path, format!("{good_event}\n{{not-json\n\n")).expect("spool is written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("malformed lines are accounted, not fatal");

    assert_eq!(summary.ingested_events, 1);
    assert_eq!(summary.dropped_events, 1);
    assert_eq!(summary.malformed_lines, vec![2]);
    assert_eq!(summary.duplicate_events, 0);
    assert!(store
        .get_event("evt_spool_good")
        .expect("event lookup succeeds")
        .is_some());
    assert_eq!(store.list_events().expect("events list").len(), 1);
    assert_eq!(
        fs::read_to_string(&checkpoint_path).expect("checkpoint exists"),
        summary.last_processed_byte.to_string()
    );

    let replay = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("restarting from checkpoint is safe");
    assert_eq!(replay.ingested_events, 0);
    assert_eq!(replay.dropped_events, 0);
    assert_eq!(store.list_events().expect("events list").len(), 1);

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn live_spool_ingestion_is_idempotent_and_processes_only_complete_lines() {
    let db_path = temp_path("restart.sqlite");
    let spool_path = temp_path("restart.jsonl");
    let checkpoint_path = temp_path("restart.offset");
    let first_event = variant_event("evt_spool_once", "Spool event ingested once");
    let second_event = variant_event("evt_spool_after_restart", "Spool event after restart");
    fs::write(&spool_path, format!("{first_event}\n{second_event}"))
        .expect("partial spool is written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let first = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("complete lines ingest");

    assert_eq!(first.ingested_events, 1);
    assert_eq!(first.dropped_events, 0);
    assert!(store
        .get_event("evt_spool_once")
        .expect("event lookup succeeds")
        .is_some());
    assert!(store
        .get_event("evt_spool_after_restart")
        .expect("event lookup succeeds")
        .is_none());

    fs::write(
        &spool_path,
        format!("{first_event}\n{second_event}\n{first_event}\n"),
    )
    .expect("spool gains complete tail and duplicate event id");
    let second = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("restart ingests only new complete lines");

    assert_eq!(second.ingested_events, 1);
    assert_eq!(second.duplicate_events, 1);
    assert_eq!(second.dropped_events, 0);
    assert_eq!(store.list_events().expect("events list").len(), 2);

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn live_spool_ingestion_ignores_partial_non_utf8_tail_without_losing_complete_events() {
    let db_path = temp_path("partial-utf8.sqlite");
    let spool_path = temp_path("partial-utf8.jsonl");
    let checkpoint_path = temp_path("partial-utf8.offset");
    let complete_event = variant_event(
        "evt_spool_before_partial_utf8",
        "Complete before UTF-8 tail",
    );
    let mut spool = format!("{complete_event}\n").into_bytes();
    spool.push(0xC3);
    fs::write(&spool_path, spool).expect("spool with partial UTF-8 tail is written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("partial non-UTF-8 tail is ignored until complete");

    assert_eq!(summary.ingested_events, 1);
    assert_eq!(summary.dropped_events, 0);
    assert!(store
        .get_event("evt_spool_before_partial_utf8")
        .expect("event lookup succeeds")
        .is_some());
    assert_eq!(
        fs::read_to_string(&checkpoint_path).expect("checkpoint exists"),
        format!("{}", complete_event.len() + 1)
    );

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn live_spool_ingestion_resets_stale_checkpoint_after_spool_truncation() {
    let db_path = temp_path("truncated.sqlite");
    let spool_path = temp_path("truncated.jsonl");
    let checkpoint_path = temp_path("truncated.offset");
    let replacement_event = variant_event("evt_spool_after_truncate", "Spool event after truncate");
    fs::write(&spool_path, format!("{replacement_event}\n")).expect("replacement spool written");
    fs::write(&checkpoint_path, "999999").expect("stale checkpoint written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("stale checkpoint is reset after truncation");

    assert_eq!(summary.ingested_events, 1);
    assert_eq!(summary.dropped_events, 0);
    assert!(store
        .get_event("evt_spool_after_truncate")
        .expect("event lookup succeeds")
        .is_some());
    assert_eq!(
        fs::read_to_string(&checkpoint_path).expect("checkpoint exists"),
        summary.last_processed_byte.to_string()
    );

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn live_spool_ingestion_opens_built_in_incident_for_cross_line_trace_sequence_once() {
    let db_path = temp_path("sequence-incident.sqlite");
    let spool_path = temp_path("sequence-incident.jsonl");
    let checkpoint_path = temp_path("sequence-incident.offset");
    let prompt = plugin_sequence_event(
        "evt_spool_pi",
        "agent.content.ingested",
        1_781_560_000_000,
        "untrusted_content",
        "medium",
        "trace_spool_sensitive",
        &serde_json::json!({
            "instruction_authority": false,
            "contains_instructional_attack": true
        }),
    );
    let tool = plugin_sequence_event(
        "evt_spool_terminal",
        "agent.tool.requested",
        1_781_560_001_000,
        "agent_action",
        "high",
        "trace_spool_sensitive",
        &serde_json::json!({
            "tool_name": "terminal",
            "network_indicator": true,
            "delivery_indicator": false,
            "sensitive_access": true,
            "params_preview": "[REDACTED:secret]"
        }),
    );
    fs::write(&spool_path, format!("{prompt}\n{tool}\n")).expect("spool is written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("sequence spool ingests");

    assert_eq!(summary.ingested_events, 2);
    assert_eq!(summary.opened_incidents, 1);
    let incidents = store.list_incidents().expect("incident list succeeds");
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].severity, Severity::High);
    assert!(incidents[0].id.as_str().starts_with("inc:EDR-PI-001:"));
    assert!(!incidents[0].title.contains("trace_spool_sensitive"));
    assert!(!incidents[0].summary.contains("trace_spool_sensitive"));
    assert!(!incidents[0].summary.contains("evt_spool_pi"));

    let replay = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("duplicate polling is safe");
    assert_eq!(replay.ingested_events, 0);
    assert_eq!(replay.opened_incidents, 0);
    assert_eq!(
        store
            .list_incidents()
            .expect("incident list succeeds")
            .len(),
        1
    );

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn live_spool_ingestion_does_not_open_incident_for_benign_spool() {
    let db_path = temp_path("benign-sequence.sqlite");
    let spool_path = temp_path("benign-sequence.jsonl");
    let checkpoint_path = temp_path("benign-sequence.offset");
    let benign = plugin_sequence_event(
        "evt_spool_benign_content",
        "agent.content.ingested",
        1_781_560_000_000,
        "untrusted_content",
        "informational",
        "trace_spool_benign",
        &serde_json::json!({
            "instruction_authority": false,
            "contains_instructional_attack": false
        }),
    );
    let tool = plugin_sequence_event(
        "evt_spool_benign_tool",
        "agent.tool.requested",
        1_781_560_001_000,
        "agent_action",
        "low",
        "trace_spool_benign",
        &serde_json::json!({
            "tool_name": "read_file",
            "network_indicator": false,
            "delivery_indicator": false,
            "sensitive_access": false
        }),
    );
    fs::write(&spool_path, format!("{benign}\n{tool}\n")).expect("spool is written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("benign spool ingests");

    assert_eq!(summary.ingested_events, 2);
    assert_eq!(summary.opened_incidents, 0);
    assert!(store
        .list_incidents()
        .expect("incident list succeeds")
        .is_empty());

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}
