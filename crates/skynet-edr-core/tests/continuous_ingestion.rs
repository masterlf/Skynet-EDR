//! Transactional continuous-ingestion regression tests.

use std::{
    fs,
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use rusqlite::Connection;
use skynet_edr_core::{
    built_in_ai_agent_sequence_rules, parse_canonical_event_json, ContinuousIngestStatus,
    LocalStore,
};

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "skynet-edr-continuous-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn canonical_event(
    id: &str,
    event_type: &str,
    observed_at_unix_ms: u64,
    trace_id: &str,
    attributes: serde_json::Value,
) -> skynet_edr_core::CanonicalEventEnvelope {
    let trust_level = if event_type == "agent.content.ingested" {
        "untrusted_content"
    } else {
        "agent_action"
    };
    parse_canonical_event_json(
        &serde_json::json!({
            "schema_version": "skynet.event.v0",
            "event_id": id,
            "event_type": event_type,
            "observed_at_unix_ms": observed_at_unix_ms,
            "received_at_unix_ms": observed_at_unix_ms,
            "severity": "high",
            "source": {"kind": "sensor", "sensor": "continuous-ingest-test", "integration": "hermes"},
            "provenance": {
                "producer": "hermes-agent",
                "collector": "skynet-edr-hermes-forwarder",
                "tenant": "fake-test",
                "source_event_id": id,
                "trace_id": trace_id,
                "span_id": id,
                "parent_span_id": null
            },
            "trust_level": trust_level,
            "title": "Clearly fake continuous ingestion test event",
            "details": null,
            "attributes": attributes,
            "redaction": {"contains_sensitive_data": false, "redacted_fields": []}
        })
        .to_string(),
    )
    .expect("test event is canonical")
}

#[test]
fn replay_is_immutable_and_returns_duplicate_without_overwrite() {
    let db_path = temp_path("immutable.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let rules = built_in_ai_agent_sequence_rules();
    let original = canonical_event(
        "evt_continuous_immutable",
        "agent.tool.requested",
        10_000,
        "trace_immutable",
        serde_json::json!({"network_indicator": false}),
    );

    let first = store
        .commit_continuous_event("uid:1000", &original, &rules, 10_000)
        .expect("first commit succeeds");
    assert_eq!(first.status, ContinuousIngestStatus::Persisted);

    let replay = store
        .commit_continuous_event("uid:1000", &original, &rules, 10_000)
        .expect("replay is accepted idempotently");
    assert_eq!(replay.status, ContinuousIngestStatus::Duplicate);
    let mut conflicting = original.clone();
    conflicting.title = "Attacker tried to overwrite an existing event".to_owned();
    let collision = store
        .commit_continuous_event("uid:1000", &conflicting, &rules, 10_000)
        .expect("conflicting replay is a bounded collision outcome");
    assert_eq!(collision.status, ContinuousIngestStatus::Collision);
    assert_eq!(
        store
            .get_event("evt_continuous_immutable")
            .expect("lookup succeeds")
            .expect("event exists")
            .title,
        "Clearly fake continuous ingestion test event"
    );
    assert_eq!(store.count_ingest_receipts().expect("receipt count"), 1);

    let receipt_time: i64 = Connection::open(&db_path)
        .expect("inspection connection")
        .query_row(
            "SELECT committed_at_unix_ms FROM ingest_receipts WHERE event_id = ?1",
            ["evt_continuous_immutable"],
            |row| row.get(0),
        )
        .expect("receipt timestamp");
    assert!(
        receipt_time > 10_000,
        "receipt time must be server-generated"
    );

    let _ = fs::remove_file(db_path);
}

#[test]
fn fast_writable_open_requires_a_current_pre_migrated_schema() {
    let db_path = temp_path("fast-open-schema.sqlite");
    drop(Connection::open(&db_path).expect("raw sqlite opens"));

    let error = match LocalStore::open_existing_writable(&db_path) {
        Ok(_) => panic!("unmigrated schema must fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("schema version"), "{error}");

    drop(LocalStore::open(&db_path).expect("startup migration succeeds"));
    drop(LocalStore::open_existing_writable(&db_path).expect("current schema opens quickly"));

    let _ = fs::remove_file(db_path);
}

#[test]
fn late_event_correlates_incrementally_inside_derived_window() {
    let db_path = temp_path("late.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let rules = built_in_ai_agent_sequence_rules();
    let action = canonical_event(
        "evt_continuous_late_action",
        "agent.tool.requested",
        1_781_600_030_000,
        "trace_late",
        serde_json::json!({"network_indicator": true, "sensitive_access": true}),
    );
    let prompt = canonical_event(
        "evt_continuous_late_prompt",
        "agent.content.ingested",
        1_781_600_000_000,
        "trace_late",
        serde_json::json!({
            "instruction_authority": false,
            "contains_instructional_attack": true
        }),
    );

    store
        .commit_continuous_event("uid:1000", &action, &rules, 10_000)
        .expect("later action commits first");
    let result = store
        .commit_continuous_event("uid:1000", &prompt, &rules, 10_000)
        .expect("late first event commits");

    assert_eq!(result.max_rule_window_ms, 60_000);
    assert_eq!(result.opened_incidents, 1);
    assert_eq!(store.count_incidents().expect("incident count"), 1);
    assert!(result.candidate_events <= 2);

    let _ = fs::remove_file(db_path);
}

#[test]
fn incident_failure_rolls_back_event_incident_and_receipt() {
    let db_path = temp_path("rollback.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let rules = built_in_ai_agent_sequence_rules();
    let prompt = canonical_event(
        "evt_continuous_rollback_prompt",
        "agent.content.ingested",
        1_781_600_000_000,
        "trace_rollback",
        serde_json::json!({
            "instruction_authority": false,
            "contains_instructional_attack": true
        }),
    );
    store
        .commit_continuous_event("uid:1000", &prompt, &rules, 10_000)
        .expect("first sequence event commits");

    let trigger = rusqlite::Connection::open(&db_path).expect("trigger connection opens");
    trigger
        .execute_batch(
            "CREATE TRIGGER fail_continuous_incident\n             BEFORE INSERT ON incidents\n             BEGIN SELECT RAISE(FAIL, 'forced continuous incident failure'); END;",
        )
        .expect("trigger installs");
    let action = canonical_event(
        "evt_continuous_rollback_action",
        "agent.tool.requested",
        1_781_600_001_000,
        "trace_rollback",
        serde_json::json!({"network_indicator": true, "sensitive_access": true}),
    );

    let error = store
        .commit_continuous_event("uid:1000", &action, &rules, 10_000)
        .expect_err("incident failure must fail the whole transaction");
    assert!(error
        .to_string()
        .contains("forced continuous incident failure"));
    assert!(store
        .get_event("evt_continuous_rollback_action")
        .expect("lookup succeeds")
        .is_none());
    assert_eq!(store.count_incidents().expect("incident count"), 0);
    assert_eq!(store.count_ingest_receipts().expect("receipt count"), 1);

    let _ = fs::remove_file(db_path);
}

#[test]
fn candidate_overflow_persists_evidence_and_reports_degraded_correlation() {
    let db_path = temp_path("overflow.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let rules = built_in_ai_agent_sequence_rules();
    for index in 0..2 {
        let event = canonical_event(
            &format!("evt_continuous_overflow_{index}"),
            "agent.content.ingested",
            1_781_600_000_000 + index,
            "trace_overflow",
            serde_json::json!({"instruction_authority": false, "contains_instructional_attack": false}),
        );
        store
            .commit_continuous_event("uid:1000", &event, &rules, 10_000)
            .expect("seed event commits");
    }
    let event = canonical_event(
        "evt_continuous_overflow_rejected",
        "agent.tool.requested",
        1_781_600_001_000,
        "trace_overflow",
        serde_json::json!({"network_indicator": false, "sensitive_access": false}),
    );

    let result = store
        .commit_continuous_event("uid:1000", &event, &rules, 2)
        .expect("bounded overflow still persists evidence");
    assert_eq!(result.status, ContinuousIngestStatus::Persisted);
    assert!(result.correlation_truncated);
    assert_eq!(result.opened_incidents, 1);
    assert!(store
        .get_event("evt_continuous_overflow_rejected")
        .expect("lookup succeeds")
        .is_some());
    assert_eq!(store.count_ingest_receipts().expect("receipt count"), 3);
    let incident = store
        .list_incidents()
        .expect("incidents list")
        .pop()
        .expect("degraded-correlation incident exists");
    assert_eq!(incident.title, "Continuous correlation degraded");
    assert_eq!(incident.events.len(), 1);
    assert_eq!(
        incident.events[0].id.as_str(),
        "evt_continuous_overflow_rejected"
    );

    let replay = store
        .commit_continuous_event("uid:1000", &event, &rules, 2)
        .expect("overflow trigger replay is idempotent");
    assert_eq!(replay.status, ContinuousIngestStatus::Duplicate);
    assert_eq!(store.count_incidents().expect("incident count"), 1);

    let later_overflow = canonical_event(
        "evt_continuous_overflow_later",
        "agent.tool.requested",
        1_781_600_001_001,
        "trace_overflow",
        serde_json::json!({"network_indicator": false, "sensitive_access": false}),
    );
    let later = store
        .commit_continuous_event("uid:1000", &later_overflow, &rules, 2)
        .expect("distinct overflow commits distinct deduplicated evidence");
    assert!(later.correlation_truncated);
    assert_eq!(later.opened_incidents, 1);
    assert_eq!(store.count_incidents().expect("incident count"), 2);

    let _ = fs::remove_file(db_path);
}

#[test]
fn malicious_sequence_overflow_fails_closed_without_leaking_hostile_payload() {
    let db_path = temp_path("malicious-overflow.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let rules = built_in_ai_agent_sequence_rules();
    let hostile_marker = "FAKE_SECRET_DO_NOT_STORE_123";
    for index in 0..3 {
        let event = canonical_event(
            &format!("evt_malicious_overflow_{index}"),
            "agent.content.ingested",
            1_781_600_000_000 + index,
            "trace_malicious_overflow",
            serde_json::json!({
                "instruction_authority": false,
                "contains_instructional_attack": index == 0,
                "token": hostile_marker
            }),
        );
        store
            .commit_continuous_event("uid:1000", &event, &rules, 10_000)
            .expect("seed event commits");
    }
    let action = canonical_event(
        "evt_malicious_overflow_action",
        "agent.tool.requested",
        1_781_600_001_000,
        "trace_malicious_overflow",
        serde_json::json!({"network_indicator": true, "sensitive_access": true}),
    );

    let result = store
        .commit_continuous_event("uid:1000", &action, &rules, 2)
        .expect("overflow commits degraded evidence atomically");
    assert!(result.correlation_truncated);
    assert_eq!(result.opened_incidents, 1);
    let serialized = serde_json::to_string(&store.list_incidents().expect("incidents list"))
        .expect("incidents serialize");
    assert!(!serialized.contains(hostile_marker));
    assert!(serialized.contains("Continuous correlation degraded"));

    let _ = fs::remove_file(db_path);
}

#[test]
fn collision_evidence_is_durable_deduplicated_and_contains_only_fingerprints() {
    let db_path = temp_path("collision-evidence.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let rules = built_in_ai_agent_sequence_rules();
    let original = canonical_event(
        "evt_collision_evidence",
        "agent.tool.requested",
        10_000,
        "trace_collision",
        serde_json::json!({"network_indicator": false}),
    );
    store
        .commit_continuous_event("uid:1000", &original, &rules, 10_000)
        .expect("original commits");
    let hostile_marker = "FAKE_COLLISION_SECRET_456";
    let mut conflicting = original.clone();
    conflicting.title = hostile_marker.to_owned();

    for _ in 0..2 {
        let collision = store
            .commit_continuous_event("uid:2000", &conflicting, &rules, 10_000)
            .expect("collision evidence commits");
        assert_eq!(collision.status, ContinuousIngestStatus::Collision);
    }
    let mut varied_collision = conflicting.clone();
    varied_collision.title = "Another attacker-controlled collision variant".to_owned();
    let varied = store
        .commit_continuous_event("uid:2000", &varied_collision, &rules, 10_000)
        .expect("varied collision returns terminal status");
    assert_eq!(varied.status, ContinuousIngestStatus::Collision);
    assert_eq!(store.count_ingest_collisions().expect("collision count"), 1);
    let connection = Connection::open(&db_path).expect("inspection connection");
    let evidence: String = connection
        .query_row(
            "SELECT event_fingerprint || source_fingerprint FROM ingest_collisions",
            [],
            |row| row.get(0),
        )
        .expect("collision evidence exists");
    assert!(!evidence.contains(hostile_marker));
    assert!(evidence.len() <= 160);
    assert_eq!(store.count_ingest_receipts().expect("receipt count"), 1);

    let _ = fs::remove_file(db_path);
}

#[test]
fn writable_open_waits_boundedly_for_concurrent_writer_and_makes_progress() {
    let db_path = temp_path("busy-timeout.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    let lock = Connection::open(&db_path).expect("lock connection opens");
    lock.execute_batch("BEGIN IMMEDIATE")
        .expect("writer lock acquired");
    let (sender, receiver) = mpsc::channel();
    let worker_path = db_path.clone();
    let event = canonical_event(
        "evt_busy_timeout_progress",
        "agent.tool.requested",
        10_000,
        "trace_busy_timeout",
        serde_json::json!({"network_indicator": false}),
    );
    let started = Instant::now();
    let worker = thread::spawn(move || {
        let result = LocalStore::open(&worker_path).and_then(|store| {
            store
                .commit_continuous_event(
                    "uid:1000",
                    &event,
                    &built_in_ai_agent_sequence_rules(),
                    10_000,
                )
                .map(|_| ())
                .map_err(|error| match error {
                    skynet_edr_core::ContinuousIngestError::Storage(error) => error,
                    other => panic!("unexpected ingest error: {other}"),
                })
        });
        sender.send(result).expect("worker result sends");
    });
    assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
    lock.execute_batch("COMMIT").expect("writer lock releases");
    receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("bounded busy wait finishes")
        .expect("write progresses after lock release");
    assert!(started.elapsed() < Duration::from_secs(3));
    worker.join().expect("worker joins");

    let _ = fs::remove_file(db_path);
}

#[test]
fn authenticated_sources_are_isolated_for_correlation_and_event_id_collisions() {
    let db_path = temp_path("source-isolation.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let rules = built_in_ai_agent_sequence_rules();
    let prompt = canonical_event(
        "evt_continuous_source_prompt",
        "agent.content.ingested",
        1_781_600_000_000,
        "shared_untrusted_trace",
        serde_json::json!({
            "instruction_authority": false,
            "contains_instructional_attack": true
        }),
    );
    let action = canonical_event(
        "evt_continuous_source_action",
        "agent.tool.requested",
        1_781_600_001_000,
        "shared_untrusted_trace",
        serde_json::json!({"network_indicator": true, "sensitive_access": true}),
    );

    store
        .commit_continuous_event("uid:1000", &prompt, &rules, 10_000)
        .expect("first source commits");
    let isolated = store
        .commit_continuous_event("uid:2000", &action, &rules, 10_000)
        .expect("second source commits without cross-principal correlation");
    assert_eq!(isolated.opened_incidents, 0);
    assert_eq!(store.count_incidents().expect("incident count"), 0);

    let collision = store
        .commit_continuous_event("uid:2000", &prompt, &rules, 10_000)
        .expect("event-id collision is a bounded protocol outcome");
    assert_eq!(collision.status, ContinuousIngestStatus::Collision);
    assert_eq!(store.count_ingest_receipts().expect("receipt count"), 2);

    let _ = fs::remove_file(db_path);
}
