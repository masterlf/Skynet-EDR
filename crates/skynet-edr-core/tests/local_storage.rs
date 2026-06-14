//! `SQLite` and JSONL local storage regression tests.

use std::{collections::BTreeMap, fs, path::PathBuf};

use skynet_edr_core::{
    append_event_jsonl, append_incident_jsonl, Event, EventId, EventSource, Incident, IncidentId,
    IncidentStatus, LocalStore, RedactionMetadata, Severity, SourceKind,
};

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "skynet-edr-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

fn no_redaction() -> RedactionMetadata {
    RedactionMetadata {
        contains_sensitive_data: false,
        redacted_fields: Vec::new(),
    }
}

fn sample_source() -> EventSource {
    EventSource {
        kind: SourceKind::McpTool,
        sensor: "storage-test".to_owned(),
        integration: Some("hermes".to_owned()),
    }
}

fn sample_event(id: &str) -> Event {
    let mut attributes = BTreeMap::new();
    attributes.insert("tool".to_owned(), serde_json::json!("shell"));

    Event {
        id: EventId::new(id),
        observed_at_unix_ms: 1_781_440_123_000,
        severity: Severity::High,
        source: sample_source(),
        title: "MCP shell invocation".to_owned(),
        details: Some("Tool execution was already redacted before storage.".to_owned()),
        attributes,
        redaction: no_redaction(),
    }
}

fn sample_incident(id: &str, event: Event) -> Incident {
    Incident {
        id: IncidentId::new(id),
        created_at_unix_ms: 1_781_440_123_000,
        updated_at_unix_ms: 1_781_440_124_000,
        status: IncidentStatus::Open,
        severity: Severity::High,
        title: "Suspicious MCP tool chain".to_owned(),
        summary: "Shell-capable MCP tool requires triage.".to_owned(),
        source: sample_source(),
        events: vec![event],
        redaction: no_redaction(),
    }
}

fn unredacted_secret_event(id: &str) -> Event {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "api_token".to_owned(),
        serde_json::json!("sk_live_fake_token"),
    );
    attributes.insert(
        "path".to_owned(),
        serde_json::json!("/home/alice/.ssh/id_rsa"),
    );

    Event {
        id: EventId::new(id),
        observed_at_unix_ms: 1_781_440_125_000,
        severity: Severity::Critical,
        source: sample_source(),
        title: "Authorization: Bearer fake-secret-title".to_owned(),
        details: Some("password=super-secret Authorization: Bearer fake-secret".to_owned()),
        attributes,
        redaction: no_redaction(),
    }
}

fn event_with_hostile_redaction_metadata(id: &str) -> Event {
    let mut event = sample_event(id);
    event.redaction = RedactionMetadata {
        contains_sensitive_data: true,
        redacted_fields: vec![skynet_edr_core::RedactedField {
            path: "metadata.password".to_owned(),
            reason: skynet_edr_core::RedactionReason::Secret,
            replacement: "metadata-secret-value".to_owned(),
        }],
    };
    event
}

#[test]
fn sqlite_store_persists_events_and_incidents() {
    let db_path = temp_path("store.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens and migrates schema");
    let event = sample_event("evt_sqlite_1");
    let incident = sample_incident("inc_sqlite_1", event.clone());

    store.insert_event(&event).expect("event is persisted");
    store
        .insert_incident(&incident)
        .expect("incident is persisted");

    let loaded_event = store
        .get_event(event.id.as_str())
        .expect("event query succeeds")
        .expect("event exists");
    assert_eq!(loaded_event, event);

    let loaded_incident = store
        .get_incident(incident.id.as_str())
        .expect("incident query succeeds")
        .expect("incident exists");
    assert_eq!(loaded_incident, incident);

    let incidents = store.list_incidents().expect("incidents list succeeds");
    assert_eq!(incidents, vec![incident]);

    fs::remove_file(db_path).expect("temporary db is removed");
}

#[test]
fn sqlite_store_redacts_untrusted_event_payloads_before_persistence() {
    let db_path = temp_path("redacted-store.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let event = unredacted_secret_event("evt_secret_storage");
    let incident = sample_incident("inc_secret_storage", event);

    store
        .insert_incident(&incident)
        .expect("incident with untrusted fields is persisted redacted");

    let loaded_incident = store
        .get_incident("inc_secret_storage")
        .expect("incident query succeeds")
        .expect("incident exists");
    let loaded_event = store
        .get_event("evt_secret_storage")
        .expect("event query succeeds")
        .expect("event exists");
    let serialized_incident = serde_json::to_string(&loaded_incident).expect("incident serializes");
    let serialized_event = serde_json::to_string(&loaded_event).expect("event serializes");

    assert!(!serialized_incident.contains("fake-secret"));
    assert!(!serialized_incident.contains("super-secret"));
    assert!(!serialized_incident.contains("sk_live_fake_token"));
    assert!(!serialized_incident.contains("/home/alice"));
    assert!(!serialized_event.contains("fake-secret"));
    assert!(!serialized_event.contains("super-secret"));
    assert!(!serialized_event.contains("sk_live_fake_token"));
    assert!(!serialized_event.contains("/home/alice"));
    assert!(loaded_event.redaction.contains_sensitive_data);
    assert!(loaded_incident.events[0].redaction.contains_sensitive_data);

    fs::remove_file(db_path).expect("temporary db is removed");
}

#[test]
fn sqlite_store_normalizes_hostile_redaction_metadata_before_persistence() {
    let db_path = temp_path("metadata-redaction.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let incident = sample_incident(
        "inc_metadata_redaction",
        event_with_hostile_redaction_metadata("evt_metadata_redaction"),
    );

    store
        .insert_incident(&incident)
        .expect("incident with hostile metadata is persisted safely");

    let loaded_incident = store
        .get_incident("inc_metadata_redaction")
        .expect("incident query succeeds")
        .expect("incident exists");
    let serialized = serde_json::to_string(&loaded_incident).expect("incident serializes");

    assert!(!serialized.contains("metadata-secret-value"));
    assert!(serialized.contains("[REDACTED:secret]"));

    fs::remove_file(db_path).expect("temporary db is removed");
}

#[test]
fn sqlite_store_upserts_events_without_duplicate_rows() {
    let db_path = temp_path("upsert.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let mut event = sample_event("evt_upsert");

    store.insert_event(&event).expect("initial insert succeeds");
    event.title = "Updated title".to_owned();
    store.insert_event(&event).expect("upsert succeeds");

    let events = store.list_events().expect("events list succeeds");
    assert_eq!(events, vec![event]);

    fs::remove_file(db_path).expect("temporary db is removed");
}

#[test]
fn jsonl_export_appends_one_event_per_line() {
    let jsonl_path = temp_path("events.jsonl");
    let first = sample_event("evt_jsonl_1");
    let second = sample_event("evt_jsonl_2");

    append_event_jsonl(&jsonl_path, &first).expect("first event appends");
    append_event_jsonl(&jsonl_path, &second).expect("second event appends");

    let content = fs::read_to_string(&jsonl_path).expect("jsonl file is readable");
    let lines = content.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);

    let decoded_first: Event = serde_json::from_str(lines[0]).expect("first line is event JSON");
    let decoded_second: Event = serde_json::from_str(lines[1]).expect("second line is event JSON");
    assert_eq!(decoded_first.id.as_str(), "evt_jsonl_1");
    assert_eq!(decoded_second.id.as_str(), "evt_jsonl_2");

    fs::remove_file(jsonl_path).expect("temporary jsonl is removed");
}

#[test]
fn jsonl_export_appends_one_incident_per_line() {
    let jsonl_path = temp_path("incidents.jsonl");
    let first = sample_incident("inc_jsonl_1", sample_event("evt_jsonl_incident_1"));
    let second = sample_incident("inc_jsonl_2", sample_event("evt_jsonl_incident_2"));

    append_incident_jsonl(&jsonl_path, &first).expect("first incident appends");
    append_incident_jsonl(&jsonl_path, &second).expect("second incident appends");

    let content = fs::read_to_string(&jsonl_path).expect("jsonl file is readable");
    let lines = content.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);

    let decoded_first: Incident =
        serde_json::from_str(lines[0]).expect("first line is incident JSON");
    let decoded_second: Incident =
        serde_json::from_str(lines[1]).expect("second line is incident JSON");
    assert_eq!(decoded_first.id.as_str(), "inc_jsonl_1");
    assert_eq!(decoded_second.id.as_str(), "inc_jsonl_2");

    fs::remove_file(jsonl_path).expect("temporary jsonl is removed");
}
