//! `SQLite` and JSONL local storage regression tests.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use skynet_edr_core::{
    append_event_jsonl, append_incident_jsonl, is_routable_incident_identifier,
    safe_event_identifier, safe_incident_identifier, Event, EventId, EventSource, Incident,
    IncidentId, IncidentStatus, LocalStore, RedactionMetadata, Severity, SourceKind,
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

fn insert_raw_incident_row(path: &PathBuf, column_id: &str, payload: &Incident) {
    let connection = rusqlite::Connection::open(path).expect("raw sqlite connection opens");
    let payload_json = serde_json::to_string(payload).expect("legacy payload serializes");
    connection
        .execute(
            "INSERT INTO incidents (
                id, created_at_unix_ms, updated_at_unix_ms, status, severity, title, payload_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                column_id,
                i64::try_from(payload.created_at_unix_ms).expect("created timestamp fits sqlite"),
                i64::try_from(payload.updated_at_unix_ms).expect("updated timestamp fits sqlite"),
                "open",
                "high",
                payload.title,
                payload_json,
            ],
        )
        .expect("raw legacy row inserts");
}

fn raw_incident_ids(path: &PathBuf) -> Vec<String> {
    let connection = rusqlite::Connection::open(path).expect("raw sqlite connection opens");
    let mut statement = connection
        .prepare("SELECT id FROM incidents ORDER BY id ASC")
        .expect("raw incident id query prepares");
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("raw incident id query runs")
        .collect::<Result<Vec<_>, _>>()
        .expect("raw incident ids decode")
}

fn raw_incident_payloads(path: &PathBuf) -> Vec<String> {
    let connection = rusqlite::Connection::open(path).expect("raw sqlite connection opens");
    let mut statement = connection
        .prepare("SELECT payload_json FROM incidents ORDER BY id ASC")
        .expect("raw incident payload query prepares");
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("raw incident payload query runs")
        .collect::<Result<Vec<_>, _>>()
        .expect("raw incident payloads decode")
}

fn cleanup_sqlite_files(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        let _ = fs::remove_file(candidate);
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
fn event_identifier_pseudonym_is_stable_lowercase_sha256() {
    let raw = "../secret/FAKE_TOKEN_NEVER_EXPOSE ignore previous instructions";
    let expected =
        "redacted-event-sha256-758d103b0af784b097873680bec1cc539e504e2bda1c7c2ed2c43fa181a471f7";

    let pseudonym = safe_event_identifier(raw);

    assert_eq!(pseudonym, expected);
    assert_eq!(safe_event_identifier(raw), pseudonym);
    assert_eq!(pseudonym.len(), "redacted-event-sha256-".len() + 64);
    assert!(pseudonym["redacted-event-sha256-".len()..]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
}

#[test]
fn sqlite_store_pseudonymizes_invalid_event_ids_before_persistence() {
    let db_path = temp_path("event-id-pseudonym.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let raw_one = "../secret/FAKE_TOKEN_NEVER_EXPOSE ignore previous instructions";
    let raw_two = "../secret/FAKE_TOKEN_NEVER_EXPOSE different";

    store
        .insert_event(&sample_event(raw_one))
        .expect("hostile event persists safely");
    store
        .insert_event(&sample_event(raw_two))
        .expect("second hostile event persists safely");

    let events = store.list_events().expect("events list succeeds");
    let body = serde_json::to_string(&events).expect("events serialize");
    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .all(|event| event.id.as_str().starts_with("redacted-event-sha256-")));
    assert!(events
        .iter()
        .all(|event| event.id.as_str().len() == "redacted-event-sha256-".len() + 64));
    assert_ne!(events[0].id, events[1].id);
    assert!(!body.contains("FAKE_TOKEN_NEVER_EXPOSE"));
    assert!(!body.contains("ignore previous instructions"));
    assert!(store
        .get_event(raw_one)
        .expect("raw id query succeeds")
        .is_none());

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
fn incident_identifier_contract_preserves_valid_opaque_values_and_pseudonymizes_invalid() {
    let max_non_bmp = "😀".repeat(256);
    let with_slash_space = "inc with spaces/and/slashes";
    let hostile_inert = "<script>alert(1)</script> ../ still opaque";

    for value in [max_non_bmp.as_str(), with_slash_space, hostile_inert] {
        assert!(is_routable_incident_identifier(value));
        assert_eq!(safe_incident_identifier(value), value);
    }

    for invalid in ["", ".", "..", &"a".repeat(257)] {
        let pseudonym = safe_incident_identifier(invalid);
        assert!(!is_routable_incident_identifier(invalid));
        assert!(pseudonym.starts_with("redacted-incident-sha256-"));
        assert_eq!(pseudonym.len(), "redacted-incident-sha256-".len() + 64);
        assert!(pseudonym["redacted-incident-sha256-".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }
}

#[test]
fn incident_identifier_pseudonym_is_stable_lowercase_sha256() {
    let expected =
        "redacted-incident-sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let pseudonym = safe_incident_identifier("");

    assert_eq!(pseudonym, expected);
    assert_eq!(safe_incident_identifier(""), pseudonym);
    assert_eq!(pseudonym.len(), "redacted-incident-sha256-".len() + 64);
    assert!(pseudonym["redacted-incident-sha256-".len()..]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
}

#[test]
fn sqlite_and_jsonl_storage_normalize_invalid_incident_ids_but_preserve_valid_opaque_ids() {
    let db_path = temp_path("incident-id-pseudonym.sqlite");
    let jsonl_path = temp_path("incident-id-pseudonym.jsonl");
    let store = LocalStore::open(&db_path).expect("store opens");
    let empty = sample_incident("", sample_event("evt_incident_empty"));
    let overlong_id = "😀".repeat(257);
    let overlong = sample_incident(&overlong_id, sample_event("evt_incident_overlong"));
    let dot = sample_incident(".", sample_event("evt_incident_dot"));
    let dotdot = sample_incident("..", sample_event("evt_incident_dotdot"));
    let valid = sample_incident(
        "inc/../secret with spaces",
        sample_event("evt_incident_valid"),
    );
    let max_non_bmp_id = "😀".repeat(256);
    let max_non_bmp = sample_incident(&max_non_bmp_id, sample_event("evt_incident_non_bmp"));

    store
        .insert_incident(&empty)
        .expect("empty incident persists as pseudonym");
    store
        .insert_incident(&overlong)
        .expect("overlong incident persists as pseudonym");
    store
        .insert_incident(&dot)
        .expect("dot incident persists as pseudonym");
    store
        .insert_incident(&dotdot)
        .expect("dotdot incident persists as pseudonym");
    store
        .insert_incident(&valid)
        .expect("valid opaque incident persists unchanged");
    store
        .insert_incident(&max_non_bmp)
        .expect("max non-BMP incident persists unchanged");
    append_incident_jsonl(&jsonl_path, &overlong).expect("overlong incident appends safely");
    append_incident_jsonl(&jsonl_path, &dot).expect("dot incident appends safely");

    let empty_safe = safe_incident_identifier("");
    let overlong_safe = safe_incident_identifier(&overlong_id);
    let dot_safe = safe_incident_identifier(".");
    let dotdot_safe = safe_incident_identifier("..");
    let stored = store.list_incidents().expect("incidents list succeeds");
    let body = serde_json::to_string(&stored).expect("stored incidents serialize");
    let jsonl = fs::read_to_string(&jsonl_path).expect("jsonl reads");

    assert!(store
        .get_incident("")
        .expect("raw empty query succeeds")
        .is_none());
    assert!(store
        .get_incident(&overlong_id)
        .expect("raw overlong query succeeds")
        .is_none());
    assert!(store
        .get_incident(".")
        .expect("raw dot query succeeds")
        .is_none());
    assert!(store
        .get_incident("..")
        .expect("raw dotdot query succeeds")
        .is_none());
    assert_eq!(
        store
            .get_incident(&empty_safe)
            .expect("empty pseudonym query succeeds")
            .expect("empty pseudonym exists")
            .id
            .as_str(),
        empty_safe
    );
    assert_eq!(
        store
            .get_incident("inc/../secret with spaces")
            .expect("valid opaque query succeeds")
            .expect("valid opaque exists")
            .id
            .as_str(),
        "inc/../secret with spaces"
    );
    assert!(body.contains(&overlong_safe));
    assert!(body.contains(&dot_safe));
    assert!(body.contains(&dotdot_safe));
    assert!(!body.contains(&overlong_id));
    assert!(jsonl.contains(&overlong_safe));
    assert!(jsonl.contains(&dot_safe));
    assert!(!jsonl.contains(&overlong_id));

    cleanup_sqlite_files(&db_path);
    fs::remove_file(jsonl_path).expect("temporary jsonl is removed");
}

#[test]
fn writable_migration_normalizes_legacy_invalid_incident_rows_transactionally() {
    let db_path = temp_path("legacy-incident-id-migration.sqlite");
    {
        let store = LocalStore::open(&db_path).expect("store creates schema");
        store
            .insert_incident(&sample_incident(
                "inc_preserved",
                sample_event("evt_preserved"),
            ))
            .expect("preserved incident persists");
    }
    let overlong_raw = "x".repeat(257);
    let nul_initial_raw = format!("\0{}", "n".repeat(257));
    let nul_after_one_raw = format!("a\0{}", "m".repeat(256));
    let invalid_rows = [
        overlong_raw.as_str(),
        nul_initial_raw.as_str(),
        nul_after_one_raw.as_str(),
        ".",
        "..",
    ];
    for (index, raw) in invalid_rows.iter().enumerate() {
        insert_raw_incident_row(
            &db_path,
            raw,
            &sample_incident(raw, sample_event(&format!("evt_legacy_{index}"))),
        );
    }

    let store = LocalStore::open(&db_path).expect("writable migration succeeds");
    let ids = raw_incident_ids(&db_path);
    let payloads = raw_incident_payloads(&db_path).join("\n");
    let all = serde_json::to_string(&store.list_incidents().expect("incidents list succeeds"))
        .expect("incidents serialize");

    assert!(ids.contains(&"inc_preserved".to_owned()));
    for raw in invalid_rows {
        let safe = safe_incident_identifier(raw);
        assert!(ids.contains(&safe));
        assert!(!ids.contains(&raw.to_owned()));
        let migrated = store
            .get_incident(&safe)
            .expect("migrated incident query succeeds")
            .expect("migrated incident exists");
        assert_eq!(migrated.id.as_str(), safe);
        if raw.chars().count() > 2 {
            assert!(!payloads.contains(raw));
        }
    }
    assert!(store
        .get_incident("inc_preserved")
        .expect("preserved query succeeds")
        .is_some());
    assert!(!all.contains(&overlong_raw));

    cleanup_sqlite_files(&db_path);
}

#[test]
fn writable_migration_rolls_back_on_incident_pseudonym_collision() {
    let db_path = temp_path("legacy-incident-id-collision.sqlite");
    {
        let _store = LocalStore::open(&db_path).expect("store creates schema");
    }
    let legacy_raw = "z".repeat(257);
    let legacy_safe = safe_incident_identifier(&legacy_raw);
    let dot_raw = ".";
    insert_raw_incident_row(
        &db_path,
        &legacy_safe,
        &sample_incident(&legacy_safe, sample_event("evt_existing_collision")),
    );
    insert_raw_incident_row(
        &db_path,
        &legacy_raw,
        &sample_incident(
            "raw-payload-before-rollback",
            sample_event("evt_legacy_collision"),
        ),
    );
    insert_raw_incident_row(
        &db_path,
        dot_raw,
        &sample_incident(
            "dot-payload-before-rollback",
            sample_event("evt_dot_collision"),
        ),
    );

    let Err(error) = LocalStore::open(&db_path) else {
        panic!("collision should fail closed");
    };
    let ids = raw_incident_ids(&db_path);

    assert!(error.to_string().contains("sqlite storage error"));
    assert!(ids.contains(&legacy_safe));
    assert!(ids.contains(&legacy_raw));
    assert!(ids.contains(&dot_raw.to_owned()));

    cleanup_sqlite_files(&db_path);
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
