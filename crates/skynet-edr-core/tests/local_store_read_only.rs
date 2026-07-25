//! Read-only `SQLite` local store regression tests.

use std::{collections::BTreeMap, fs, path::Path};

use skynet_edr_core::{
    Event, EventId, EventSource, Incident, IncidentId, IncidentStatus, LocalStore,
    RedactionMetadata, Severity, SourceKind,
};

#[test]
fn open_read_only_missing_database_fails_without_creating_db_or_sidecars() {
    let db_path = temp_path("missing-read-only.sqlite");
    cleanup_sqlite_files(&db_path);

    let Err(error) = LocalStore::open_read_only(&db_path) else {
        panic!("missing DB must not open read-only");
    };

    assert!(error.to_string().contains("sqlite"));
    assert!(
        !db_path.exists(),
        "read-only open must not create the DB file"
    );
    assert!(
        !db_path.with_extension("sqlite-wal").exists(),
        "read-only open must not create a WAL sidecar"
    );
    assert!(
        !db_path.with_extension("sqlite-shm").exists(),
        "read-only open must not create a SHM sidecar"
    );
}

#[test]
fn open_read_only_does_not_create_schema_in_empty_existing_file() {
    let db_path = temp_path("empty-existing-read-only.sqlite");
    cleanup_sqlite_files(&db_path);
    fs::write(&db_path, b"").expect("empty placeholder DB file is created");

    let store = LocalStore::open_read_only(&db_path).expect("empty existing file opens read-only");
    let error = store
        .count_incidents()
        .expect_err("read-only constructor must not migrate or create incidents table");

    assert!(error.to_string().contains("no such table: incidents"));
    cleanup_sqlite_files(&db_path);
}

#[test]
fn read_only_store_reads_counts_pages_and_rejects_mutations_without_changes() {
    let db_path = temp_path("read-only-queries.sqlite");
    cleanup_sqlite_files(&db_path);

    {
        let writable = LocalStore::open(&db_path).expect("writable store opens and migrates");
        writable
            .insert_event(&sample_event("evt_read_only_seed"))
            .expect("event persists");
        writable
            .insert_incident(&sample_incident(
                "inc_read_only_seed",
                sample_event("evt_read_only_embedded"),
            ))
            .expect("incident persists");
        assert_eq!(writable.count_events().expect("event count succeeds"), 2);
        assert_eq!(
            writable.count_incidents().expect("incident count succeeds"),
            1
        );
    }

    let read_only = LocalStore::open_read_only(&db_path).expect("read-only store opens");

    assert_eq!(read_only.path(), db_path.as_path());
    assert!(read_only
        .get_event("evt_read_only_seed")
        .expect("read-only event lookup succeeds")
        .is_some());
    assert!(read_only
        .get_incident("inc_read_only_seed")
        .expect("read-only incident lookup succeeds")
        .is_some());
    assert_eq!(read_only.count_events().expect("event count succeeds"), 2);
    assert_eq!(
        read_only
            .count_incidents()
            .expect("incident count succeeds"),
        1
    );
    assert_eq!(
        read_only
            .list_incidents_page(10, 0)
            .expect("read-only page succeeds")
            .len(),
        1
    );

    let event_error = read_only
        .insert_event(&sample_event("evt_rejected_read_only"))
        .expect_err("read-only event mutation must fail");
    let incident_error = read_only
        .insert_incident(&sample_incident(
            "inc_rejected_read_only",
            sample_event("evt_rejected_embedded"),
        ))
        .expect_err("read-only incident mutation must fail");

    assert!(event_error.to_string().contains("readonly"));
    assert!(incident_error.to_string().contains("readonly"));
    assert_eq!(read_only.count_events().expect("event count unchanged"), 2);
    assert_eq!(
        read_only
            .count_incidents()
            .expect("incident count unchanged"),
        1
    );
    assert!(read_only
        .get_event("evt_rejected_read_only")
        .expect("rejected event lookup succeeds")
        .is_none());
    assert!(read_only
        .get_incident("inc_rejected_read_only")
        .expect("rejected incident lookup succeeds")
        .is_none());

    cleanup_sqlite_files(&db_path);
}

#[test]
fn count_events_and_count_incidents_return_exact_counts() {
    let db_path = temp_path("exact-counts.sqlite");
    cleanup_sqlite_files(&db_path);
    let store = LocalStore::open(&db_path).expect("store opens");

    store
        .insert_event(&sample_event("evt_exact_1"))
        .expect("first event persists");
    store
        .insert_event(&sample_event("evt_exact_2"))
        .expect("second event persists");
    store
        .insert_incident(&sample_incident(
            "inc_exact_1",
            sample_event("evt_exact_embedded_1"),
        ))
        .expect("first incident persists");
    store
        .insert_incident(&sample_incident(
            "inc_exact_2",
            sample_event("evt_exact_embedded_2"),
        ))
        .expect("second incident persists");

    assert_eq!(store.count_events().expect("event count succeeds"), 4);
    assert_eq!(store.count_incidents().expect("incident count succeeds"), 2);

    cleanup_sqlite_files(&db_path);
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "skynet-edr-{name}-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos()
    ))
}

fn cleanup_sqlite_files(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = fs::remove_file(path.with_extension("sqlite-shm"));
}

fn no_redaction() -> RedactionMetadata {
    RedactionMetadata {
        contains_sensitive_data: false,
        redacted_fields: Vec::new(),
    }
}

fn sample_source() -> EventSource {
    EventSource {
        kind: SourceKind::Sensor,
        sensor: "read-only-storage-test".to_owned(),
        integration: Some("fake-test".to_owned()),
    }
}

fn sample_event(id: &str) -> Event {
    Event {
        id: EventId::new(id),
        observed_at_unix_ms: 1_781_440_123_000,
        severity: Severity::High,
        source: sample_source(),
        title: "Fake redacted event".to_owned(),
        details: Some("Clearly fake test data; no secrets.".to_owned()),
        attributes: BTreeMap::from([("rule_id".to_owned(), serde_json::json!("EDR-FAKE-001"))]),
        redaction: no_redaction(),
    }
}

fn sample_incident(id: &str, event: Event) -> Incident {
    Incident {
        id: IncidentId::new(id),
        created_at_unix_ms: 1_781_440_123_000,
        updated_at_unix_ms: 1_781_440_124_000,
        status: IncidentStatus::Open,
        severity: event.severity,
        title: "Fake read-only incident".to_owned(),
        summary: "Clearly fake test incident; no secrets.".to_owned(),
        source: event.source.clone(),
        events: vec![event],
        redaction: no_redaction(),
    }
}
