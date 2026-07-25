//! Local `SQLite` incident pagination tests.

use std::collections::BTreeMap;

use skynet_edr_core::{
    Event, EventId, EventSource, Incident, IncidentId, IncidentStatus, LocalStore,
    RedactionMetadata, Severity, SourceKind,
};

#[test]
fn local_store_counts_and_pages_incidents_in_sqlite_order() {
    let store = temp_store();
    for (id, updated) in [
        ("inc-old", 100),
        ("inc-new-b", 300),
        ("inc-new-a", 300),
        ("inc-mid", 200),
    ] {
        store
            .insert_incident(&incident(id, updated))
            .expect("incident persists");
    }

    assert_eq!(store.count_incidents().expect("count succeeds"), 4);

    let first_page = store
        .list_incidents_page(2, 0)
        .expect("first page succeeds")
        .into_iter()
        .map(|incident| incident.id.as_str().to_owned())
        .collect::<Vec<_>>();
    let second_page = store
        .list_incidents_page(2, 2)
        .expect("second page succeeds")
        .into_iter()
        .map(|incident| incident.id.as_str().to_owned())
        .collect::<Vec<_>>();
    let empty_page = store
        .list_incidents_page(2, 4)
        .expect("empty later page succeeds");

    assert_eq!(first_page, ["inc-new-a", "inc-new-b"]);
    assert_eq!(second_page, ["inc-mid", "inc-old"]);
    assert!(empty_page.is_empty());
}

fn temp_store() -> LocalStore {
    let db_path = std::env::temp_dir().join(format!(
        "skynet-edr-local-store-pagination-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    LocalStore::open(db_path).expect("temporary local store opens")
}

fn incident(id: &str, updated_at_unix_ms: u64) -> Incident {
    let source = EventSource {
        kind: SourceKind::Sensor,
        sensor: "pagination-test".to_owned(),
        integration: None,
    };
    Incident {
        id: IncidentId::new(id),
        created_at_unix_ms: 1,
        updated_at_unix_ms,
        status: IncidentStatus::Open,
        severity: Severity::Medium,
        title: format!("Incident {id}"),
        summary: "Stored summary".to_owned(),
        source: source.clone(),
        events: vec![Event {
            id: EventId::new(format!("evt-{id}")),
            observed_at_unix_ms: updated_at_unix_ms,
            severity: Severity::Medium,
            source,
            title: "Stored event title".to_owned(),
            details: None,
            attributes: BTreeMap::new(),
            redaction: no_redaction(),
        }],
        redaction: no_redaction(),
    }
}

fn no_redaction() -> RedactionMetadata {
    RedactionMetadata {
        contains_sensitive_data: false,
        redacted_fields: Vec::new(),
    }
}
