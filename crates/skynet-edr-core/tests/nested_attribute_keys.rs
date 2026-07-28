//! Full-tree JSON attribute-key boundary regressions.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde_json::{json, Map, Value};
use skynet_edr_core::{
    append_event_jsonl, append_incident_jsonl, ingest_canonical_jsonl_spool,
    parse_canonical_event_json, Event, EventId, EventSource, Incident, IncidentId, IncidentStatus,
    LocalStore, RedactionMetadata, Severity, SourceKind,
};

const CANONICAL_EVENT: &str = include_str!("fixtures/canonical_event_v0.json");
const MAX_ATTRIBUTE_CONTAINER_DEPTH: usize = 64;
const MAX_ATTRIBUTE_TREE_UNITS: usize = 4_096;
const MAX_STORAGE_ATTRIBUTE_TREE_UNITS: usize = MAX_ATTRIBUTE_TREE_UNITS + 18;
const RAW_SECRET_KEY: &str = "api_token=FAKE_NESTED_SECRET_KEY_P1A";
const RAW_PATH_KEY: &str = "/fake/home/FAKE_NESTED_PRIVATE_PATH_P1A";

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "skynet-edr-nested-keys-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ))
}

fn canonical_with_attribute(id: &str, key: &str, value: Value) -> Value {
    let mut event: Value = serde_json::from_str(CANONICAL_EVENT).expect("fixture JSON");
    event["event_id"] = json!(id);
    event["provenance"]["source_event_id"] = json!(id);
    event["attributes"][key] = value;
    event
}

fn canonical_with_only_attribute(id: &str, key: &str, value: Value) -> Value {
    let mut event = canonical_with_attribute(id, key, value);
    event["attributes"] = json!({key: event["attributes"][key].take()});
    event["redaction"] = json!({"contains_sensitive_data": false, "redacted_fields": []});
    event
}

fn no_redaction() -> RedactionMetadata {
    RedactionMetadata {
        contains_sensitive_data: false,
        redacted_fields: Vec::new(),
    }
}

fn sample_event(id: &str, attributes: BTreeMap<String, Value>) -> Event {
    Event {
        id: EventId::new(id),
        observed_at_unix_ms: 1_781_700_000_000,
        severity: Severity::High,
        source: EventSource {
            kind: SourceKind::McpTool,
            sensor: "nested-key-test".to_owned(),
            integration: Some("hermes".to_owned()),
        },
        title: "Bounded generic event".to_owned(),
        details: None,
        attributes,
        redaction: no_redaction(),
    }
}

fn sample_incident(id: &str, events: Vec<Event>) -> Incident {
    Incident {
        id: IncidentId::new(id),
        created_at_unix_ms: 1_781_700_000_000,
        updated_at_unix_ms: 1_781_700_000_001,
        status: IncidentStatus::Open,
        severity: Severity::High,
        title: "Bounded generic incident".to_owned(),
        summary: "Generic incident with prevalidated evidence.".to_owned(),
        source: EventSource {
            kind: SourceKind::McpTool,
            sensor: "nested-key-test".to_owned(),
            integration: Some("hermes".to_owned()),
        },
        events,
        redaction: no_redaction(),
    }
}

fn nested_object(depth: usize) -> Value {
    let mut value = json!("safe-leaf");
    for _ in 0..depth {
        value = json!({"safe_level": value});
    }
    value
}

fn object_with_keys(count: usize) -> Value {
    let mut object = Map::new();
    for index in 0..count {
        object.insert(format!("safe_{index}"), Value::Null);
    }
    Value::Object(object)
}

fn database_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        if let Ok(mut stored) = fs::read(candidate) {
            bytes.append(&mut stored);
        }
    }
    bytes
}

fn cleanup_sqlite(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        let _ = fs::remove_file(candidate);
    }
}

#[test]
fn canonical_parser_rejects_hostile_keys_through_nested_objects_and_arrays() {
    let hostile_keys = [
        "api_token".to_owned(),
        RAW_SECRET_KEY.to_owned(),
        RAW_PATH_KEY.to_owned(),
        "control\nkey".to_owned(),
        "x".repeat(129),
    ];

    let mut errors = Vec::new();
    for (index, hostile_key) in hostile_keys.iter().enumerate() {
        for (shape, nested) in [
            ("object", json!({hostile_key: "[REDACTED:secret]"})),
            (
                "array",
                json!([{"safe_child": {hostile_key: "[REDACTED:secret]"}}]),
            ),
        ] {
            let candidate = canonical_with_attribute(
                &format!("evt_nested_hostile_{index}_{shape}"),
                "safe_container",
                nested,
            );
            let error = parse_canonical_event_json(&candidate.to_string())
                .expect_err("hostile nested key must fail closed")
                .to_string();
            assert!(!error.contains(hostile_key));
            assert!(!error.contains("[REDACTED:secret]"));
            errors.push(error);
        }
    }
    assert!(errors.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn canonical_spool_rejects_nested_hostile_keys_without_sqlite_or_incident_persistence() {
    let db_path = temp_path("spool.sqlite");
    let spool_path = temp_path("spool.jsonl");
    let checkpoint_path = temp_path("spool.offset");
    let candidate = canonical_with_attribute(
        "evt_nested_hostile_spool",
        "safe_container",
        json!([{"safe_child": {RAW_PATH_KEY: "[REDACTED:local_context]"}}]),
    );
    fs::write(&spool_path, format!("{candidate}\n")).expect("spool writes");
    let store = LocalStore::open(&db_path).expect("store opens");

    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("invalid canonical lines are counted and skipped");

    assert_eq!(summary.ingested_events, 0);
    assert_eq!(summary.dropped_events, 1);
    assert_eq!(summary.opened_incidents, 0);
    assert_eq!(store.count_events().expect("event count"), 0);
    assert_eq!(store.count_incidents().expect("incident count"), 0);
    assert!(store
        .get_event("evt_nested_hostile_spool")
        .expect("event lookup")
        .is_none());
    assert!(!String::from_utf8_lossy(&database_bytes(&db_path)).contains(RAW_PATH_KEY));
    let checkpoint = fs::read_to_string(&checkpoint_path).expect("checkpoint exists");
    assert!(checkpoint.trim().bytes().all(|byte| byte.is_ascii_digit()));
    assert!(!checkpoint.contains(RAW_PATH_KEY));

    drop(store);
    cleanup_sqlite(&db_path);
    fs::remove_file(spool_path).expect("spool removes");
    fs::remove_file(checkpoint_path).expect("checkpoint removes");
}

#[test]
fn direct_event_storage_rejects_nested_hostile_keys_before_sanitization() {
    let db_path = temp_path("event.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let benign = sample_event(
        "evt_nested_benign_seed",
        BTreeMap::from([("safe_container".to_owned(), json!({"safe_child": true}))]),
    );
    store.insert_event(&benign).expect("benign seed persists");
    let hostile = sample_event(
        "evt_nested_hostile_direct",
        BTreeMap::from([(
            "safe_container".to_owned(),
            json!({"safe_child": {RAW_SECRET_KEY: "[REDACTED:secret]"}}),
        )]),
    );

    let error = store
        .insert_event(&hostile)
        .expect_err("direct event insertion must reject hostile nested keys")
        .to_string();

    assert!(!error.contains(RAW_SECRET_KEY));
    assert!(!error.contains("[REDACTED:secret]"));
    assert_eq!(store.count_events().expect("event count"), 1);
    assert!(store
        .get_event("evt_nested_hostile_direct")
        .expect("event lookup")
        .is_none());
    assert!(!String::from_utf8_lossy(&database_bytes(&db_path)).contains(RAW_SECRET_KEY));

    drop(store);
    cleanup_sqlite(&db_path);
}

#[test]
fn direct_incident_storage_validates_every_event_before_starting_transaction() {
    let db_path = temp_path("incident.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let benign = sample_event(
        "evt_nested_incident_benign",
        BTreeMap::from([("safe_container".to_owned(), json!([{"safe_child": true}]))]),
    );
    let hostile = sample_event(
        "evt_nested_incident_hostile",
        BTreeMap::from([(
            "safe_container".to_owned(),
            json!([{"safe_child": {RAW_PATH_KEY: "[REDACTED:local_context]"}}]),
        )]),
    );
    let incident = sample_incident("inc_nested_hostile_direct", vec![benign, hostile]);

    let error = store
        .insert_incident(&incident)
        .expect_err("incident insertion must reject before writing any embedded event")
        .to_string();

    assert!(!error.contains(RAW_PATH_KEY));
    assert!(!error.contains("[REDACTED:local_context]"));
    assert_eq!(store.count_events().expect("event count"), 0);
    assert_eq!(store.count_incidents().expect("incident count"), 0);
    assert!(store
        .get_incident("inc_nested_hostile_direct")
        .expect("incident lookup")
        .is_none());
    assert!(!String::from_utf8_lossy(&database_bytes(&db_path)).contains(RAW_PATH_KEY));

    drop(store);
    cleanup_sqlite(&db_path);
}

#[test]
fn direct_jsonl_append_rejects_nested_hostile_keys_without_partial_output() {
    let event_path = temp_path("hostile-event.jsonl");
    let incident_path = temp_path("hostile-incident.jsonl");
    let benign = sample_event(
        "evt_nested_jsonl_benign",
        BTreeMap::from([("safe_container".to_owned(), json!({"safe_child": true}))]),
    );
    let hostile = sample_event(
        "evt_nested_jsonl_hostile",
        BTreeMap::from([(
            "safe_container".to_owned(),
            json!([{"safe_child": {RAW_SECRET_KEY: "[REDACTED:secret]"}}]),
        )]),
    );

    let event_error = append_event_jsonl(&event_path, &hostile)
        .expect_err("event JSONL append must reject hostile nested keys")
        .to_string();
    let incident = sample_incident("inc_nested_jsonl_hostile", vec![benign, hostile]);
    let incident_error = append_incident_jsonl(&incident_path, &incident)
        .expect_err("incident JSONL append must validate every event before opening the file")
        .to_string();

    assert_eq!(event_error, incident_error);
    assert!(!event_error.contains(RAW_SECRET_KEY));
    assert!(!event_path.exists());
    assert!(!incident_path.exists());
}

#[test]
fn canonical_attribute_tree_depth_node_and_key_limits_are_exact() {
    let exact_depth = canonical_with_only_attribute(
        "evt_nested_exact_depth",
        "safe_container",
        nested_object(MAX_ATTRIBUTE_CONTAINER_DEPTH),
    );
    parse_canonical_event_json(&exact_depth.to_string()).expect("exact depth is accepted");
    let excessive_depth = canonical_with_only_attribute(
        "evt_nested_excessive_depth",
        "safe_container",
        nested_object(MAX_ATTRIBUTE_CONTAINER_DEPTH + 1),
    );
    parse_canonical_event_json(&excessive_depth.to_string())
        .expect_err("one container beyond depth limit is rejected");

    let exact_nodes = canonical_with_only_attribute(
        "evt_nested_exact_nodes",
        "safe_container",
        Value::Array(vec![Value::Null; MAX_ATTRIBUTE_TREE_UNITS - 1]),
    );
    parse_canonical_event_json(&exact_nodes.to_string()).expect("exact node budget is accepted");
    let excessive_nodes = canonical_with_only_attribute(
        "evt_nested_excessive_nodes",
        "safe_container",
        Value::Array(vec![Value::Null; MAX_ATTRIBUTE_TREE_UNITS]),
    );
    parse_canonical_event_json(&excessive_nodes.to_string())
        .expect_err("one array item beyond tree budget is rejected");

    let exact_keys = canonical_with_only_attribute(
        "evt_nested_exact_keys",
        "safe_container",
        object_with_keys(MAX_ATTRIBUTE_TREE_UNITS - 1),
    );
    parse_canonical_event_json(&exact_keys.to_string()).expect("exact key budget is accepted");
    let excessive_keys = canonical_with_only_attribute(
        "evt_nested_excessive_keys",
        "safe_container",
        object_with_keys(MAX_ATTRIBUTE_TREE_UNITS),
    );
    parse_canonical_event_json(&excessive_keys.to_string())
        .expect_err("one object key beyond tree budget is rejected");
}

#[test]
fn exact_canonical_tree_budget_survives_spool_storage_projection() {
    let db_path = temp_path("exact-spool.sqlite");
    let spool_path = temp_path("exact-spool.jsonl");
    let checkpoint_path = temp_path("exact-spool.offset");
    let candidate = canonical_with_only_attribute(
        "evt_nested_exact_spool_nodes",
        "safe_container",
        Value::Array(vec![Value::Null; MAX_ATTRIBUTE_TREE_UNITS - 1]),
    );
    fs::write(&spool_path, format!("{candidate}\n")).expect("spool writes");
    let store = LocalStore::open(&db_path).expect("store opens");

    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("exact canonical tree budget ingests");

    assert_eq!(summary.ingested_events, 1);
    assert_eq!(summary.dropped_events, 0);
    assert!(store
        .get_event("evt_nested_exact_spool_nodes")
        .expect("event lookup")
        .is_some());

    drop(store);
    cleanup_sqlite(&db_path);
    fs::remove_file(spool_path).expect("spool removes");
    fs::remove_file(checkpoint_path).expect("checkpoint removes");
}

#[test]
fn direct_storage_tree_budget_is_exact() {
    let db_path = temp_path("exact-storage.sqlite");
    let store = LocalStore::open(&db_path).expect("store opens");
    let exact = sample_event(
        "evt_nested_exact_storage_nodes",
        BTreeMap::from([(
            "safe_container".to_owned(),
            Value::Array(vec![Value::Null; MAX_STORAGE_ATTRIBUTE_TREE_UNITS - 1]),
        )]),
    );
    store
        .insert_event(&exact)
        .expect("exact storage tree budget persists");
    let excessive = sample_event(
        "evt_nested_excessive_storage_nodes",
        BTreeMap::from([(
            "safe_container".to_owned(),
            Value::Array(vec![Value::Null; MAX_STORAGE_ATTRIBUTE_TREE_UNITS]),
        )]),
    );

    store
        .insert_event(&excessive)
        .expect_err("one array item beyond storage tree budget is rejected");
    assert_eq!(store.count_events().expect("event count"), 1);

    drop(store);
    cleanup_sqlite(&db_path);
}

#[test]
fn benign_nested_attributes_survive_generic_spool_and_direct_storage() {
    let db_path = temp_path("benign.sqlite");
    let spool_path = temp_path("benign.jsonl");
    let checkpoint_path = temp_path("benign.offset");
    let nested = json!({
        "safe_child": [
            {"safe_leaf": true},
            {"safe_count": 7},
            {"safe_label": "benign"}
        ]
    });
    let candidate =
        canonical_with_attribute("evt_nested_benign_spool", "safe_container", nested.clone());
    fs::write(&spool_path, format!("{candidate}\n")).expect("spool writes");
    let store = LocalStore::open(&db_path).expect("store opens");

    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("benign nested canonical event ingests");
    assert_eq!(summary.ingested_events, 1);
    assert_eq!(summary.dropped_events, 0);
    let stored = store
        .get_event("evt_nested_benign_spool")
        .expect("event lookup")
        .expect("event persisted");
    assert_eq!(stored.attributes.get("safe_container"), Some(&nested));

    let direct = sample_event(
        "evt_nested_benign_direct",
        BTreeMap::from([("safe_container".to_owned(), nested)]),
    );
    store
        .insert_event(&direct)
        .expect("benign direct event persists");
    assert_eq!(
        store
            .get_event("evt_nested_benign_direct")
            .expect("event lookup")
            .expect("direct event persisted"),
        direct
    );

    drop(store);
    cleanup_sqlite(&db_path);
    fs::remove_file(spool_path).expect("spool removes");
    fs::remove_file(checkpoint_path).expect("checkpoint removes");
}
