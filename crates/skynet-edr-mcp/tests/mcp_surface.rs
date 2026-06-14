//! MCP surface tests for the read-only integration skeleton.

use std::{collections::BTreeMap, fs, path::PathBuf};

use skynet_edr_core::{
    Event, EventId, EventSource, Incident, IncidentId, IncidentStatus, LocalStore,
    RedactionMetadata, Severity, SourceKind,
};
use skynet_edr_mcp::{
    get_config_drift, get_incident, list_incidents, list_rules, list_sensors, read_only_tool_specs,
    status, status_summary, McpReadError, McpServerInfo, READ_ONLY_TOOLS,
};

#[test]
fn mcp_surface_is_read_only_by_default() {
    let info = McpServerInfo::default();

    assert_eq!(info.name, "skynet-edr-mcp");
    assert!(info.read_only);
    assert_eq!(info.tools, READ_ONLY_TOOLS);
}

#[test]
fn planned_tool_names_are_status_and_investigation_only() {
    assert!(READ_ONLY_TOOLS.contains(&"skynet_status"));
    assert!(READ_ONLY_TOOLS.contains(&"skynet_list_incidents"));
    assert!(READ_ONLY_TOOLS.contains(&"skynet_get_config_drift"));
    assert!(READ_ONLY_TOOLS.iter().all(|tool| !tool.contains("disable")));
    assert!(READ_ONLY_TOOLS
        .iter()
        .all(|tool| !tool.contains("quarantine")));
}

#[test]
fn status_summary_is_operator_readable() {
    let summary = status_summary();

    assert!(summary.contains("Skynet-EDR"));
    assert!(summary.contains("read_only=true"));
    assert!(summary.contains("tools="));
}

#[test]
fn read_only_tool_specs_expose_only_requested_safe_tools() {
    let specs = read_only_tool_specs();
    let names = specs.iter().map(|spec| spec.name).collect::<Vec<_>>();

    assert_eq!(names, READ_ONLY_TOOLS);
    assert_eq!(names.len(), 6);
    assert!(names.contains(&"skynet_status"));
    assert!(names.contains(&"skynet_list_incidents"));
    assert!(names.contains(&"skynet_get_incident"));
    assert!(names.contains(&"skynet_list_rules"));
    assert!(names.contains(&"skynet_list_sensors"));
    assert!(names.contains(&"skynet_get_config_drift"));
    assert!(specs.iter().all(|spec| spec.read_only));
    assert!(names.iter().all(|name| !name.contains("write")));
    assert!(names.iter().all(|name| !name.contains("delete")));
    assert!(names.iter().all(|name| !name.contains("response")));
}

#[test]
fn status_reports_store_counts_without_mutating_local_storage() {
    let db_path = temp_path("mcp-status.sqlite");
    let store = seeded_store(&db_path);

    let before = store
        .list_incidents()
        .expect("incidents list before status");
    let value = status(&store).expect("status query succeeds");
    let after = store.list_incidents().expect("incidents list after status");

    assert_eq!(before, after);
    assert_eq!(value["product"], "Skynet-EDR");
    assert_eq!(value["server"], "skynet-edr-mcp");
    assert_eq!(value["read_only"], true);
    assert_eq!(value["incident_count"], 2);
    assert_eq!(value["event_count"], 2);
    assert_eq!(value["tool_count"], 6);

    fs::remove_file(db_path).expect("temporary db is removed");
}

#[test]
fn incidents_tools_list_summaries_and_fetch_one_redacted_incident() {
    let db_path = temp_path("mcp-incidents.sqlite");
    let store = seeded_store(&db_path);

    let listed = list_incidents(&store).expect("incidents list query succeeds");
    let summaries = listed.as_array().expect("list is array");
    assert_eq!(summaries.len(), 2);
    let open = summaries
        .iter()
        .find(|incident| incident["id"] == "inc_mcp_open")
        .expect("open incident summary is present");
    assert_eq!(open["status"], "open");
    assert_eq!(open["event_count"], 1);
    assert!(open.get("events").is_none());

    let incident = get_incident(&store, "inc_mcp_open").expect("incident query succeeds");
    assert_eq!(incident["id"], "inc_mcp_open");
    assert_eq!(
        incident["events"].as_array().expect("events array").len(),
        1
    );
    let serialized = serde_json::to_string(&incident).expect("incident serializes");
    assert!(!serialized.contains("super-secret-token"));
    assert!(serialized.contains("[REDACTED:secret]"));

    fs::remove_file(db_path).expect("temporary db is removed");
}

#[test]
fn missing_incident_returns_not_found_error() {
    let db_path = temp_path("mcp-missing.sqlite");
    let store = seeded_store(&db_path);

    let error = get_incident(&store, "inc_missing").expect_err("missing incident is an error");
    assert_eq!(
        error,
        McpReadError::IncidentNotFound("inc_missing".to_owned())
    );

    fs::remove_file(db_path).expect("temporary db is removed");
}

#[test]
fn rules_sensors_and_config_drift_are_operator_readable() {
    let db_path = temp_path("mcp-drift.sqlite");
    let store = seeded_store(&db_path);

    let rules = list_rules();
    assert!(rules
        .as_array()
        .expect("rules array")
        .iter()
        .any(|rule| rule["id"] == "EDR-MCP-001" && rule["read_only"] == true));
    assert!(rules
        .as_array()
        .expect("rules array")
        .iter()
        .any(|rule| rule["id"] == "EDR-CONFIG-001"));

    let sensors = list_sensors();
    assert!(sensors
        .as_array()
        .expect("sensors array")
        .iter()
        .any(|sensor| sensor["name"] == "linux-passive-fixture"));

    let drift = get_config_drift(&store).expect("config drift query succeeds");
    assert_eq!(drift.as_array().expect("drift array").len(), 1);
    assert_eq!(drift[0]["rule_id"], "EDR-CONFIG-001");
    assert_eq!(drift[0]["path"], ".hermes/config.yaml");
    assert!(drift[0].get("api_token").is_none());

    fs::remove_file(db_path).expect("temporary db is removed");
}

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

fn seeded_store(db_path: &PathBuf) -> LocalStore {
    let store = LocalStore::open(db_path).expect("store opens");
    store
        .insert_incident(&sample_incident(
            "inc_mcp_open",
            IncidentStatus::Open,
            sample_mcp_event("evt_mcp_shell", "EDR-MCP-001"),
        ))
        .expect("first incident persists");
    store
        .insert_incident(&sample_incident(
            "inc_config_drift",
            IncidentStatus::Investigating,
            sample_config_drift_event("evt_config_drift"),
        ))
        .expect("second incident persists");
    store
}

fn sample_incident(id: &str, status: IncidentStatus, event: Event) -> Incident {
    Incident {
        id: IncidentId::new(id),
        created_at_unix_ms: 1_781_440_123_000,
        updated_at_unix_ms: 1_781_440_124_000,
        status,
        severity: event.severity,
        title: format!("Incident {id}"),
        summary: "Operator-readable incident summary".to_owned(),
        source: event.source.clone(),
        events: vec![event],
        redaction: no_redaction(),
    }
}

fn sample_source(kind: SourceKind) -> EventSource {
    EventSource {
        kind,
        sensor: "linux-passive-fixture".to_owned(),
        integration: Some("hermes".to_owned()),
    }
}

fn sample_mcp_event(id: &str, rule_id: &str) -> Event {
    let mut attributes = BTreeMap::new();
    attributes.insert("rule_id".to_owned(), serde_json::json!(rule_id));
    attributes.insert("path".to_owned(), serde_json::json!(".hermes/config.yaml"));
    attributes.insert(
        "api_token".to_owned(),
        serde_json::json!("super-secret-token"),
    );

    Event {
        id: EventId::new(id),
        observed_at_unix_ms: 1_781_440_123_000,
        severity: Severity::Critical,
        source: sample_source(SourceKind::Configuration),
        title: "MCP server can execute shell with network egress".to_owned(),
        details: Some("Untrusted config was redacted before MCP exposure.".to_owned()),
        attributes,
        redaction: no_redaction(),
    }
}

fn sample_config_drift_event(id: &str) -> Event {
    let mut event = sample_mcp_event(id, "EDR-CONFIG-001");
    event.severity = Severity::High;
    "Agent configuration drift detected".clone_into(&mut event.title);
    event
        .attributes
        .insert("drift_kind".to_owned(), serde_json::json!("changed"));
    event.attributes.insert(
        "current_fingerprint".to_owned(),
        serde_json::json!("current123"),
    );
    event.attributes.insert(
        "baseline_fingerprint".to_owned(),
        serde_json::json!("baseline123"),
    );
    event
}
