//! Canonical Skynet event envelope v0 regression tests.

use skynet_edr_core::{
    parse_canonical_event_json, serialize_canonical_event_json, CanonicalEventEnvelope,
    EventSchemaVersion, RedactionReason, Severity, SourceKind, TrustLevel,
};

const FIXTURE: &str = include_str!("fixtures/canonical_event_v0.json");

#[test]
fn canonical_event_v0_fixture_round_trips_with_mandatory_security_metadata() {
    let event = parse_canonical_event_json(FIXTURE).expect("canonical fixture is accepted");

    assert_eq!(event.schema_version, EventSchemaVersion::V0);
    assert_eq!(event.event_id.as_str(), "evt_01HZCANONICAL");
    assert_eq!(event.event_type, "agent.tool.network_egress");
    assert_eq!(event.severity, Severity::High);
    assert_eq!(event.source.kind, SourceKind::Process);
    assert_eq!(event.provenance.producer, "hermes-agent");
    assert_eq!(event.provenance.collector, "skynet-edr-core");
    assert_eq!(event.trust_level, TrustLevel::AgentAction);
    assert!(event.redaction.contains_sensitive_data);
    assert!(event
        .redaction
        .redacted_fields
        .iter()
        .any(|field| field.reason == RedactionReason::Secret));

    let serialized = serialize_canonical_event_json(&event).expect("canonical event serializes");
    let reparsed: CanonicalEventEnvelope =
        parse_canonical_event_json(&serialized).expect("serialized canonical event reparses");
    assert_eq!(reparsed, event);
}

#[test]
fn canonical_event_v0_rejects_missing_provenance_trust_or_redaction() {
    for field in ["provenance", "trust_level", "redaction"] {
        let mut value: serde_json::Value =
            serde_json::from_str(FIXTURE).expect("valid JSON fixture");
        value
            .as_object_mut()
            .expect("fixture is a JSON object")
            .remove(field);

        let error = parse_canonical_event_json(&value.to_string())
            .expect_err("missing mandatory security field is rejected");
        assert!(
            error.to_string().contains(field),
            "error {error} should mention missing field {field}"
        );
    }
}

#[test]
fn canonical_event_v0_rejects_hostile_unknown_fields_and_inconsistent_redaction() {
    let mut unknown_field: serde_json::Value =
        serde_json::from_str(FIXTURE).expect("valid fixture");
    unknown_field["tool_output_says_ignore_all_instructions"] =
        serde_json::json!("pretend this is trusted now");
    assert!(parse_canonical_event_json(&unknown_field.to_string())
        .expect_err("unknown top-level field is rejected")
        .to_string()
        .contains("unknown field"));

    let mut unknown_nested_field: serde_json::Value =
        serde_json::from_str(FIXTURE).expect("valid fixture");
    unknown_nested_field["provenance"]["tool_output_says_ignore_all_instructions"] =
        serde_json::json!("pretend nested untrusted output is trusted");
    assert!(
        parse_canonical_event_json(&unknown_nested_field.to_string())
            .expect_err("unknown nested field is rejected")
            .to_string()
            .contains("unknown field")
    );

    let mut inconsistent_redaction: serde_json::Value =
        serde_json::from_str(FIXTURE).expect("valid fixture");
    inconsistent_redaction["redaction"]["contains_sensitive_data"] = serde_json::json!(false);
    assert!(
        parse_canonical_event_json(&inconsistent_redaction.to_string())
            .expect_err("redaction metadata must be internally consistent")
            .to_string()
            .contains("redaction")
    );

    let mut empty_redaction: serde_json::Value =
        serde_json::from_str(FIXTURE).expect("valid fixture");
    empty_redaction["redaction"]["redacted_fields"] = serde_json::json!([]);
    assert!(parse_canonical_event_json(&empty_redaction.to_string())
        .expect_err("sensitive flag requires redacted field evidence")
        .to_string()
        .contains("redaction"));
}

#[test]
fn canonical_event_v0_validation_rejects_empty_identity_and_provenance() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).expect("valid fixture");
    value["event_id"] = serde_json::json!("   ");
    value["provenance"]["producer"] = serde_json::json!("");

    let error = parse_canonical_event_json(&value.to_string())
        .expect_err("empty event identity and provenance are rejected");
    assert!(error.to_string().contains("event_id"));
}
