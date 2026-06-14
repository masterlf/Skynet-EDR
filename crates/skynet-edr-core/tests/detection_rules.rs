//! Detection rule schema and parser regression tests.

use skynet_edr_core::{parse_detection_rule_yaml, DetectionRuleError, Severity, SourceKind};

const VALID_RULE: &str = r"
id: suspicious_mcp_shell_egress
name: MCP shell followed by network egress
severity: high
source_kinds:
  - mcp_tool
  - network
conditions:
  - field: attributes.tool_name
    contains: shell
  - field: attributes.destination
    contains: example.invalid
actions:
  - alert
  - require_approval
description: Detects a tool chain that combines shell execution with outbound traffic.
";

#[test]
fn parses_valid_yaml_detection_rule() {
    let rule = parse_detection_rule_yaml(VALID_RULE).expect("valid rule parses");

    assert_eq!(rule.id.as_str(), "suspicious_mcp_shell_egress");
    assert_eq!(rule.name, "MCP shell followed by network egress");
    assert_eq!(rule.severity, Severity::High);
    assert_eq!(
        rule.source_kinds,
        vec![SourceKind::McpTool, SourceKind::Network]
    );
    assert_eq!(rule.conditions.len(), 2);
    assert_eq!(rule.actions.len(), 2);
}

#[test]
fn parses_fixture_detection_rules() {
    for fixture in [
        include_str!("fixtures/suspicious_mcp_shell_egress.yaml"),
        include_str!("fixtures/risky_cron_background_job.yaml"),
    ] {
        let rule = parse_detection_rule_yaml(fixture).expect("fixture rule parses");

        assert!(!rule.id.as_str().is_empty());
        assert!(!rule.conditions.is_empty());
        assert!(!rule.actions.is_empty());
    }
}

#[test]
fn rejects_empty_conditions_fail_closed() {
    let yaml = r"
id: empty_conditions
name: Empty conditions
severity: medium
source_kinds: [process]
conditions: []
actions: [alert]
";

    let err = parse_detection_rule_yaml(yaml).expect_err("empty conditions rejected");
    assert_eq!(
        err,
        DetectionRuleError::Validation("conditions must not be empty".to_owned())
    );
}

#[test]
fn rejects_rule_without_response_action_fail_closed() {
    let yaml = r"
id: no_actions
name: No actions
severity: low
source_kinds: [configuration]
conditions:
  - field: attributes.path
    contains: cron
actions: []
";

    let err = parse_detection_rule_yaml(yaml).expect_err("empty actions rejected");
    assert_eq!(
        err,
        DetectionRuleError::Validation("actions must not be empty".to_owned())
    );
}

#[test]
fn rejects_malformed_yaml_as_parse_error() {
    let err = parse_detection_rule_yaml("id: [not valid").expect_err("malformed yaml rejected");

    assert!(matches!(err, DetectionRuleError::Parse(_)));
}

#[test]
fn rejects_unknown_enum_values() {
    let yaml = r"
id: bad_enum
name: Bad enum
severity: catastrophic
source_kinds: [mcp_tool]
conditions:
  - field: attributes.tool_name
    contains: shell
actions: [alert]
";

    let err = parse_detection_rule_yaml(yaml).expect_err("unknown severity rejected");

    assert!(matches!(err, DetectionRuleError::Parse(_)));
}

#[test]
fn rejects_unknown_schema_fields_fail_closed() {
    let yaml = r"
id: extra_field
name: Extra field
severity: high
source_kinds: [mcp_tool]
conditions:
  - field: attributes.tool_name
    contains: shell
    regex: /bin/(bash|sh)
actions: [alert]
";

    let err = parse_detection_rule_yaml(yaml).expect_err("unknown field rejected");

    assert!(matches!(err, DetectionRuleError::Parse(_)));
}
