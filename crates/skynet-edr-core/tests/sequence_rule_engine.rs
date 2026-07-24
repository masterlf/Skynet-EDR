//! Deterministic sequence correlation engine regression tests.

use std::collections::BTreeMap;

use skynet_edr_core::{
    built_in_ai_agent_sequence_rules, correlate_sequence_rule, correlate_sequence_rules,
    parse_canonical_event_json, CanonicalEventEnvelope, EventId, EventProvenance,
    EventSchemaVersion, EventSource, RedactionMetadata, SequenceAttributePredicate, SequenceJoin,
    SequenceRule, SequenceStep, Severity, SourceKind, TrustLevel,
};

type TestAttributes = Vec<(&'static str, serde_json::Value)>;
type TestStep = (&'static str, TrustLevel, TestAttributes);

#[test]
fn correlates_ordered_same_session_events_with_explainable_match() {
    let rule = SequenceRule {
        id: "EDR-SEQ-001".to_owned(),
        name: "untrusted prompt then tool egress".to_owned(),
        severity: Severity::High,
        window_ms: 60_000,
        join: SequenceJoin::SameSession,
        steps: vec![
            SequenceStep {
                name: "untrusted content".to_owned(),
                event_type: "agent.content.ingested".to_owned(),
                trust_level: TrustLevel::UntrustedContent,
                attributes: vec![SequenceAttributePredicate::equals_bool(
                    "attributes.prompt_injection",
                    true,
                )],
            },
            SequenceStep {
                name: "network egress".to_owned(),
                event_type: "agent.network.egress".to_owned(),
                trust_level: TrustLevel::AgentAction,
                attributes: Vec::new(),
            },
        ],
    };
    let events = vec![
        canonical_event(
            "evt_egress_other_session",
            "agent.network.egress",
            1_781_560_050_000,
            TrustLevel::AgentAction,
            "sess_other",
            Some("trace_other"),
            &[],
        ),
        canonical_event(
            "evt_prompt",
            "agent.content.ingested",
            1_781_560_000_000,
            TrustLevel::UntrustedContent,
            "sess_a",
            Some("trace_a"),
            &[("prompt_injection", serde_json::json!(true))],
        ),
        canonical_event(
            "evt_egress",
            "agent.network.egress",
            1_781_560_030_000,
            TrustLevel::AgentAction,
            "sess_a",
            Some("trace_b"),
            &[],
        ),
    ];

    let matches = correlate_sequence_rule(&rule, &events).expect("valid rule evaluates");

    assert_eq!(matches.len(), 1);
    let first_match = &matches[0];
    assert_eq!(first_match.rule_id, "EDR-SEQ-001");
    assert_eq!(first_match.severity, Severity::High);
    assert_eq!(
        first_match.matched_event_ids,
        vec![EventId::new("evt_prompt"), EventId::new("evt_egress")]
    );
    assert_eq!(first_match.join_key.as_deref(), Some("session:sess_a"));
    assert!(first_match
        .explanations
        .iter()
        .any(|explanation| explanation.contains("step 1 'untrusted content' matched evt_prompt")));
    assert!(first_match
        .explanations
        .iter()
        .any(|explanation| explanation.contains("within 30000ms of sequence start")));
}

#[test]
fn supports_same_trace_join_independent_of_session() {
    let rule = SequenceRule {
        id: "EDR-SEQ-TRACE".to_owned(),
        name: "trace joined scope expansion".to_owned(),
        severity: Severity::High,
        window_ms: 60_000,
        join: SequenceJoin::SameTrace,
        steps: vec![
            SequenceStep {
                name: "untrusted content".to_owned(),
                event_type: "agent.content.ingested".to_owned(),
                trust_level: TrustLevel::UntrustedContent,
                attributes: Vec::new(),
            },
            SequenceStep {
                name: "scope expansion".to_owned(),
                event_type: "agent.approval.granted".to_owned(),
                trust_level: TrustLevel::AgentAction,
                attributes: vec![SequenceAttributePredicate::equals_bool(
                    "attributes.scope_expansion",
                    true,
                )],
            },
        ],
    };
    let events = vec![
        canonical_event(
            "evt_prompt",
            "agent.content.ingested",
            1_781_560_000_000,
            TrustLevel::UntrustedContent,
            "sess_a",
            Some("trace_scope"),
            &[],
        ),
        canonical_event(
            "evt_scope",
            "agent.approval.granted",
            1_781_560_010_000,
            TrustLevel::AgentAction,
            "sess_b",
            Some("trace_scope"),
            &[("scope_expansion", serde_json::json!(true))],
        ),
    ];

    let matches = correlate_sequence_rule(&rule, &events).expect("valid rule evaluates");

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].join_key.as_deref(), Some("trace:trace_scope"));
}

#[test]
fn does_not_match_when_candidate_is_outside_time_window() {
    let rule = SequenceRule {
        id: "EDR-SEQ-WINDOW".to_owned(),
        name: "secret read then egress".to_owned(),
        severity: Severity::Critical,
        window_ms: 60_000,
        join: SequenceJoin::SameSession,
        steps: vec![
            SequenceStep {
                name: "secret read".to_owned(),
                event_type: "agent.file.accessed".to_owned(),
                trust_level: TrustLevel::AgentAction,
                attributes: vec![SequenceAttributePredicate::equals_bool(
                    "attributes.sensitive_access",
                    true,
                )],
            },
            SequenceStep {
                name: "network egress".to_owned(),
                event_type: "agent.network.egress".to_owned(),
                trust_level: TrustLevel::AgentAction,
                attributes: Vec::new(),
            },
        ],
    };
    let events = vec![
        canonical_event(
            "evt_secret",
            "agent.file.accessed",
            1_781_560_000_000,
            TrustLevel::AgentAction,
            "sess_a",
            Some("trace_a"),
            &[("sensitive_access", serde_json::json!(true))],
        ),
        canonical_event(
            "evt_late_egress",
            "agent.network.egress",
            1_781_560_061_000,
            TrustLevel::AgentAction,
            "sess_a",
            Some("trace_a"),
            &[],
        ),
    ];

    let matches = correlate_sequence_rule(&rule, &events).expect("valid rule evaluates");

    assert!(matches.is_empty());
}

#[test]
fn rejects_ambiguous_sequence_rules_fail_closed() {
    let rule = SequenceRule {
        id: "EDR-SEQ-BAD".to_owned(),
        name: "bad".to_owned(),
        severity: Severity::High,
        window_ms: 60_000,
        join: SequenceJoin::SameSession,
        steps: vec![SequenceStep {
            name: "matches anything".to_owned(),
            event_type: String::new(),
            trust_level: TrustLevel::AgentAction,
            attributes: Vec::new(),
        }],
    };

    let err = correlate_sequence_rule(&rule, &[]).expect_err("ambiguous rule rejected");

    assert!(err
        .to_string()
        .contains("sequence rules require at least two steps"));
}

#[test]
fn built_in_ai_agent_rule_pack_has_malicious_and_benign_coverage() {
    let rules = built_in_ai_agent_sequence_rules();
    let expected = [
        "EDR-MCP-001",
        "EDR-CONFIG-001",
        "EDR-CRON-001",
        "EDR-PI-001",
        "EDR-MSG-001",
        "EDR-NET-001",
        "EDR-SCOPE-001",
        "EDR-PERSIST-001",
    ];
    assert_eq!(
        rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<Vec<_>>(),
        expected
    );
    assert!(rules.iter().all(|rule| rule.id != "EDR-EXFIL-001"));
    assert!(rules.iter().all(|rule| rule.severity != Severity::Critical));

    for rule_id in expected {
        let malicious = malicious_rule_events(rule_id);
        let matches = correlate_sequence_rules(&rules, &malicious).expect("rule pack evaluates");
        assert_eq!(
            matches
                .iter()
                .filter(|matched| matched.rule_id == rule_id)
                .count(),
            1,
            "{rule_id} should match malicious sequence"
        );

        let benign = benign_rule_events(rule_id);
        let benign_matches =
            correlate_sequence_rules(&rules, &benign).expect("rule pack evaluates");
        assert!(
            benign_matches
                .iter()
                .all(|matched| matched.rule_id != rule_id),
            "{rule_id} should not match benign sequence"
        );
    }
}

#[test]
fn direct_ip_egress_rule_requires_explicit_direct_ip_attribute() {
    let rules = built_in_ai_agent_sequence_rules();
    for attributes in [
        vec![bool_attr("network_indicator", true)],
        vec![
            bool_attr("network_indicator", true),
            bool_attr("direct_ip", false),
        ],
    ] {
        let events = sequence(
            "EDR-NET-001",
            &[
                step(
                    "agent.content.ingested",
                    TrustLevel::UntrustedContent,
                    &[bool_attr("prompt_injection", true)],
                ),
                step("agent.network.egress", TrustLevel::AgentAction, &attributes),
            ],
        );

        let matches = correlate_sequence_rules(&rules, &events).expect("rule pack evaluates");
        assert!(
            matches
                .iter()
                .all(|matched| matched.rule_id != "EDR-NET-001"),
            "EDR-NET-001 must not match without attributes.direct_ip=true"
        );
    }
}

#[test]
fn text_only_prompt_injection_is_low_signal_and_never_critical() {
    let events = vec![canonical_event(
        "evt_text_only_pi",
        "agent.content.ingested",
        1_781_560_000_000,
        TrustLevel::UntrustedContent,
        "sess_pi_only",
        Some("trace_pi_only"),
        &[("prompt_injection", serde_json::json!(true))],
    )];

    let matches = correlate_sequence_rules(&built_in_ai_agent_sequence_rules(), &events)
        .expect("rule pack evaluates");

    assert!(matches.is_empty());
    assert!(events
        .iter()
        .all(|event| event.severity != Severity::Critical));
}

fn parse_jsonl_fixture(input: &str) -> Vec<CanonicalEventEnvelope> {
    input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| parse_canonical_event_json(line).expect("golden canonical event parses"))
        .collect()
}

#[test]
fn built_in_rules_match_checked_in_hermes_and_openclaw_golden_canonical_fixtures() {
    for (fixture_name, fixture) in [
        (
            "hermes",
            include_str!("fixtures/hermes_agent_golden_events_v0.jsonl"),
        ),
        (
            "openclaw",
            include_str!("fixtures/openclaw_agent_golden_events_v0.jsonl"),
        ),
    ] {
        let events = parse_jsonl_fixture(fixture);
        let matches = correlate_sequence_rules(&built_in_ai_agent_sequence_rules(), &events)
            .expect("rule pack evaluates golden fixture");
        let matched_rule_ids = matches
            .iter()
            .map(|matched| matched.rule_id.as_str())
            .collect::<Vec<_>>();

        assert!(
            matched_rule_ids.contains(&"EDR-MCP-001"),
            "{fixture_name} golden fixture should match MCP tool request sequence"
        );
        assert!(
            matched_rule_ids.contains(&"EDR-CONFIG-001"),
            "{fixture_name} golden fixture should match config drift sequence"
        );
        assert!(
            matched_rule_ids.contains(&"EDR-CRON-001"),
            "{fixture_name} golden fixture should match scheduled persistence sequence"
        );
        assert!(matches.iter().all(|matched| matched
            .join_key
            .as_deref()
            .is_some_and(|key| key.starts_with("trace:"))));
    }
}

#[test]
fn built_in_rules_match_realistic_plugin_shaped_trace_without_session_attribute() {
    let events = vec![
        plugin_canonical_event(
            "evt_plugin_pi",
            "agent.content.ingested",
            1_781_560_000_000,
            TrustLevel::UntrustedContent,
            Severity::Medium,
            "trace_plugin_real",
            &[
                bool_attr("instruction_authority", false),
                bool_attr("contains_instructional_attack", true),
            ],
        ),
        plugin_canonical_event(
            "evt_plugin_tool",
            "agent.tool.requested",
            1_781_560_001_000,
            TrustLevel::AgentAction,
            Severity::High,
            "trace_plugin_real",
            &[
                str_attr("tool_name", "terminal"),
                bool_attr("network_indicator", true),
                bool_attr("delivery_indicator", false),
                bool_attr("sensitive_access", true),
            ],
        ),
    ];

    let matches = correlate_sequence_rules(&built_in_ai_agent_sequence_rules(), &events)
        .expect("rule pack evaluates plugin-shaped sequence");

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_id, "EDR-PI-001");
    assert_eq!(matches[0].severity, Severity::High);
    assert_eq!(
        matches[0].join_key.as_deref(),
        Some("trace:trace_plugin_real")
    );
}

#[allow(clippy::too_many_lines)]
fn malicious_rule_events(rule_id: &str) -> Vec<CanonicalEventEnvelope> {
    match rule_id {
        "EDR-MCP-001" => sequence(
            rule_id,
            &[
                step(
                    "agent.content.ingested",
                    TrustLevel::UntrustedContent,
                    &[bool_attr("prompt_injection", true)],
                ),
                step(
                    "agent.mcp.tool.requested",
                    TrustLevel::AgentAction,
                    &[
                        str_attr("tool_name", "shell"),
                        bool_attr("network_indicator", true),
                    ],
                ),
            ],
        ),
        "EDR-CONFIG-001" => sequence(
            rule_id,
            &[
                step(
                    "agent.content.ingested",
                    TrustLevel::UntrustedContent,
                    &[bool_attr("prompt_injection", true)],
                ),
                step(
                    "agent.config.changed",
                    TrustLevel::AgentAction,
                    &[bool_attr("approval_required", false)],
                ),
            ],
        ),
        "EDR-CRON-001" => sequence(
            rule_id,
            &[
                step(
                    "agent.content.ingested",
                    TrustLevel::UntrustedContent,
                    &[bool_attr("prompt_injection", true)],
                ),
                step(
                    "agent.automation.scheduled",
                    TrustLevel::AgentAction,
                    &[bool_attr("persistence_indicator", true)],
                ),
            ],
        ),
        "EDR-PI-001" => sequence(
            rule_id,
            &[
                step(
                    "agent.content.ingested",
                    TrustLevel::UntrustedContent,
                    &[bool_attr("prompt_injection", true)],
                ),
                step(
                    "agent.tool.requested",
                    TrustLevel::AgentAction,
                    &[
                        bool_attr("network_indicator", true),
                        bool_attr("sensitive_access", true),
                    ],
                ),
            ],
        ),
        "EDR-MSG-001" => sequence(
            rule_id,
            &[
                step(
                    "agent.content.ingested",
                    TrustLevel::UntrustedContent,
                    &[bool_attr("prompt_injection", true)],
                ),
                step(
                    "agent.tool.requested",
                    TrustLevel::AgentAction,
                    &[
                        bool_attr("delivery_indicator", true),
                        bool_attr("sensitive_access", true),
                    ],
                ),
            ],
        ),
        "EDR-NET-001" => sequence(
            rule_id,
            &[
                step(
                    "agent.content.ingested",
                    TrustLevel::UntrustedContent,
                    &[bool_attr("prompt_injection", true)],
                ),
                step(
                    "agent.network.egress",
                    TrustLevel::AgentAction,
                    &[
                        bool_attr("network_indicator", true),
                        bool_attr("direct_ip", true),
                    ],
                ),
            ],
        ),
        "EDR-SCOPE-001" => sequence(
            rule_id,
            &[
                step(
                    "agent.content.ingested",
                    TrustLevel::UntrustedContent,
                    &[bool_attr("prompt_injection", true)],
                ),
                step(
                    "agent.approval.granted",
                    TrustLevel::AgentAction,
                    &[bool_attr("scope_expansion", true)],
                ),
            ],
        ),
        "EDR-PERSIST-001" => sequence(
            rule_id,
            &[
                step(
                    "agent.content.ingested",
                    TrustLevel::UntrustedContent,
                    &[bool_attr("prompt_injection", true)],
                ),
                step(
                    "agent.config.changed",
                    TrustLevel::AgentAction,
                    &[bool_attr("persistence_indicator", true)],
                ),
            ],
        ),
        _ => unreachable!("covered by expected rule ids"),
    }
}

fn benign_rule_events(rule_id: &str) -> Vec<CanonicalEventEnvelope> {
    let mut events = malicious_rule_events(rule_id);
    events[0].trust_level = TrustLevel::AuthenticatedUser;
    events[0]
        .attributes
        .insert("prompt_injection".to_owned(), serde_json::json!(false));
    events[0]
        .attributes
        .insert("instruction_authority".to_owned(), serde_json::json!(true));
    events
}

fn sequence(rule_id: &str, steps: &[TestStep]) -> Vec<CanonicalEventEnvelope> {
    steps
        .iter()
        .enumerate()
        .map(|(index, (event_type, trust_level, attributes))| {
            let mut event = canonical_event(
                &format!("evt_{rule_id}_{index}"),
                event_type,
                1_781_560_000_000 + u64::try_from(index).expect("index fits") * 1_000,
                *trust_level,
                &format!("sess_{rule_id}"),
                Some(&format!("trace_{rule_id}")),
                attributes,
            );
            if *event_type == "agent.content.ingested" {
                event
                    .attributes
                    .insert("instruction_authority".to_owned(), serde_json::json!(false));
            }
            event
        })
        .collect()
}

fn step(
    event_type: &'static str,
    trust_level: TrustLevel,
    attributes: &[(&'static str, serde_json::Value)],
) -> TestStep {
    (event_type, trust_level, attributes.to_vec())
}

fn bool_attr(name: &'static str, value: bool) -> (&'static str, serde_json::Value) {
    (name, serde_json::json!(value))
}

fn str_attr(name: &'static str, value: &'static str) -> (&'static str, serde_json::Value) {
    (name, serde_json::json!(value))
}

fn canonical_event(
    id: &str,
    event_type: &str,
    observed_at_unix_ms: u64,
    trust_level: TrustLevel,
    session_id: &str,
    trace_id: Option<&str>,
    extra_attributes: &[(&str, serde_json::Value)],
) -> CanonicalEventEnvelope {
    let mut attributes = BTreeMap::new();
    attributes.insert("session_id".to_owned(), serde_json::json!(session_id));
    for (key, value) in extra_attributes {
        attributes.insert((*key).to_owned(), value.clone());
    }
    CanonicalEventEnvelope {
        schema_version: EventSchemaVersion::V0,
        event_id: EventId::new(id),
        event_type: event_type.to_owned(),
        observed_at_unix_ms,
        received_at_unix_ms: None,
        severity: if event_type == "agent.content.ingested" {
            Severity::Low
        } else {
            Severity::High
        },
        source: EventSource {
            kind: SourceKind::Sensor,
            sensor: "sequence-fixture".to_owned(),
            integration: None,
        },
        provenance: EventProvenance {
            producer: "sequence-fixture".to_owned(),
            collector: "skynet-edr-core".to_owned(),
            tenant: Some("skynet-edr".to_owned()),
            source_event_id: None,
            trace_id: trace_id.map(str::to_owned),
            span_id: None,
            parent_span_id: None,
        },
        trust_level,
        title: format!("fixture {id}"),
        details: None,
        attributes,
        redaction: RedactionMetadata {
            contains_sensitive_data: false,
            redacted_fields: Vec::new(),
        },
    }
}

fn plugin_canonical_event(
    id: &str,
    event_type: &str,
    observed_at_unix_ms: u64,
    trust_level: TrustLevel,
    severity: Severity,
    trace_id: &str,
    extra_attributes: &[(&str, serde_json::Value)],
) -> CanonicalEventEnvelope {
    let mut event = canonical_event(
        id,
        event_type,
        observed_at_unix_ms,
        trust_level,
        "unused_session_removed_below",
        Some(trace_id),
        extra_attributes,
    );
    event.severity = severity;
    event.source.integration = Some("hermes".to_owned());
    event.attributes.remove("session_id");
    event
}
