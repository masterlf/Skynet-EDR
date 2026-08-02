//! Versioned S2 detection-corpus contract.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use serde::Deserialize;
use serde_json::Value;
use skynet_edr_core::{built_in_ai_agent_sequence_rules, parse_canonical_event_json, LocalStore};

const LIVE: [(&str, &str); 7] = [
    ("EDR-EXFIL-001", "critical"),
    ("EDR-MCP-001", "high"),
    ("EDR-PI-001", "high"),
    ("EDR-MSG-001", "high"),
    ("EDR-NET-001", "high"),
    ("EDR-CRON-001", "high"),
    ("EDR-MALWARE-001", "high"),
];
const DARK: [&str; 3] = ["EDR-CONFIG-001", "EDR-SCOPE-001", "EDR-PERSIST-001"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    corpus_notice: String,
    live_rules: BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    #[serde(rename = "case_id")]
    id: String,
    rule_id: Option<String>,
    category: String,
    expected_match: bool,
    expected_severity: Option<String>,
    expected_incident_count: usize,
    forbidden_markers: Vec<String>,
    events: Vec<Value>,
    producer_calls: Vec<Value>,
    #[serde(default)]
    hostile_payload: Option<Value>,
}

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/detections/v1/manifest.json")
}

fn load_manifest() -> Manifest {
    let bytes = fs::read(corpus_path()).expect("versioned S2 corpus manifest must exist");
    serde_json::from_slice(&bytes).expect("S2 corpus manifest must be strict valid JSON")
}

#[test]
fn manifest_is_complete_unique_and_locks_the_live_support_set() {
    let manifest = load_manifest();
    assert_eq!(manifest.schema_version, "skynet.detection-corpus.v1");
    assert_eq!(
        manifest.corpus_notice,
        "FAKE HONEYTOKEN FOR SKYNET-EDR LAB ONLY"
    );
    assert_eq!(manifest.live_rules.len(), LIVE.len());
    for (rule, severity) in LIVE {
        assert_eq!(
            manifest.live_rules.get(rule).map(String::as_str),
            Some(severity)
        );
    }
    for rule in DARK.into_iter().chain(["EDR-SECRET-001"]) {
        assert!(!manifest.live_rules.contains_key(rule));
    }

    let mut ids = BTreeSet::new();
    for case in &manifest.cases {
        assert!(
            ids.insert(case.id.as_str()),
            "duplicate case_id {}",
            case.id
        );
        assert!(!case.category.is_empty());
    }
    assert_eq!(manifest.cases.len(), 23);
    assert_eq!(
        manifest
            .cases
            .iter()
            .filter(|case| case.category == "malicious")
            .count(),
        7
    );
    assert_eq!(
        manifest
            .cases
            .iter()
            .filter(|case| case.category == "near_miss")
            .count(),
        7
    );
    assert_eq!(
        manifest
            .cases
            .iter()
            .filter(|case| case.category == "hostile")
            .count(),
        4
    );
    assert_eq!(
        manifest
            .cases
            .iter()
            .filter(|case| case.category == "synthetic_secret")
            .count(),
        2
    );
    assert_eq!(
        manifest
            .cases
            .iter()
            .filter(|case| case.category == "producer_dark")
            .count(),
        3
    );

    let rules = built_in_ai_agent_sequence_rules();
    for (rule_id, severity) in LIVE
        .into_iter()
        .filter(|(id, _)| !matches!(*id, "EDR-EXFIL-001" | "EDR-MALWARE-001"))
    {
        let rule = rules
            .iter()
            .find(|candidate| candidate.id == rule_id)
            .expect("live sequence rule exists");
        assert_eq!(
            format!("{:?}", rule.severity).to_ascii_lowercase(),
            severity
        );
    }
}

#[test]
fn corpus_replays_exact_rule_cardinality_and_redacts_forbidden_markers() {
    let manifest = load_manifest();
    for case in manifest.cases.iter().filter(|case| !case.events.is_empty()) {
        let root = std::env::temp_dir().join(format!(
            "skynet-s2-corpus-{}-{}",
            std::process::id(),
            case.id
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("private corpus state created");
        let store = LocalStore::open(root.join("events.sqlite")).expect("corpus store opens");
        let rules = built_in_ai_agent_sequence_rules();
        for event in &case.events {
            let encoded = serde_json::to_string(event).expect("fixture event serializes");
            let parsed = parse_canonical_event_json(&encoded).expect("fixture event is canonical");
            store
                .commit_continuous_event("uid:4242", &parsed, &rules, 10_000)
                .expect("fixture commits");
        }
        let incidents = store.list_incidents().expect("incidents list");
        let matching = case.rule_id.as_deref().map_or(0, |rule| {
            incidents
                .iter()
                .filter(|incident| incident.id.as_str().contains(rule))
                .count()
        });
        assert_eq!(matching, case.expected_incident_count, "{}", case.id);
        assert_eq!(case.expected_match, matching > 0, "{}", case.id);
        if let (Some(severity), Some(rule)) = (&case.expected_severity, &case.rule_id) {
            for incident in incidents
                .iter()
                .filter(|incident| incident.id.as_str().contains(rule))
            {
                assert_eq!(
                    format!("{:?}", incident.severity).to_ascii_lowercase(),
                    *severity
                );
            }
        }
        let serialized = format!(
            "{}\n{}",
            serde_json::to_string(&store.list_events().expect("events list")).unwrap(),
            serde_json::to_string(&incidents).unwrap()
        );
        for marker in &case.forbidden_markers {
            assert!(
                !serialized.contains(marker),
                "{} leaked forbidden marker",
                case.id
            );
        }
        let unrelated = incidents
            .iter()
            .filter(|incident| {
                matches!(
                    format!("{:?}", incident.severity).as_str(),
                    "High" | "Critical"
                ) && case
                    .rule_id
                    .as_deref()
                    .is_none_or(|rule| !incident.id.as_str().contains(rule))
            })
            .count();
        assert_eq!(unrelated, 0, "{} created unrelated High/Critical", case.id);
        drop(store);
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn malformed_manifest_and_duplicate_case_ids_fail_closed() {
    assert!(serde_json::from_str::<Manifest>(
        r#"{"schema_version":"x","corpus_notice":"x","live_rules":{},"cases":[],"extra":true}"#
    )
    .is_err());
    let manifest = load_manifest();
    let duplicate = serde_json::json!({
        "schema_version": manifest.schema_version,
        "corpus_notice": manifest.corpus_notice,
        "live_rules": manifest.live_rules,
        "cases": [
            {"case_id":"duplicate","rule_id":null,"category":"hostile","expected_match":false,"expected_severity":null,"expected_incident_count":0,"forbidden_markers":[],"events":[],"producer_calls":[]},
            {"case_id":"duplicate","rule_id":null,"category":"hostile","expected_match":false,"expected_severity":null,"expected_incident_count":0,"forbidden_markers":[],"events":[],"producer_calls":[]}
        ]
    });
    let parsed: Manifest = serde_json::from_value(duplicate).expect("shape remains valid");
    let unique = parsed
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_ne!(
        unique.len(),
        parsed.cases.len(),
        "duplicate oracle must reject manifest"
    );
}

#[test]
fn producer_calls_are_present_only_for_supported_live_cases() {
    let manifest = load_manifest();
    for case in &manifest.cases {
        if case.category == "malicious"
            || case.category == "near_miss"
            || case.category == "synthetic_secret"
        {
            assert!(
                !case.producer_calls.is_empty(),
                "{} lacks producer callback payload",
                case.id
            );
        }
        if case.category == "producer_dark" {
            assert!(case.events.is_empty());
            assert!(case.producer_calls.is_empty());
            assert!(!case.expected_match);
        }
    }
}

#[test]
fn hostile_corpus_payloads_fail_closed_as_canonical_events() {
    let manifest = load_manifest();
    for case in manifest
        .cases
        .iter()
        .filter(|case| case.category == "hostile")
    {
        let payload = case
            .hostile_payload
            .as_ref()
            .expect("hostile case has deterministic payload");
        let encoded = payload
            .as_str()
            .map_or_else(|| payload.to_string(), str::to_owned);
        assert!(
            parse_canonical_event_json(&encoded).is_err(),
            "{} hostile payload was accepted",
            case.id
        );
    }
}
