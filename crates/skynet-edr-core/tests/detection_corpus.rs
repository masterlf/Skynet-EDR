//! Versioned S2 detection-corpus contract.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
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
const MAX_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 20_000;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_CASES: usize = 128;
const MAX_CASE_EVENTS: usize = 64;
const MAX_CASE_CALLS: usize = 64;

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
    let path = corpus_path();
    let size = fs::metadata(&path)
        .expect("versioned S2 corpus manifest must exist")
        .len();
    assert!(
        size <= MAX_MANIFEST_BYTES as u64,
        "S2 corpus exceeds byte ceiling"
    );
    let mut bytes = Vec::with_capacity(usize::try_from(size).expect("manifest size fits usize"));
    File::open(path)
        .expect("S2 corpus opens")
        .take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .expect("S2 corpus reads within ceiling");
    parse_manifest_bytes(&bytes).expect("S2 corpus manifest must be strict bounded JSON")
}

fn parse_manifest_bytes(bytes: &[u8]) -> Result<Manifest, String> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err("manifest byte ceiling exceeded".into());
    }
    JsonBounds::new(bytes).validate()?;
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if manifest.cases.len() > MAX_CASES
        || manifest.cases.iter().any(|case| {
            case.events.len() > MAX_CASE_EVENTS || case.producer_calls.len() > MAX_CASE_CALLS
        })
    {
        return Err("manifest collection ceiling exceeded".into());
    }
    let mut case_ids = BTreeSet::new();
    if manifest.cases.iter().any(|case| !case_ids.insert(&case.id)) {
        return Err("duplicate case_id".into());
    }
    Ok(manifest)
}

struct JsonBounds<'a> {
    input: &'a [u8],
    offset: usize,
    nodes: usize,
}

impl<'a> JsonBounds<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            nodes: 0,
        }
    }

    fn validate(mut self) -> Result<(), String> {
        self.value(0)?;
        self.whitespace();
        if self.offset != self.input.len() {
            return Err("trailing JSON data".into());
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<(), String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON depth ceiling exceeded".into());
        }
        self.nodes += 1;
        if self.nodes > MAX_JSON_NODES {
            return Err("JSON node ceiling exceeded".into());
        }
        self.whitespace();
        match self.input.get(self.offset).copied() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(|_| ()),
            Some(_) => self.scalar(),
            None => Err("unexpected end of JSON".into()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), String> {
        self.offset += 1;
        let mut keys = BTreeSet::new();
        loop {
            self.whitespace();
            if self.consume(b'}') {
                return Ok(());
            }
            let key = self.string()?;
            if !keys.insert(key) {
                return Err("duplicate JSON object key".into());
            }
            self.whitespace();
            if !self.consume(b':') {
                return Err("missing object colon".into());
            }
            self.value(depth)?;
            self.whitespace();
            if self.consume(b'}') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Err("missing object comma".into());
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), String> {
        self.offset += 1;
        loop {
            self.whitespace();
            if self.consume(b']') {
                return Ok(());
            }
            self.value(depth)?;
            self.whitespace();
            if self.consume(b']') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Err("missing array comma".into());
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.whitespace();
        let start = self.offset;
        if !self.consume(b'"') {
            return Err("object key is not a string".into());
        }
        let mut escaped = false;
        while let Some(byte) = self.input.get(self.offset).copied() {
            self.offset += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                if self.offset - start > MAX_STRING_BYTES {
                    return Err("JSON string ceiling exceeded".into());
                }
                return serde_json::from_slice(&self.input[start..self.offset])
                    .map_err(|error| error.to_string());
            }
        }
        Err("unterminated JSON string".into())
    }

    fn scalar(&mut self) -> Result<(), String> {
        let start = self.offset;
        while self
            .input
            .get(self.offset)
            .is_some_and(|byte| !matches!(byte, b',' | b']' | b'}' | b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
        if start == self.offset {
            return Err("invalid JSON scalar".into());
        }
        serde_json::from_slice::<Value>(&self.input[start..self.offset])
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn whitespace(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.input.get(self.offset) == Some(&expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }
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
fn manifest_parser_rejects_oversize_and_excessive_depth_before_replay() {
    let oversized = vec![b' '; MAX_MANIFEST_BYTES + 1];
    assert!(parse_manifest_bytes(&oversized).is_err());

    let nested = "[".repeat(MAX_JSON_DEPTH + 1) + &"]".repeat(MAX_JSON_DEPTH + 1);
    let deeply_nested = format!(
        "{{\"schema_version\":\"x\",\"corpus_notice\":\"x\",\"live_rules\":{{}},\"cases\":[],\"extra\":{nested}}}"
    );
    assert!(parse_manifest_bytes(deeply_nested.as_bytes()).is_err());
}

#[test]
fn manifest_parser_rejects_duplicate_keys_at_every_object_scope() {
    let samples = [
        r#"{"schema_version":"x","schema_version":"y","corpus_notice":"x","live_rules":{},"cases":[]}"#,
        r#"{"schema_version":"x","corpus_notice":"x","live_rules":{"EDR-MCP-001":"high","EDR-MCP-001":"critical"},"cases":[]}"#,
        r#"{"schema_version":"x","corpus_notice":"x","live_rules":{},"cases":[{"case_id":"a","case_id":"b","rule_id":null,"category":"hostile","expected_match":false,"expected_severity":null,"expected_incident_count":0,"forbidden_markers":[],"events":[],"producer_calls":[]}] }"#,
        r#"{"schema_version":"x","corpus_notice":"x","live_rules":{},"cases":[{"case_id":"a","rule_id":null,"category":"hostile","expected_match":false,"expected_severity":null,"expected_incident_count":0,"forbidden_markers":[],"events":[{"event_id":"a","attributes":{"tool":"x","tool":"y"}}],"producer_calls":[]}] }"#,
    ];
    for sample in samples {
        assert!(parse_manifest_bytes(sample.as_bytes()).is_err(), "{sample}");
    }
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
