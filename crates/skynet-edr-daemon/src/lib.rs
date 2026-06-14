//! Passive Linux fixture scanner for agent runtime configuration drift.
//!
//! The scanner is intentionally read-only and root-scoped. Tests exercise fake
//! fixtures so the daemon never needs privileged access or live Hermes state.

use std::{
    collections::{hash_map::DefaultHasher, BTreeMap},
    fs,
    hash::{Hash, Hasher},
    io,
    path::{Path, PathBuf},
};

use skynet_edr_core::{
    redact_attributes, Event, EventId, EventSource, RedactionMetadata, Severity, SourceKind,
};

const SENSOR_NAME: &str = "linux-passive-fixture";
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Manual Linux lab plan for future privileged sensor validation.
///
/// The current product deliberately does not start privileged sensors. This
/// structure records the safety preconditions that must be true before a human
/// operator runs disposable lab workflows outside CI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinuxLabPlan {
    /// Human-provided disposable VM label or inventory reference.
    pub disposable_vm_label: Option<String>,
    /// Human-provided controlled sink label for network-egress tests.
    pub controlled_sink_label: Option<String>,
    /// Fake honeytoken names only; never real secrets.
    pub fake_honeytoken_labels: Vec<String>,
    /// Manual approval reference, such as a ticket or chat thread.
    pub manual_approval_reference: Option<String>,
    /// Reserved future flag. Must remain false until real privileged sensors exist.
    pub allow_privileged_sensor_start: bool,
}

/// Linux lab plan validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxLabPlanError {
    missing_controls: Vec<&'static str>,
}

impl std::fmt::Display for LinuxLabPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Linux lab plan is not safe to run: ")?;
        write!(formatter, "{}", self.missing_controls.join(", "))
    }
}

impl std::error::Error for LinuxLabPlanError {}

/// Validate the manual Linux lab plan fail-closed.
///
/// # Errors
///
/// Returns [`LinuxLabPlanError`] when any required human-provided safety control
/// is absent, or when privileged sensor startup is requested before it exists.
pub fn validate_linux_lab_plan(plan: &LinuxLabPlan) -> Result<(), LinuxLabPlanError> {
    let mut missing_controls = Vec::new();
    if blank(plan.disposable_vm_label.as_deref()) {
        missing_controls.push("disposable VM details");
    }
    if blank(plan.controlled_sink_label.as_deref()) {
        missing_controls.push("controlled sink");
    }
    if plan.fake_honeytoken_labels.is_empty()
        || plan
            .fake_honeytoken_labels
            .iter()
            .any(|label| label.trim().is_empty())
    {
        missing_controls.push("fake honeytokens");
    }
    if blank(plan.manual_approval_reference.as_deref()) {
        missing_controls.push("manual approval");
    }
    if plan.allow_privileged_sensor_start {
        missing_controls.push("privileged sensor start is not implemented");
    }

    if missing_controls.is_empty() {
        Ok(())
    } else {
        Err(LinuxLabPlanError { missing_controls })
    }
}

/// Build a manual-only Linux lab workflow summary from a validated plan.
///
/// The rendered text is intentionally non-executable: it uses checklist language
/// and labels, not real shell commands, endpoints, credentials, or privileged
/// invocations.
///
/// # Errors
///
/// Returns [`LinuxLabPlanError`] if the plan is missing safety controls.
pub fn build_manual_linux_lab_workflow(plan: &LinuxLabPlan) -> Result<String, LinuxLabPlanError> {
    validate_linux_lab_plan(plan)?;
    let vm = plan.disposable_vm_label.as_deref().unwrap_or_default();
    let sink = plan.controlled_sink_label.as_deref().unwrap_or_default();
    let approval = plan
        .manual_approval_reference
        .as_deref()
        .unwrap_or_default();
    let honeytokens = plan.fake_honeytoken_labels.join(", ");

    Ok(format!(
        "manual-only Linux lab workflow\n\
         approval: {approval}\n\
         disposable_vm: {vm}\n\
         controlled_sink: {sink}\n\
         fake_honeytokens: {honeytokens}\n\
         steps:\n\
         1. Snapshot or rebuild the disposable VM.\n\
         2. Place fake honeytokens only; never copy personal or production secrets.\n\
         3. Point any egress simulation at the controlled sink label only.\n\
         4. Run passive fixture scanner first and record redacted events.\n\
         5. Stop and preserve evidence before any privileged sensor experiment."
    ))
}

fn blank(value: Option<&str>) -> bool {
    value.map_or(true, |value| value.trim().is_empty())
}

/// Root-scoped configuration for a passive Linux fixture scan.
#[derive(Debug, Clone)]
pub struct LinuxPassiveScanConfig {
    root: PathBuf,
    baseline_root: Option<PathBuf>,
    max_file_bytes: u64,
}

impl LinuxPassiveScanConfig {
    /// Create a scanner config rooted at a fake fixture tree.
    #[must_use]
    pub fn fixture_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            baseline_root: None,
            max_file_bytes: MAX_FILE_BYTES,
        }
    }

    /// Add a baseline fixture root for config-drift comparison.
    #[must_use]
    pub fn with_baseline_root(mut self, baseline_root: impl Into<PathBuf>) -> Self {
        self.baseline_root = Some(baseline_root.into());
        self
    }

    /// Limit file reads to avoid accidentally ingesting large local artifacts.
    #[must_use]
    pub const fn with_max_file_bytes(mut self, max_file_bytes: u64) -> Self {
        self.max_file_bytes = max_file_bytes;
        self
    }
}

/// Passive scanner output.
#[derive(Debug, Clone, PartialEq)]
pub struct LinuxPassiveScanReport {
    /// Security events emitted by the scan.
    pub events: Vec<Event>,
    /// Relative file paths skipped because they were unsafe or unreadable.
    pub skipped_files: Vec<String>,
}

/// Scan a fake Linux/Hermes filesystem fixture for suspicious MCP, cron, and drift signals.
///
/// This function is read-only: it lists and reads bounded files under `config.root` only.
///
/// # Errors
///
/// Returns an I/O error if the fixture root cannot be canonicalized, listed, or read.
pub fn scan_linux_fixture(config: &LinuxPassiveScanConfig) -> io::Result<LinuxPassiveScanReport> {
    let root = canonical_root(&config.root)?;
    let baseline_root = config
        .baseline_root
        .as_deref()
        .map(canonical_root)
        .transpose()?;

    let mut report = LinuxPassiveScanReport {
        events: Vec::new(),
        skipped_files: Vec::new(),
    };

    for relative_path in known_config_paths() {
        if let Some(content) = read_scoped_text_file(
            &root,
            Path::new(relative_path),
            config.max_file_bytes,
            &mut report.skipped_files,
        )? {
            scan_config_content(relative_path, &content, &mut report.events);
            if let Some(baseline) = baseline_root.as_deref() {
                scan_drift(
                    baseline,
                    relative_path,
                    &content,
                    config.max_file_bytes,
                    &mut report,
                )?;
            }
        }
    }

    scan_cron_directory(&root, config.max_file_bytes, &mut report)?;

    report.events.sort_by(|left, right| left.id.cmp(&right.id));
    report.skipped_files.sort();
    report.skipped_files.dedup();

    Ok(report)
}

fn known_config_paths() -> &'static [&'static str] {
    &[
        ".hermes/config.yaml",
        ".hermes/config.yml",
        ".hermes/config.json",
        ".config/hermes/config.yaml",
        ".config/hermes/config.yml",
        ".config/hermes/config.json",
    ]
}

fn scan_config_content(relative_path: &str, content: &str, events: &mut Vec<Event>) {
    let lower = content.to_ascii_lowercase();
    let has_mcp = lower.contains("mcp_servers") || lower.contains("mcpservers");
    let shell = contains_shell_interpreter(&lower);
    let egress = contains_network_egress(&lower);
    let sensitive = contains_sensitive_reference(&lower);

    if has_mcp && shell && egress {
        let severity = if sensitive {
            Severity::Critical
        } else {
            Severity::High
        };
        events.push(make_event(
            "EDR-MCP-001",
            severity,
            SourceKind::Configuration,
            "MCP server can execute shell with network egress",
            Some("MCP configuration references a shell interpreter and outbound transfer capability."),
            BTreeMap::from([
                ("path".to_owned(), serde_json::json!(relative_path)),
                ("evidence".to_owned(), serde_json::json!(interesting_lines(content))),
                (
                    "sensitive_reference".to_owned(),
                    serde_json::json!(sensitive),
                ),
            ]),
        ));
    }
}

fn scan_drift(
    baseline_root: &Path,
    relative_path: &str,
    content: &str,
    max_file_bytes: u64,
    report: &mut LinuxPassiveScanReport,
) -> io::Result<()> {
    let Some(baseline_content) = read_scoped_text_file(
        baseline_root,
        Path::new(relative_path),
        max_file_bytes,
        &mut Vec::new(),
    )?
    else {
        return Ok(());
    };

    if content == baseline_content {
        return Ok(());
    }

    let combined_lower = content.to_ascii_lowercase();
    let high_risk =
        contains_network_egress(&combined_lower) || contains_sensitive_reference(&combined_lower);
    let severity = if high_risk {
        Severity::High
    } else {
        Severity::Medium
    };
    report.events.push(make_event(
        "EDR-CONFIG-001",
        severity,
        SourceKind::Configuration,
        "Agent configuration drift detected",
        Some("Current fixture config differs from the configured baseline fixture."),
        BTreeMap::from([
            ("path".to_owned(), serde_json::json!(relative_path)),
            ("baseline_path".to_owned(), serde_json::json!(relative_path)),
            ("drift_kind".to_owned(), serde_json::json!("changed")),
            (
                "current_fingerprint".to_owned(),
                serde_json::json!(stable_fingerprint(content)),
            ),
            (
                "baseline_fingerprint".to_owned(),
                serde_json::json!(stable_fingerprint(&baseline_content)),
            ),
        ]),
    ));

    Ok(())
}

fn scan_cron_directory(
    root: &Path,
    max_file_bytes: u64,
    report: &mut LinuxPassiveScanReport,
) -> io::Result<()> {
    let cron_dir = root.join(".hermes/cron");
    if !cron_dir.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(cron_dir)?.collect::<Result<Vec<_>, io::Error>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let relative_string = relative_path_string(relative);
        if !entry.file_type()?.is_file() {
            if entry.file_type()?.is_symlink() {
                let _ = read_scoped_text_file(
                    root,
                    relative,
                    max_file_bytes,
                    &mut report.skipped_files,
                )?;
            }
            continue;
        }
        if let Some(content) =
            read_scoped_text_file(root, relative, max_file_bytes, &mut report.skipped_files)?
        {
            scan_cron_content(&relative_string, &content, &mut report.events);
        }
    }

    Ok(())
}

fn scan_cron_content(relative_path: &str, content: &str, events: &mut Vec<Event>) {
    let lower = content.to_ascii_lowercase();
    let broad_tools = ["terminal", "file", "web"]
        .iter()
        .all(|tool| lower.contains(tool));
    let messaging = ["discord", "telegram", "slack", "email", "send_message"]
        .iter()
        .any(|tool| lower.contains(tool));
    let sensitive = contains_sensitive_reference(&lower);
    let delivery = lower.contains("deliver raw") || lower.contains("raw data") || messaging;

    if broad_tools && (sensitive || delivery) {
        let severity = if sensitive && delivery {
            Severity::High
        } else {
            Severity::Medium
        };
        events.push(make_event(
            "EDR-CRON-001",
            severity,
            SourceKind::ScheduledTask,
            "Risky unattended Hermes automation",
            Some("Cron fixture combines broad tool access with sensitive or external-delivery indicators."),
            BTreeMap::from([
                ("path".to_owned(), serde_json::json!(relative_path)),
                ("evidence".to_owned(), serde_json::json!(interesting_lines(content))),
                ("broad_toolsets".to_owned(), serde_json::json!(broad_tools)),
                (
                    "sensitive_reference".to_owned(),
                    serde_json::json!(sensitive),
                ),
            ]),
        ));
    }
}

fn make_event(
    rule_id: &str,
    severity: Severity,
    source_kind: SourceKind,
    title: &str,
    details: Option<&str>,
    mut attributes: BTreeMap<String, serde_json::Value>,
) -> Event {
    attributes.insert("rule_id".to_owned(), serde_json::json!(rule_id));
    let redacted = redact_attributes(&attributes);
    let redaction = if redacted.metadata.contains_sensitive_data {
        redacted.metadata
    } else {
        RedactionMetadata {
            contains_sensitive_data: false,
            redacted_fields: Vec::new(),
        }
    };
    let id = EventId::new(format!(
        "evt_linux_passive_{:016x}",
        event_hash(rule_id, title, &redacted.value)
    ));

    Event {
        id,
        observed_at_unix_ms: 0,
        severity,
        source: EventSource {
            kind: source_kind,
            sensor: SENSOR_NAME.to_owned(),
            integration: Some("hermes".to_owned()),
        },
        title: title.to_owned(),
        details: details.map(str::to_owned),
        attributes: redacted.value,
        redaction,
    }
}

fn canonical_root(root: &Path) -> io::Result<PathBuf> {
    fs::canonicalize(root)
}

fn read_scoped_text_file(
    root: &Path,
    relative_path: &Path,
    max_file_bytes: u64,
    skipped_files: &mut Vec<String>,
) -> io::Result<Option<String>> {
    let relative_string = relative_path_string(relative_path);
    let candidate = root.join(relative_path);
    if !candidate.exists() {
        return Ok(None);
    }

    let Ok(canonical) = fs::canonicalize(&candidate) else {
        skipped_files.push(relative_string);
        return Ok(None);
    };
    if !canonical.starts_with(root) {
        skipped_files.push(relative_string);
        return Ok(None);
    }

    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() || metadata.len() > max_file_bytes {
        skipped_files.push(relative_string);
        return Ok(None);
    }

    match fs::read_to_string(canonical) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            skipped_files.push(relative_string);
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn relative_path_string(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn contains_shell_interpreter(lowercase: &str) -> bool {
    [
        "command: bash",
        "command: sh",
        "\"command\": \"bash",
        "\"command\": \"sh",
    ]
    .iter()
    .any(|needle| lowercase.contains(needle))
        || lowercase.contains("/bin/bash")
        || lowercase.contains("/bin/sh")
}

fn contains_network_egress(lowercase: &str) -> bool {
    [
        "curl ",
        "wget ",
        "invoke-webrequest",
        "/dev/tcp/",
        " nc ",
        " ncat ",
        " socat ",
        "https://",
        "http://",
    ]
    .iter()
    .any(|needle| lowercase.contains(needle))
}

fn contains_sensitive_reference(lowercase: &str) -> bool {
    [
        "~/.hermes/auth.json",
        ".hermes/auth.json",
        "~/.ssh/",
        "/.ssh/",
        "aws_access_key",
        "google_application_credentials",
        "api_key",
        "apikey",
        "token",
        "secret",
        "password",
    ]
    .iter()
    .any(|needle| lowercase.contains(needle))
}

fn interesting_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            contains_shell_interpreter(&lower)
                || contains_network_egress(&lower)
                || contains_sensitive_reference(&lower)
                || lower.contains("enabled_toolsets")
        })
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(8)
        .map(str::to_owned)
        .collect()
}

fn stable_fingerprint(content: &str) -> String {
    format!(
        "{:016x}",
        event_hash("fingerprint", content, &BTreeMap::new())
    )
}

fn event_hash(rule_id: &str, title: &str, attributes: &BTreeMap<String, serde_json::Value>) -> u64 {
    let mut hasher = DefaultHasher::new();
    rule_id.hash(&mut hasher);
    title.hash(&mut hasher);
    for (key, value) in attributes {
        key.hash(&mut hasher);
        value.to_string().hash(&mut hasher);
    }
    hasher.finish()
}
