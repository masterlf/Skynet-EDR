//! Platform-independent core primitives for Skynet-EDR.
//!
//! Platform sensors, storage, and response actions build on these stable core
//! types without coupling event or incident handling to privileged OS APIs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Operator-facing Skynet-EDR runtime mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Passive detection mode: observe and alert, but do not block.
    Passive,
    /// Guard mode: allow selected high-confidence actions to require approval.
    Guard,
    /// Enforcement mode: allow high-confidence containment actions.
    Enforcement,
}

impl RunMode {
    /// Return the stable lowercase label used in CLI output and configuration.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Guard => "guard",
            Self::Enforcement => "enforcement",
        }
    }
}

/// Severity assigned to events and incidents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational signal with no immediate security impact.
    Informational,
    /// Low-risk signal that may become useful when correlated.
    Low,
    /// Medium-risk signal that deserves triage.
    Medium,
    /// High-risk signal that should trigger operator attention.
    High,
    /// Critical signal indicating likely compromise or active exfiltration.
    Critical,
}

/// Platform-independent category for the telemetry producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Process execution, ancestry, arguments, or runtime metadata.
    Process,
    /// File read, write, metadata, or permission activity.
    File,
    /// Network connection, DNS, proxy, or egress activity.
    Network,
    /// MCP tool call, response, or server interaction.
    McpTool,
    /// Configuration, policy, or drift signal.
    Configuration,
    /// Scheduled job, cron entry, launch agent, or background task.
    ScheduledTask,
    /// Generic sensor signal when a narrower category is not yet available.
    Sensor,
}

/// Platform-independent source metadata for an event or incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSource {
    /// Coarse source category that avoids OS-specific type coupling.
    pub kind: SourceKind,
    /// Sensor, detector, or component name that produced the signal.
    pub sensor: String,
    /// Optional upstream integration name, such as an MCP client or `SaaS` source.
    pub integration: Option<String>,
}

/// Reason a field was redacted before storage or alerting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionReason {
    /// Field contained a credential, token, key, cookie, or equivalent secret.
    Secret,
    /// Field contained personally identifiable information.
    PersonalData,
    /// Field contained local environment or host details not needed downstream.
    LocalContext,
    /// Field was removed by policy even though the exact class is broader.
    Policy,
}

/// One JSON field redacted from an event or incident payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedField {
    /// Dotted JSON path to the redacted value.
    pub path: String,
    /// Why the value was redacted.
    pub reason: RedactionReason,
    /// Replacement marker stored in the serialized payload.
    pub replacement: String,
}

/// Redaction metadata carried with stored events and incidents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionMetadata {
    /// Whether sensitive data was found before redaction.
    pub contains_sensitive_data: bool,
    /// Fields removed or replaced before persistence or alerting.
    pub redacted_fields: Vec<RedactedField>,
}

/// Replacement marker used when a secret is removed before persistence or alerting.
pub const SECRET_REPLACEMENT: &str = "[REDACTED:secret]";

/// Replacement marker used when local host or filesystem context is minimized.
pub const LOCAL_CONTEXT_REPLACEMENT: &str = "[REDACTED:local_context]";

/// Value plus redaction metadata produced by the redaction engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Redacted<T> {
    /// Redacted value safe for storage or alerting.
    pub value: T,
    /// Redaction decisions applied to produce the value.
    pub metadata: RedactionMetadata,
}

/// Redact secrets and sensitive local context from free-form text.
#[must_use]
pub fn redact_text(input: &str) -> Redacted<String> {
    let mut fields = Vec::new();
    let mut output = Vec::new();

    let mut inside_key_block = false;
    let mut block_was_redacted = false;

    for line in input.lines() {
        if is_key_block_start(line) {
            inside_key_block = true;
            block_was_redacted = true;
            if output
                .last()
                .map_or(true, |previous| previous != SECRET_REPLACEMENT)
            {
                output.push(SECRET_REPLACEMENT.to_owned());
                fields.push(redaction_field(
                    "text",
                    RedactionReason::Secret,
                    SECRET_REPLACEMENT,
                ));
            }
            continue;
        }
        if inside_key_block {
            if is_key_block_end(line) {
                inside_key_block = false;
            }
            continue;
        }
        let redacted = redact_text_line(line, "text", &mut fields);
        output.push(redacted);
    }

    if inside_key_block && !block_was_redacted {
        fields.push(redaction_field(
            "text",
            RedactionReason::Secret,
            SECRET_REPLACEMENT,
        ));
    }

    Redacted {
        value: join_like_input(input, &output),
        metadata: metadata_from_fields(fields),
    }
}

/// Redact sensitive JSON attributes while preserving safe attributes unchanged.
#[must_use]
pub fn redact_attributes(
    attributes: &BTreeMap<String, serde_json::Value>,
) -> Redacted<BTreeMap<String, serde_json::Value>> {
    let mut fields = Vec::new();
    let mut value = BTreeMap::new();

    for (key, attribute) in attributes {
        let path = format!("attributes.{key}");
        value.insert(
            key.clone(),
            redact_json_value(key, attribute, &path, &mut fields),
        );
    }

    Redacted {
        value,
        metadata: metadata_from_fields(fields),
    }
}

fn redact_json_value(
    key: &str,
    value: &serde_json::Value,
    path: &str,
    fields: &mut Vec<RedactedField>,
) -> serde_json::Value {
    if is_sensitive_key(key) {
        fields.push(redaction_field(
            path,
            RedactionReason::Secret,
            SECRET_REPLACEMENT,
        ));
        return serde_json::Value::String(SECRET_REPLACEMENT.to_owned());
    }

    match value {
        serde_json::Value::String(text) => {
            if is_local_context(text) {
                fields.push(redaction_field(
                    path,
                    RedactionReason::LocalContext,
                    LOCAL_CONTEXT_REPLACEMENT,
                ));
                serde_json::Value::String(LOCAL_CONTEXT_REPLACEMENT.to_owned())
            } else {
                let redacted = redact_text_line(text, path, fields);
                serde_json::Value::String(redacted)
            }
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    redact_json_value("", item, &format!("{path}[{index}]"), fields)
                })
                .collect(),
        ),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(child_key, child_value)| {
                    let child_path = format!("{path}.{child_key}");
                    (
                        child_key.clone(),
                        redact_json_value(child_key, child_value, &child_path, fields),
                    )
                })
                .collect(),
        ),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            value.clone()
        }
    }
}

fn redact_text_line(line: &str, path: &str, fields: &mut Vec<RedactedField>) -> String {
    if contains_private_key_marker(line) {
        fields.push(redaction_field(
            path,
            RedactionReason::Secret,
            SECRET_REPLACEMENT,
        ));
        return SECRET_REPLACEMENT.to_owned();
    }

    let mut output = line.to_owned();
    output = redact_authorization_header(&output, path, fields);
    output = redact_key_value_secrets(&output, path, fields);
    output = redact_local_context(&output, path, fields);
    output
}

fn redact_authorization_header(line: &str, path: &str, fields: &mut Vec<RedactedField>) -> String {
    let lower = line.to_ascii_lowercase();
    let needle = concat!("authorization", ": bearer ");
    if let Some(index) = lower.find(needle) {
        let value_start = index + needle.len();
        let value_end = find_value_end(line, value_start);
        let mut output = String::with_capacity(line.len());
        output.push_str(&line[..value_start]);
        output.push_str(SECRET_REPLACEMENT);
        output.push_str(&line[value_end..]);
        fields.push(redaction_field(
            path,
            RedactionReason::Secret,
            SECRET_REPLACEMENT,
        ));
        return output;
    }
    line.to_owned()
}

fn redact_key_value_secrets(line: &str, path: &str, fields: &mut Vec<RedactedField>) -> String {
    let mut output = line.to_owned();
    for marker in ["=", ": "] {
        let lower = output.to_ascii_lowercase();
        let Some(marker_index) = lower.find(marker) else {
            continue;
        };
        let key_start = lower[..marker_index]
            .rfind(|character: char| character.is_whitespace() || character == ';')
            .map_or(0, |index| index + 1);
        let key = &output[key_start..marker_index];
        if !is_sensitive_key(
            key.trim_matches(|character| character == '-' || character == '\'' || character == '"'),
        ) {
            continue;
        }
        let value_start = marker_index + marker.len();
        let value_end = find_value_end(&output, value_start);
        output.replace_range(value_start..value_end, SECRET_REPLACEMENT);
        fields.push(redaction_field(
            path,
            RedactionReason::Secret,
            SECRET_REPLACEMENT,
        ));
    }
    output
}

fn redact_local_context(line: &str, path: &str, fields: &mut Vec<RedactedField>) -> String {
    let mut output = line.to_owned();
    for marker in ["/root/", "/home/"] {
        while let Some(start) = output.find(marker) {
            let end = find_value_end(&output, start);
            output.replace_range(start..end, LOCAL_CONTEXT_REPLACEMENT);
            fields.push(redaction_field(
                path,
                RedactionReason::LocalContext,
                LOCAL_CONTEXT_REPLACEMENT,
            ));
        }
    }
    output
}

fn is_key_block_start(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("-----begin ") && lower.contains(" key-----")
}

fn is_key_block_end(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("-----end ") && lower.contains(" key-----")
}

fn contains_private_key_marker(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("private key") || lower.contains("begin openssh key")
}

fn is_local_context(value: &str) -> bool {
    value.starts_with("/root/") || value.starts_with("/home/")
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase);
    let normalized: String = normalized.collect();

    normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("apikey")
        || normalized.contains("authorization")
        || normalized.contains("cookie")
        || normalized.contains("privatekey")
}

fn find_value_end(value: &str, start: usize) -> usize {
    value[start..]
        .find(|character: char| character.is_whitespace() || character == ';' || character == '&')
        .map_or(value.len(), |offset| start + offset)
}

fn redaction_field(
    path: impl Into<String>,
    reason: RedactionReason,
    replacement: &str,
) -> RedactedField {
    RedactedField {
        path: path.into(),
        reason,
        replacement: replacement.to_owned(),
    }
}

fn metadata_from_fields(redacted_fields: Vec<RedactedField>) -> RedactionMetadata {
    RedactionMetadata {
        contains_sensitive_data: !redacted_fields.is_empty(),
        redacted_fields,
    }
}

fn join_like_input(input: &str, lines: &[String]) -> String {
    let mut output = lines.join("\n");
    if input.ends_with('\n') {
        output.push('\n');
    }
    output
}

/// Stable platform-independent event identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(String);

impl EventId {
    /// Construct an event identifier from a stable string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable platform-independent incident identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IncidentId(String);

impl IncidentId {
    /// Construct an incident identifier from a stable string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Platform-independent security event payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Stable event identifier.
    pub id: EventId,
    /// Observation timestamp in Unix epoch milliseconds.
    pub observed_at_unix_ms: u64,
    /// Event severity.
    pub severity: Severity,
    /// Platform-independent source metadata.
    pub source: EventSource,
    /// Short operator-facing event title.
    pub title: String,
    /// Optional longer event details.
    pub details: Option<String>,
    /// Structured event attributes. Values must already be redacted if needed.
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// Redaction decisions applied before storage or alerting.
    pub redaction: RedactionMetadata,
}

/// Operator workflow status for an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Incident is open and requires triage or response.
    Open,
    /// Incident is under active investigation.
    Investigating,
    /// Incident has been contained but is not fully resolved.
    Contained,
    /// Incident is resolved and retained for audit/history.
    Resolved,
    /// Incident was determined to be benign or duplicate.
    Dismissed,
}

/// Platform-independent incident assembled from one or more events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    /// Stable incident identifier.
    pub id: IncidentId,
    /// Creation timestamp in Unix epoch milliseconds.
    pub created_at_unix_ms: u64,
    /// Last update timestamp in Unix epoch milliseconds.
    pub updated_at_unix_ms: u64,
    /// Current incident workflow status.
    pub status: IncidentStatus,
    /// Highest currently assessed incident severity.
    pub severity: Severity,
    /// Short operator-facing incident title.
    pub title: String,
    /// Operator-facing incident summary.
    pub summary: String,
    /// Primary source or detector that opened the incident.
    pub source: EventSource,
    /// Events correlated into this incident.
    pub events: Vec<Event>,
    /// Redaction decisions applied to incident-level data.
    pub redaction: RedactionMetadata,
}

/// Static product metadata shared by the CLI, daemon, and future API surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductInfo {
    /// Human-readable product name.
    pub name: &'static str,
    /// Canonical binary name.
    pub binary_name: &'static str,
    /// Default runtime mode for a fresh installation.
    pub run_mode: RunMode,
}

impl Default for ProductInfo {
    fn default() -> Self {
        Self {
            name: "Skynet-EDR",
            binary_name: "skynet-edr",
            run_mode: RunMode::Passive,
        }
    }
}
