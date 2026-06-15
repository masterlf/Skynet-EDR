//! Platform-independent core primitives for Skynet-EDR.
//!
//! Platform sensors, storage, and response actions build on these stable core
//! types without coupling event or incident handling to privileged OS APIs.

use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension};
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
    /// Messaging, email, chat, or notification delivery action.
    Messaging,
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
    let mut output = line.to_owned();
    let mut search_from = 0;

    while let Some(index) = output[search_from..]
        .to_ascii_lowercase()
        .find("authorization:")
        .map(|offset| search_from + offset)
    {
        let value_start = index + "authorization:".len();
        let token_start = authorization_token_start(&output, value_start);
        let token_end = find_header_value_end(&output, token_start);
        if token_start < token_end {
            output.replace_range(token_start..token_end, SECRET_REPLACEMENT);
            fields.push(redaction_field(
                path,
                RedactionReason::Secret,
                SECRET_REPLACEMENT,
            ));
            search_from = token_start + SECRET_REPLACEMENT.len();
        } else {
            search_from = value_start;
        }
    }

    output
}

fn authorization_token_start(value: &str, start: usize) -> usize {
    let mut cursor = skip_ascii_whitespace(value, start);
    let scheme_end = value[cursor..]
        .find(char::is_whitespace)
        .map_or(cursor, |offset| cursor + offset);
    if scheme_end > cursor {
        cursor = skip_ascii_whitespace(value, scheme_end);
    }
    cursor
}

fn find_header_value_end(value: &str, start: usize) -> usize {
    if value[start..].starts_with(['\'', '"']) {
        return find_secret_value_bounds(value, start).1;
    }
    value[start..]
        .find([';', ',', '"'])
        .map_or(value.len(), |offset| start + offset)
}

fn skip_ascii_whitespace(value: &str, mut start: usize) -> usize {
    while value[start..].starts_with(char::is_whitespace) {
        start += value[start..].chars().next().map_or(0, char::len_utf8);
    }
    start
}

fn redact_key_value_secrets(line: &str, path: &str, fields: &mut Vec<RedactedField>) -> String {
    let mut output = line.to_owned();
    let mut search_from = 0;

    while let Some((separator, separator_len)) = find_next_key_value_separator(&output, search_from)
    {
        let key_end = output[..separator]
            .trim_end_matches(char::is_whitespace)
            .len();
        let key_start = output[..key_end]
            .rfind(|character: char| {
                character.is_whitespace() || character == ';' || character == '&'
            })
            .map_or(0, |index| index + 1);
        let key = output[key_start..key_end]
            .trim_matches(|character| character == '-' || character == '\'' || character == '"');

        if key.eq_ignore_ascii_case("authorization") {
            search_from = separator + separator_len;
            continue;
        }

        if is_sensitive_key(key) {
            let raw_value_start = separator + separator_len;
            let (value_start, value_end) = find_secret_value_bounds(&output, raw_value_start);
            if value_start < value_end {
                output.replace_range(value_start..value_end, SECRET_REPLACEMENT);
                fields.push(redaction_field(
                    path,
                    RedactionReason::Secret,
                    SECRET_REPLACEMENT,
                ));
                search_from = value_start + SECRET_REPLACEMENT.len();
            } else {
                search_from = raw_value_start;
            }
        } else {
            search_from = separator + separator_len;
        }
    }

    output
}

fn find_next_key_value_separator(value: &str, start: usize) -> Option<(usize, usize)> {
    let equals = value[start..].find('=').map(|offset| (start + offset, 1));
    let colon_space = value[start..].find(": ").map(|offset| (start + offset, 2));
    match (equals, colon_space) {
        (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
        (Some(found), None) | (None, Some(found)) => Some(found),
        (None, None) => None,
    }
}

fn find_secret_value_bounds(value: &str, start: usize) -> (usize, usize) {
    let mut value_start = start;
    while value[value_start..].starts_with(char::is_whitespace) {
        value_start += value[value_start..]
            .chars()
            .next()
            .map_or(0, char::len_utf8);
    }

    let quote = value[value_start..]
        .chars()
        .next()
        .filter(|character| *character == '\'' || *character == '"');
    if let Some(quote) = quote {
        let content_start = value_start + quote.len_utf8();
        let mut escaped = false;
        for (offset, character) in value[content_start..].char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
                continue;
            }
            if character == quote {
                return (content_start, content_start + offset);
            }
        }
        return (content_start, value.len());
    }

    (value_start, find_value_end(value, value_start))
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

/// Detection action requested when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionAction {
    /// Emit an alert for operator triage.
    Alert,
    /// Require explicit approval before continuing a risky operation.
    RequireApproval,
    /// Pause the related automation while an operator investigates.
    PauseAutomation,
}

/// Response action recorded on an emitted alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    /// Alert only; no runtime behavior changed.
    EmitAlert,
    /// Stop before a risky operation until an operator explicitly approves it.
    RequireApproval,
    /// Pause the related automation while an operator investigates.
    PauseAutomation,
    /// Block a suspected exfiltration network destination.
    BlockNetworkEgress,
}

/// Approval boundary that constrains which response actions may run automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalBoundary {
    /// Passive mode: alerting is allowed; containment or workflow changes are not.
    PassiveOnly,
    /// A human operator must approve disruptive or containment actions.
    OperatorRequired,
    /// Containment actions are pre-approved by local policy for high-confidence cases.
    PreApprovedContainment,
}

impl ApprovalBoundary {
    /// Return whether this boundary permits a response action.
    #[must_use]
    pub const fn allows(self, action: ResponseAction) -> bool {
        matches!(
            (self, action),
            (
                _,
                ResponseAction::EmitAlert | ResponseAction::RequireApproval
            ) | (Self::OperatorRequired, ResponseAction::PauseAutomation)
                | (
                    Self::PreApprovedContainment,
                    ResponseAction::PauseAutomation | ResponseAction::BlockNetworkEgress,
                )
        )
    }
}

/// Destination selected for alert delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlertDestination {
    /// Write the alert to stdout for CLI or daemon log forwarding.
    Stdout,
    /// Append the alert as one JSON object per line.
    JsonlFile {
        /// Relative or absolute JSONL output path supplied by configuration.
        path: String,
    },
    /// Send the alert to a configured HTTPS webhook.
    Webhook {
        /// Operator-facing destination name.
        name: String,
        /// Webhook URL; rendered alerts redact embedded credentials.
        url: String,
    },
    /// Send the alert by email through a configured mail backend.
    Email {
        /// Recipient address or alias.
        to: String,
    },
}

/// Stable platform-independent detection rule identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DetectionRuleId(String);

impl DetectionRuleId {
    /// Construct a rule identifier from a stable string.
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

/// Stable platform-independent alert identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AlertId(String);

impl AlertId {
    /// Construct an alert identifier from a stable string.
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

/// Operator-facing alert assembled from a rule match or correlated incident.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    /// Stable alert identifier.
    pub id: AlertId,
    /// Alert creation timestamp in Unix epoch milliseconds.
    pub created_at_unix_ms: u64,
    /// Alert severity.
    pub severity: Severity,
    /// Detection rule that triggered the alert.
    pub rule_id: DetectionRuleId,
    /// Primary source or detector that produced the alert.
    pub source: EventSource,
    /// Originating session, profile, tenant, or integration context.
    pub origin: String,
    /// Redacted operator-facing evidence snippet.
    pub evidence: String,
    /// Risky action attempted by the agent or tool, if known.
    pub attempted_action: Option<String>,
    /// Affected files, credentials, hosts, tenants, or other assets.
    pub affected_assets: Vec<String>,
    /// Network destination involved in the alert, if known.
    pub network_destination: Option<String>,
    /// Response action already taken or requested.
    pub action_taken: ResponseAction,
    /// Recommended operator response steps.
    pub recommended_next_steps: Vec<String>,
    /// Delivery destinations selected for this alert.
    pub destinations: Vec<AlertDestination>,
    /// Approval boundary applied to the response action.
    pub approval_boundary: ApprovalBoundary,
    /// Redaction decisions applied before alert rendering or delivery.
    pub redaction: RedactionMetadata,
}

/// Alert rendering error.
#[derive(Debug)]
pub enum AlertRenderError {
    /// JSON serialization failed while rendering a sanitized alert.
    Json(serde_json::Error),
}

impl std::fmt::Display for AlertRenderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "alert rendering JSON error: {error}"),
        }
    }
}

impl std::error::Error for AlertRenderError {}

impl From<serde_json::Error> for AlertRenderError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// Render an alert as JSON after applying server-side redaction.
///
/// # Errors
///
/// Returns [`AlertRenderError`] if the sanitized alert cannot be serialized.
pub fn render_alert_json(alert: &Alert) -> Result<Redacted<String>, AlertRenderError> {
    let alert = sanitize_alert_for_rendering(alert);
    let metadata = alert.redaction.clone();
    let value = serde_json::to_string(&alert)?;
    Ok(Redacted { value, metadata })
}

fn sanitize_alert_for_rendering(alert: &Alert) -> Alert {
    let mut sanitized = alert.clone();
    let mut fields = normalize_redaction_fields(&sanitized.redaction.redacted_fields);

    sanitized.source = sanitize_source_for_storage(&sanitized.source, "source", &mut fields);
    sanitized.origin = redact_text_field(&sanitized.origin, "origin", &mut fields);
    sanitized.evidence = redact_text_field(&sanitized.evidence, "evidence", &mut fields);
    sanitized.attempted_action = sanitized
        .attempted_action
        .as_deref()
        .map(|action| redact_text_field(action, "attempted_action", &mut fields));
    sanitized.affected_assets = sanitized
        .affected_assets
        .iter()
        .enumerate()
        .map(|(index, asset)| {
            redact_text_field(asset, &format!("affected_assets[{index}]"), &mut fields)
        })
        .collect();
    sanitized.network_destination = sanitized
        .network_destination
        .as_deref()
        .map(|destination| redact_text_field(destination, "network_destination", &mut fields));
    sanitized.recommended_next_steps = sanitized
        .recommended_next_steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            redact_text_field(
                step,
                &format!("recommended_next_steps[{index}]"),
                &mut fields,
            )
        })
        .collect();
    sanitized.destinations = sanitized
        .destinations
        .iter()
        .enumerate()
        .map(|(index, destination)| sanitize_alert_destination(destination, index, &mut fields))
        .collect();
    sanitized.redaction = metadata_from_fields(fields);
    sanitized
}

fn sanitize_alert_destination(
    destination: &AlertDestination,
    index: usize,
    fields: &mut Vec<RedactedField>,
) -> AlertDestination {
    match destination {
        AlertDestination::Stdout => AlertDestination::Stdout,
        AlertDestination::JsonlFile { path } => AlertDestination::JsonlFile {
            path: redact_text_field(path, &format!("destinations[{index}].path"), fields),
        },
        AlertDestination::Webhook { name, url } => AlertDestination::Webhook {
            name: redact_text_field(name, &format!("destinations[{index}].name"), fields),
            url: redact_text_field(url, &format!("destinations[{index}].url"), fields),
        },
        AlertDestination::Email { to } => AlertDestination::Email {
            to: redact_text_field(to, &format!("destinations[{index}].to"), fields),
        },
    }
}

/// One condition in a detection rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCondition {
    /// Dotted event or incident field path evaluated by the rule engine.
    pub field: String,
    /// Case-sensitive substring that must be present for the condition to match.
    pub contains: String,
}

/// Platform-independent YAML detection rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionRule {
    /// Stable detection rule identifier.
    pub id: DetectionRuleId,
    /// Operator-facing name.
    pub name: String,
    /// Severity assigned when the rule matches.
    pub severity: Severity,
    /// Source kinds the rule can evaluate.
    pub source_kinds: Vec<SourceKind>,
    /// Conditions that must match. Empty conditions fail validation.
    pub conditions: Vec<RuleCondition>,
    /// Actions requested on match. Empty actions fail validation.
    pub actions: Vec<DetectionAction>,
    /// Optional longer rule description.
    pub description: Option<String>,
}

impl DetectionRule {
    /// Validate the rule fail-closed before it can be evaluated.
    ///
    /// Validation rejects structurally ambiguous rules before matching can start.
    ///
    /// # Errors
    ///
    /// Returns [`DetectionRuleError::Validation`] when a required top-level field,
    /// condition, or response action is empty.
    pub fn validate(&self) -> Result<(), DetectionRuleError> {
        if self.id.as_str().trim().is_empty() {
            return Err(DetectionRuleError::Validation(
                "id must not be empty".to_owned(),
            ));
        }
        if self.name.trim().is_empty() {
            return Err(DetectionRuleError::Validation(
                "name must not be empty".to_owned(),
            ));
        }
        if self.source_kinds.is_empty() {
            return Err(DetectionRuleError::Validation(
                "source_kinds must not be empty".to_owned(),
            ));
        }
        if self.conditions.is_empty() {
            return Err(DetectionRuleError::Validation(
                "conditions must not be empty".to_owned(),
            ));
        }
        if self.actions.is_empty() {
            return Err(DetectionRuleError::Validation(
                "actions must not be empty".to_owned(),
            ));
        }
        for condition in &self.conditions {
            if condition.field.trim().is_empty() {
                return Err(DetectionRuleError::Validation(
                    "condition field must not be empty".to_owned(),
                ));
            }
            if condition.contains.is_empty() {
                return Err(DetectionRuleError::Validation(
                    "condition contains must not be empty".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Detection rule parsing and validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionRuleError {
    /// YAML parsing or schema deserialization failed.
    Parse(String),
    /// Rule parsed but failed fail-closed validation.
    Validation(String),
}

impl std::fmt::Display for DetectionRuleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "detection rule parse error: {error}"),
            Self::Validation(error) => {
                write!(formatter, "detection rule validation error: {error}")
            }
        }
    }
}

impl std::error::Error for DetectionRuleError {}

/// Parse and validate one YAML detection rule.
///
/// Invalid YAML, unknown schema fields, unknown enum values, or validation failures
/// return an error so callers can fail closed instead of silently disabling a rule.
///
/// # Errors
///
/// Returns [`DetectionRuleError::Parse`] for malformed YAML, unknown fields, or
/// unknown enum values. Returns [`DetectionRuleError::Validation`] for parsed
/// rules that are structurally empty or ambiguous.
pub fn parse_detection_rule_yaml(input: &str) -> Result<DetectionRule, DetectionRuleError> {
    let rule: DetectionRule = serde_yaml::from_str(input)
        .map_err(|error| DetectionRuleError::Parse(error.to_string()))?;
    rule.validate()?;
    Ok(rule)
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

/// Raw Hermes event kind accepted by the ingestion layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HermesIngestKind {
    /// Hermes tool invocation requested by the agent runtime.
    ToolCall,
    /// Hermes tool/MCP result content returned to the agent runtime.
    ToolResult,
}

/// One normalized raw record from Hermes session/tool traces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HermesIngestRecord {
    /// Observation timestamp in Unix epoch milliseconds.
    pub timestamp_unix_ms: u64,
    /// Hermes session identifier.
    pub session_id: String,
    /// Hermes profile name.
    pub profile: String,
    /// Raw event kind.
    pub kind: HermesIngestKind,
    /// Tool name, such as `read_file`, `terminal`, or `send_message`.
    pub tool: String,
    /// Optional MCP server name for MCP/tool result content.
    #[serde(default)]
    pub mcp_server: Option<String>,
    /// Tool arguments captured as hostile untrusted data.
    #[serde(default)]
    pub arguments: serde_json::Value,
    /// Tool result content captured as hostile untrusted data.
    #[serde(default)]
    pub content: Option<String>,
}

/// Error returned by Hermes ingestion.
#[derive(Debug)]
pub enum HermesIngestError {
    /// A JSONL record failed to parse. Line numbers are 1-based.
    Parse {
        /// JSONL line number that failed.
        line: usize,
        /// Parser error message.
        error: String,
    },
    /// Local storage failed while persisting redacted events.
    Storage(StorageError),
}

impl std::fmt::Display for HermesIngestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse { line, error } => {
                write!(
                    formatter,
                    "Hermes ingestion parse error on line {line}: {error}"
                )
            }
            Self::Storage(error) => write!(formatter, "Hermes ingestion storage error: {error}"),
        }
    }
}

impl std::error::Error for HermesIngestError {}

impl From<StorageError> for HermesIngestError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// Ingest Hermes JSONL records into the local store after normalization and redaction.
///
/// Empty lines are ignored. All JSON lines are parsed before anything is
/// persisted, so malformed input fails closed without partial writes.
///
/// # Errors
///
/// Returns [`HermesIngestError::Parse`] for malformed JSONL records, or
/// [`HermesIngestError::Storage`] if local persistence fails.
pub fn ingest_hermes_json_lines(
    store: &LocalStore,
    input: &str,
) -> Result<Vec<Event>, HermesIngestError> {
    let mut records = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record = serde_json::from_str::<HermesIngestRecord>(trimmed).map_err(|error| {
            HermesIngestError::Parse {
                line: index + 1,
                error: error.to_string(),
            }
        })?;
        records.push(record);
    }

    persist_hermes_records(store, &records)
}

/// Ingest a Hermes trace JSON object or array into the local store.
///
/// This accepts the looser object shape emitted by Hermes session/tool-call traces
/// and maps it into the strict [`HermesIngestRecord`] normalization boundary.
///
/// # Errors
///
/// Returns [`HermesIngestError::Parse`] for malformed JSON, or
/// [`HermesIngestError::Storage`] if local persistence fails.
pub fn ingest_hermes_events_json(
    store: &LocalStore,
    input: &str,
) -> Result<usize, HermesIngestError> {
    let value = serde_json::from_str::<serde_json::Value>(input).map_err(|error| {
        HermesIngestError::Parse {
            line: 1,
            error: error.to_string(),
        }
    })?;
    let records = hermes_records_from_trace_value(&value);
    let events = persist_hermes_records(store, &records)?;
    Ok(events.len())
}

fn persist_hermes_records(
    store: &LocalStore,
    records: &[HermesIngestRecord],
) -> Result<Vec<Event>, HermesIngestError> {
    let events = records
        .iter()
        .enumerate()
        .map(|(index, record)| normalize_hermes_record(record, index))
        .collect::<Vec<_>>();

    for event in &events {
        store.insert_event(event)?;
    }

    Ok(events)
}

fn hermes_records_from_trace_value(value: &serde_json::Value) -> Vec<HermesIngestRecord> {
    match value {
        serde_json::Value::Array(records) => records
            .iter()
            .flat_map(hermes_records_from_trace_object)
            .collect(),
        serde_json::Value::Object(_) => hermes_records_from_trace_object(value),
        _ => Vec::new(),
    }
}

fn hermes_records_from_trace_object(value: &serde_json::Value) -> Vec<HermesIngestRecord> {
    let mut records = Vec::new();
    if let Some(tool_call) = value.get("tool_call") {
        records.push(HermesIngestRecord {
            timestamp_unix_ms: trace_timestamp(value),
            session_id: trace_string(value, "session_id", "unknown_session"),
            profile: trace_string(value, "profile", "unknown_profile"),
            kind: HermesIngestKind::ToolCall,
            tool: trace_string(tool_call, "name", "unknown_tool"),
            mcp_server: value
                .get("mcp_server")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            arguments: tool_call
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            content: value
                .get("tool_output")
                .or_else(|| value.get("mcp_output"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        });
    } else if let Some(output) = value.get("tool_output").or_else(|| value.get("mcp_output")) {
        records.push(HermesIngestRecord {
            timestamp_unix_ms: trace_timestamp(value),
            session_id: trace_string(value, "session_id", "unknown_session"),
            profile: trace_string(value, "profile", "unknown_profile"),
            kind: HermesIngestKind::ToolResult,
            tool: trace_string(value, "tool", "unknown_tool"),
            mcp_server: value
                .get("mcp_server")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            arguments: serde_json::Value::Null,
            content: output.as_str().map(str::to_owned),
        });
    }

    if let Some(file_accesses) = value
        .get("file_accesses")
        .and_then(serde_json::Value::as_array)
    {
        for file_access in file_accesses {
            records.push(HermesIngestRecord {
                timestamp_unix_ms: trace_timestamp(value),
                session_id: trace_string(value, "session_id", "unknown_session"),
                profile: trace_string(value, "profile", "unknown_profile"),
                kind: HermesIngestKind::ToolCall,
                tool: "file_access".to_owned(),
                mcp_server: None,
                arguments: file_access.clone(),
                content: None,
            });
        }
    }

    records
}

fn trace_timestamp(value: &serde_json::Value) -> u64 {
    value
        .get("timestamp_unix_ms")
        .or_else(|| value.get("observed_at_unix_ms"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn trace_string(value: &serde_json::Value, key: &str, fallback: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

fn hermes_source_kind(
    kind: HermesIngestKind,
    tool: &str,
    network_indicator: bool,
    delivery_indicator: bool,
) -> SourceKind {
    match kind {
        HermesIngestKind::ToolCall if is_process_tool(tool) => SourceKind::Process,
        HermesIngestKind::ToolCall if delivery_indicator => SourceKind::Messaging,
        HermesIngestKind::ToolCall if is_file_tool(tool) => SourceKind::File,
        HermesIngestKind::ToolCall if network_indicator => SourceKind::Network,
        HermesIngestKind::ToolCall | HermesIngestKind::ToolResult => SourceKind::McpTool,
    }
}

#[allow(clippy::too_many_lines)]
fn normalize_hermes_record(record: &HermesIngestRecord, index: usize) -> Event {
    let tool_lower = record.tool.to_ascii_lowercase();
    let arguments_text = record.arguments.to_string().to_ascii_lowercase();
    let network_indicator = is_networkish_tool_call(&tool_lower, &arguments_text);
    let delivery_indicator = is_delivery_tool_call(&tool_lower, &arguments_text);
    let sensitive_access = contains_sensitive_path(&arguments_text);

    let source_kind = hermes_source_kind(
        record.kind,
        &tool_lower,
        network_indicator,
        delivery_indicator,
    );
    let severity = hermes_severity(
        record.kind,
        sensitive_access,
        network_indicator,
        delivery_indicator,
    );
    let attributes =
        hermes_event_attributes(record, &tool_lower, network_indicator, delivery_indicator);
    let title = hermes_event_title(record, &tool_lower, delivery_indicator);
    let details = Some(hermes_event_details(record.kind));

    redacted_hermes_event(Event {
        id: EventId::new(stable_hermes_event_id(record, index)),
        observed_at_unix_ms: record.timestamp_unix_ms,
        severity,
        source: EventSource {
            kind: source_kind,
            sensor: "hermes-event-ingestion".to_owned(),
            integration: Some("hermes".to_owned()),
        },
        title,
        details,
        attributes,
        redaction: RedactionMetadata {
            contains_sensitive_data: false,
            redacted_fields: redaction_from_omitted_content(record),
        },
    })
}

fn hermes_severity(
    kind: HermesIngestKind,
    sensitive_access: bool,
    network_indicator: bool,
    delivery_indicator: bool,
) -> Severity {
    match kind {
        HermesIngestKind::ToolResult => Severity::Medium,
        HermesIngestKind::ToolCall
            if sensitive_access || network_indicator || delivery_indicator =>
        {
            Severity::High
        }
        HermesIngestKind::ToolCall => Severity::Low,
    }
}

fn hermes_event_attributes(
    record: &HermesIngestRecord,
    tool_lower: &str,
    network_indicator: bool,
    delivery_indicator: bool,
) -> BTreeMap<String, serde_json::Value> {
    let mut attributes = hermes_base_attributes(record, network_indicator, delivery_indicator);
    insert_optional_hermes_arguments(&mut attributes, record);
    if is_process_tool(tool_lower) {
        attributes.insert(
            "command_class".to_owned(),
            serde_json::json!(command_class_from_arguments(&record.arguments)),
        );
    }
    if delivery_indicator {
        attributes.insert("delivery_action".to_owned(), serde_json::json!(record.tool));
    }
    if let Some(content) = record.content.as_deref() {
        attributes.insert("content_redacted".to_owned(), serde_json::json!(true));
        attributes.insert(
            "content_length".to_owned(),
            serde_json::json!(content.len()),
        );
    }
    attributes
}

fn hermes_base_attributes(
    record: &HermesIngestRecord,
    network_indicator: bool,
    delivery_indicator: bool,
) -> BTreeMap<String, serde_json::Value> {
    BTreeMap::from([
        (
            "session_id".to_owned(),
            serde_json::json!(record.session_id),
        ),
        ("profile".to_owned(), serde_json::json!(record.profile)),
        ("kind".to_owned(), serde_json::json!(record.kind)),
        ("tool".to_owned(), serde_json::json!(record.tool)),
        ("tool_name".to_owned(), serde_json::json!(record.tool)),
        (
            "mcp_output_untrusted".to_owned(),
            serde_json::json!(
                record.content.is_some() || record.kind == HermesIngestKind::ToolResult
            ),
        ),
        (
            "trust_level".to_owned(),
            serde_json::json!(match record.kind {
                HermesIngestKind::ToolCall => "agent_action",
                HermesIngestKind::ToolResult => "untrusted_content",
            }),
        ),
        (
            "network_indicator".to_owned(),
            serde_json::json!(network_indicator),
        ),
        (
            "delivery_indicator".to_owned(),
            serde_json::json!(delivery_indicator),
        ),
    ])
}

fn insert_optional_hermes_arguments(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    record: &HermesIngestRecord,
) {
    if let Some(server) = record.mcp_server.as_deref() {
        attributes.insert("mcp_server".to_owned(), serde_json::json!(server));
    }
    if !record.arguments.is_null() {
        attributes.insert("arguments".to_owned(), record.arguments.clone());
    }
    for (field, attribute) in [
        ("path", "path"),
        ("command", "command"),
        ("target", "delivery_target"),
    ] {
        if let Some(value) = extract_string_argument(&record.arguments, field) {
            attributes.insert(attribute.to_owned(), serde_json::json!(value));
        }
    }
}

fn hermes_event_title(
    record: &HermesIngestRecord,
    tool_lower: &str,
    delivery_indicator: bool,
) -> String {
    match record.kind {
        HermesIngestKind::ToolCall if is_process_tool(tool_lower) => format!(
            "Hermes terminal command observed: {}",
            command_class_from_arguments(&record.arguments)
        ),
        HermesIngestKind::ToolCall if delivery_indicator => {
            "Hermes delivery action observed".to_owned()
        }
        HermesIngestKind::ToolCall if is_file_tool(tool_lower) => format!(
            "Hermes file {} observed",
            extract_string_argument(&record.arguments, "operation").unwrap_or("access")
        ),
        HermesIngestKind::ToolCall => format!("Hermes tool call: {}", record.tool),
        HermesIngestKind::ToolResult => format!("Hermes tool result: {}", record.tool),
    }
}

fn hermes_event_details(kind: HermesIngestKind) -> String {
    match kind {
        HermesIngestKind::ToolCall => "Hermes tool call normalized from agent trace.".to_owned(),
        HermesIngestKind::ToolResult => {
            "Hermes tool output treated as untrusted content and not stored raw.".to_owned()
        }
    }
}

fn redacted_hermes_event(mut event: Event) -> Event {
    let mut fields = event.redaction.redacted_fields.clone();
    let title = redact_text(&event.title);
    event.title = title.value;
    fields.extend(title.metadata.redacted_fields);

    if let Some(details) = event.details.as_deref() {
        let redacted = redact_text(details);
        event.details = Some(redacted.value);
        fields.extend(redacted.metadata.redacted_fields);
    }

    let attributes = redact_attributes(&event.attributes);
    event.attributes = attributes.value;
    fields.extend(attributes.metadata.redacted_fields);
    fields.sort_by(|left, right| left.path.cmp(&right.path));
    fields.dedup_by(|left, right| left.path == right.path && left.reason == right.reason);
    event.redaction = RedactionMetadata {
        contains_sensitive_data: !fields.is_empty(),
        redacted_fields: fields,
    };
    event
}

fn redaction_from_omitted_content(record: &HermesIngestRecord) -> Vec<RedactedField> {
    let Some(content) = record.content.as_deref() else {
        return Vec::new();
    };
    let redacted = redact_text(content);
    redacted
        .metadata
        .redacted_fields
        .into_iter()
        .map(|mut field| {
            field.path = format!("content.{}", field.path);
            field
        })
        .collect()
}

fn stable_hermes_event_id(record: &HermesIngestRecord, index: usize) -> String {
    format!(
        "hermes:{}:{}:{}:{}",
        safe_id_fragment(&record.session_id),
        record.timestamp_unix_ms,
        safe_id_fragment(&record.tool),
        index
    )
}

fn safe_id_fragment(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn extract_string_argument<'a>(arguments: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    arguments.get(key).and_then(serde_json::Value::as_str)
}

fn is_file_tool(tool: &str) -> bool {
    matches!(
        tool,
        "file_access" | "read_file" | "write_file" | "search_files" | "patch"
    )
}

fn is_process_tool(tool: &str) -> bool {
    matches!(
        tool,
        "terminal" | "shell" | "bash" | "sh" | "zsh" | "execute_code"
    )
}

fn command_class_from_arguments(arguments: &serde_json::Value) -> &'static str {
    let command = extract_string_argument(arguments, "command")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if [
        "curl", "wget", "nc ", "ncat", "socat", "ssh ", "scp ", "sftp", "http://", "https://",
        "/dev/tcp",
    ]
    .iter()
    .any(|indicator| command.contains(indicator))
    {
        "network_egress"
    } else if command.contains("cron") || command.contains("crontab") {
        "scheduled_task"
    } else {
        "process_execution"
    }
}

fn is_networkish_tool_call(tool: &str, arguments: &str) -> bool {
    tool == "web_extract"
        || tool == "web_search"
        || tool == "browser"
        || arguments.contains("curl ")
        || arguments.contains("wget ")
        || arguments.contains("/dev/tcp")
        || arguments.contains("http://")
        || arguments.contains("https://")
}

fn is_delivery_tool_call(tool: &str, arguments: &str) -> bool {
    tool == "send_message"
        || tool == "himalaya"
        || tool.contains("email")
        || tool.contains("gmail")
        || arguments.contains("telegram")
        || arguments.contains("discord")
        || arguments.contains("slack")
        || arguments.contains("sendmessage")
}

fn contains_sensitive_path(text: &str) -> bool {
    text.contains(".hermes/auth")
        || text.contains(".hermes/.env")
        || text.contains(".ssh/")
        || text.contains("id_rsa")
        || text.contains(".env")
        || text.contains("oauth")
        || text.contains("credentials")
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

/// Result type used by local storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Error returned by `SQLite` or JSONL local storage operations.
#[derive(Debug)]
pub enum StorageError {
    /// `SQLite` schema migration, write, or query failed.
    Sqlite(rusqlite::Error),
    /// JSON serialization or deserialization failed.
    Json(serde_json::Error),
    /// Filesystem I/O failed for a database or JSONL export path.
    Io(std::io::Error),
    /// A timestamp does not fit `SQLite`'s signed integer representation.
    IntegerOutOfRange {
        /// Name of the timestamp field being persisted.
        field: &'static str,
        /// Original unsigned timestamp value.
        value: u64,
    },
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "sqlite storage error: {error}"),
            Self::Json(error) => write!(formatter, "json storage error: {error}"),
            Self::Io(error) => write!(formatter, "local storage I/O error: {error}"),
            Self::IntegerOutOfRange { field, value } => {
                write!(
                    formatter,
                    "local storage integer out of range: {field}={value}"
                )
            }
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Local `SQLite` storage for redacted events and incidents.
pub struct LocalStore {
    path: PathBuf,
    connection: Connection,
}

impl LocalStore {
    /// Open or create a local `SQLite` store and apply the MVP schema.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when `SQLite` cannot open the database or migrate
    /// the schema.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        let connection = Connection::open(&path)?;
        let store = Self { path, connection };
        store.migrate()?;
        Ok(store)
    }

    /// Return the database path backing this local store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Insert or replace one redacted event.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when JSON serialization or `SQLite` persistence
    /// fails.
    pub fn insert_event(&self, event: &Event) -> StorageResult<()> {
        let event = sanitize_event_for_storage(event);
        insert_event_on_connection(&self.connection, &event)
    }

    /// Insert or replace one redacted incident and its embedded events.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when embedded event persistence, JSON
    /// serialization, or `SQLite` persistence fails.
    pub fn insert_incident(&self, incident: &Incident) -> StorageResult<()> {
        let incident = sanitize_incident_for_storage(incident);
        let transaction = self.connection.unchecked_transaction()?;
        for event in &incident.events {
            insert_event_on_connection(&transaction, event)?;
        }
        insert_incident_on_connection(&transaction, &incident)?;
        transaction.commit()?;
        Ok(())
    }

    /// Load one event by identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when `SQLite` query or JSON deserialization fails.
    pub fn get_event(&self, id: &str) -> StorageResult<Option<Event>> {
        self.connection
            .query_row(
                "SELECT payload_json FROM events WHERE id = ?1",
                params![id],
                |row| deserialize_row_json(row, 0),
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Load one incident by identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when `SQLite` query or JSON deserialization fails.
    pub fn get_incident(&self, id: &str) -> StorageResult<Option<Incident>> {
        self.connection
            .query_row(
                "SELECT payload_json FROM incidents WHERE id = ?1",
                params![id],
                |row| deserialize_row_json(row, 0),
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// List all stored events ordered by observation time and identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when `SQLite` query or JSON deserialization fails.
    pub fn list_events(&self) -> StorageResult<Vec<Event>> {
        let mut statement = self
            .connection
            .prepare("SELECT payload_json FROM events ORDER BY observed_at_unix_ms ASC, id ASC")?;
        collect_payload_rows(&mut statement, [])
    }

    /// List all stored incidents ordered by last update time and identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when `SQLite` query or JSON deserialization fails.
    pub fn list_incidents(&self) -> StorageResult<Vec<Incident>> {
        let mut statement = self.connection.prepare(
            "SELECT payload_json FROM incidents ORDER BY updated_at_unix_ms ASC, id ASC",
        )?;
        collect_payload_rows(&mut statement, [])
    }

    fn migrate(&self) -> StorageResult<()> {
        self.connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY NOT NULL,
                observed_at_unix_ms INTEGER NOT NULL,
                severity TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                title TEXT NOT NULL,
                payload_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_events_observed_at
                ON events(observed_at_unix_ms);
             CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY NOT NULL,
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                payload_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_incidents_updated_at
                ON incidents(updated_at_unix_ms);",
        )?;
        Ok(())
    }
}

fn insert_event_on_connection(connection: &Connection, event: &Event) -> StorageResult<()> {
    let payload = serde_json::to_string(event)?;
    let severity = serde_json::to_value(event.severity)?;
    let source_kind = serde_json::to_value(event.source.kind)?;
    let observed_at_unix_ms =
        sqlite_unix_ms("event.observed_at_unix_ms", event.observed_at_unix_ms)?;
    connection.execute(
        "INSERT INTO events (
            id, observed_at_unix_ms, severity, source_kind, title, payload_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET
            observed_at_unix_ms = excluded.observed_at_unix_ms,
            severity = excluded.severity,
            source_kind = excluded.source_kind,
            title = excluded.title,
            payload_json = excluded.payload_json",
        params![
            event.id.as_str(),
            observed_at_unix_ms,
            json_string_value(&severity),
            json_string_value(&source_kind),
            event.title,
            payload,
        ],
    )?;
    Ok(())
}

fn insert_incident_on_connection(
    connection: &Connection,
    incident: &Incident,
) -> StorageResult<()> {
    let payload = serde_json::to_string(incident)?;
    let severity = serde_json::to_value(incident.severity)?;
    let status = serde_json::to_value(incident.status)?;
    let created_at_unix_ms =
        sqlite_unix_ms("incident.created_at_unix_ms", incident.created_at_unix_ms)?;
    let updated_at_unix_ms =
        sqlite_unix_ms("incident.updated_at_unix_ms", incident.updated_at_unix_ms)?;
    connection.execute(
        "INSERT INTO incidents (
            id, created_at_unix_ms, updated_at_unix_ms, status, severity, title, payload_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(id) DO UPDATE SET
            created_at_unix_ms = excluded.created_at_unix_ms,
            updated_at_unix_ms = excluded.updated_at_unix_ms,
            status = excluded.status,
            severity = excluded.severity,
            title = excluded.title,
            payload_json = excluded.payload_json",
        params![
            incident.id.as_str(),
            created_at_unix_ms,
            updated_at_unix_ms,
            json_string_value(&status),
            json_string_value(&severity),
            incident.title,
            payload,
        ],
    )?;
    Ok(())
}

fn sqlite_unix_ms(field: &'static str, value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| StorageError::IntegerOutOfRange { field, value })
}

fn sanitize_incident_for_storage(incident: &Incident) -> Incident {
    let mut sanitized = incident.clone();
    let mut fields = normalize_redaction_fields(&sanitized.redaction.redacted_fields);

    sanitized.title = redact_text_field(&sanitized.title, "title", &mut fields);
    sanitized.summary = redact_text_field(&sanitized.summary, "summary", &mut fields);
    sanitized.source = sanitize_source_for_storage(&sanitized.source, "source", &mut fields);
    sanitized.events = sanitized
        .events
        .iter()
        .map(sanitize_event_for_storage)
        .collect();
    sanitized.redaction = metadata_from_fields(fields);
    sanitized
}

fn sanitize_event_for_storage(event: &Event) -> Event {
    let mut sanitized = event.clone();
    let mut fields = normalize_redaction_fields(&sanitized.redaction.redacted_fields);

    sanitized.title = redact_text_field(&sanitized.title, "title", &mut fields);
    sanitized.details = sanitized
        .details
        .as_deref()
        .map(|details| redact_text_field(details, "details", &mut fields));
    sanitized.source = sanitize_source_for_storage(&sanitized.source, "source", &mut fields);

    let attributes = redact_attributes(&sanitized.attributes);
    sanitized.attributes = attributes.value;
    fields.extend(attributes.metadata.redacted_fields);
    sanitized.redaction = metadata_from_fields(fields);
    sanitized
}

fn normalize_redaction_fields(fields: &[RedactedField]) -> Vec<RedactedField> {
    fields
        .iter()
        .map(|field| RedactedField {
            path: redact_text(&field.path).value,
            reason: field.reason,
            replacement: replacement_for_reason(field.reason).to_owned(),
        })
        .collect()
}

fn replacement_for_reason(reason: RedactionReason) -> &'static str {
    match reason {
        RedactionReason::Secret => SECRET_REPLACEMENT,
        RedactionReason::LocalContext => LOCAL_CONTEXT_REPLACEMENT,
        RedactionReason::PersonalData => "[REDACTED:personal_data]",
        RedactionReason::Policy => "[REDACTED:policy]",
    }
}

fn sanitize_source_for_storage(
    source: &EventSource,
    path: &str,
    fields: &mut Vec<RedactedField>,
) -> EventSource {
    EventSource {
        kind: source.kind,
        sensor: redact_text_field(&source.sensor, &format!("{path}.sensor"), fields),
        integration: source.integration.as_deref().map(|integration| {
            redact_text_field(integration, &format!("{path}.integration"), fields)
        }),
    }
}

fn redact_text_field(text: &str, path: &str, fields: &mut Vec<RedactedField>) -> String {
    let redacted = redact_text(text);
    fields.extend(
        redacted
            .metadata
            .redacted_fields
            .into_iter()
            .map(|field| RedactedField {
                path: if field.path == "text" {
                    path.to_owned()
                } else {
                    format!("{path}.{}", field.path)
                },
                reason: field.reason,
                replacement: field.replacement,
            }),
    );
    redacted.value
}

/// Append one redacted event to a JSONL file.
///
/// # Errors
///
/// Returns [`StorageError`] when JSON serialization or file append fails.
pub fn append_event_jsonl(path: impl AsRef<Path>, event: &Event) -> StorageResult<()> {
    let event = sanitize_event_for_storage(event);
    append_jsonl(path, &event)
}

/// Append one redacted incident to a JSONL file.
///
/// # Errors
///
/// Returns [`StorageError`] when JSON serialization or file append fails.
pub fn append_incident_jsonl(path: impl AsRef<Path>, incident: &Incident) -> StorageResult<()> {
    let incident = sanitize_incident_for_storage(incident);
    append_jsonl(path, &incident)
}

fn append_jsonl<T: Serialize>(path: impl AsRef<Path>, value: &T) -> StorageResult<()> {
    let mut record = serde_json::to_vec(value)?;
    record.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    let start_len = file.metadata()?.len();
    if let Err(error) = file.write_all(&record) {
        let _ = file.set_len(start_len);
        return Err(StorageError::Io(error));
    }
    Ok(())
}

fn json_string_value(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

fn deserialize_row_json<T: for<'de> Deserialize<'de>>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<T> {
    let payload: String = row.get(index)?;
    serde_json::from_str(&payload).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn collect_payload_rows<T: for<'de> Deserialize<'de>, P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    params: P,
) -> StorageResult<Vec<T>> {
    let rows = statement.query_map(params, |row| deserialize_row_json(row, 0))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StorageError::from)
}
