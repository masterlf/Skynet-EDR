//! Read-only MCP integration primitives for Skynet-EDR.
//!
//! The crate exposes typed, side-effect-free handlers that map to the initial
//! local MCP tools. It deliberately avoids response or mutation operations: all
//! tool functions read already-redacted local state or static product metadata.

use serde::Serialize;
use serde_json::{json, Value};
use skynet_edr_core::{
    built_in_incident_rule_id, built_in_rule_metadata, safe_event_identifier,
    safe_incident_identifier, ArtifactKind, ArtifactProvenance, Event, Incident, LocalStore,
    ProductInfo, StorageError, TrustLevel,
};

const RISK_SCHEMA_VERSION: &str = "skynet.risk.v1";

/// Metadata for the local Skynet-EDR MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerInfo {
    /// Human-readable server name.
    pub name: &'static str,
    /// Whether all initial tools are read-only.
    pub read_only: bool,
    /// Tool names exposed by the initial MCP surface.
    pub tools: &'static [&'static str],
}

impl Default for McpServerInfo {
    fn default() -> Self {
        Self {
            name: "skynet-edr-mcp",
            read_only: true,
            tools: READ_ONLY_TOOLS,
        }
    }
}

/// Static metadata for one read-only MCP tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpToolSpec {
    /// Stable MCP tool name.
    pub name: &'static str,
    /// Operator-facing tool description.
    pub description: &'static str,
    /// Whether the tool is guaranteed not to mutate endpoint or store state.
    pub read_only: bool,
}

/// Errors returned by read-only MCP tool handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpReadError {
    /// Local storage could not be read or decoded.
    Storage(String),
    /// The requested incident identifier does not exist in local storage.
    IncidentNotFound(String),
}

impl std::fmt::Display for McpReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "MCP read storage error: {error}"),
            Self::IncidentNotFound(id) => write!(formatter, "incident not found: {id}"),
        }
    }
}

impl std::error::Error for McpReadError {}

impl From<StorageError> for McpReadError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error.to_string())
    }
}

/// Initial read-only MCP tool names exposed for local operator visibility.
pub const READ_ONLY_TOOLS: &[&str] = &[
    "skynet_status",
    "skynet_list_incidents",
    "skynet_get_incident",
    "skynet_list_rules",
    "skynet_list_sensors",
    "skynet_get_config_drift",
];

const TOOL_SPECS: &[McpToolSpec] = &[
    McpToolSpec {
        name: "skynet_status",
        description: "Return product, server, read-only mode, tool count, and local store counts.",
        read_only: true,
    },
    McpToolSpec {
        name: "skynet_list_incidents",
        description: "List stored incident summaries without expanding embedded event payloads.",
        read_only: true,
    },
    McpToolSpec {
        name: "skynet_get_incident",
        description: "Return one stored, already-redacted incident by identifier.",
        read_only: true,
    },
    McpToolSpec {
        name: "skynet_list_rules",
        description: "List built-in detection rule metadata relevant to the current MVP.",
        read_only: true,
    },
    McpToolSpec {
        name: "skynet_list_sensors",
        description: "List available read-only sensors and their platform scope.",
        read_only: true,
    },
    McpToolSpec {
        name: "skynet_get_config_drift",
        description:
            "List redacted config-drift findings derived from stored EDR-CONFIG-001 events.",
        read_only: true,
    },
];

/// Return the static read-only MCP tool specifications.
#[must_use]
pub const fn read_only_tool_specs() -> &'static [McpToolSpec] {
    TOOL_SPECS
}

/// Return a concise status string suitable for logging or CLI smoke tests.
#[must_use]
pub fn status_summary() -> String {
    let product = ProductInfo::default();
    let server = McpServerInfo::default();
    format!(
        "{} MCP server={} read_only={} tools={}",
        product.name,
        server.name,
        server.read_only,
        server.tools.len()
    )
}

/// Return read-only product/server status plus local storage counts.
///
/// # Errors
///
/// Returns [`McpReadError::Storage`] if local event or incident count queries fail.
pub fn status(store: &LocalStore) -> Result<Value, McpReadError> {
    let product = ProductInfo::default();
    let server = McpServerInfo::default();
    let incident_count = store.count_incidents()?;
    let event_count = store.count_events()?;

    Ok(json!({
        "product": product.name,
        "binary": product.binary_name,
        "run_mode": product.run_mode.as_str(),
        "server": server.name,
        "read_only": server.read_only,
        "tool_count": server.tools.len(),
        "incident_count": incident_count,
        "event_count": event_count,
    }))
}

/// List stored incidents as compact operator-facing summaries.
///
/// Embedded events are deliberately omitted to keep list output bounded and to
/// avoid turning an overview call into a bulk evidence export.
///
/// # Errors
///
/// Returns [`McpReadError::Storage`] if local incident listing fails.
pub fn list_incidents(store: &LocalStore) -> Result<Value, McpReadError> {
    let incidents = store.list_incidents()?;
    let summaries = incidents.iter().map(incident_summary).collect::<Vec<_>>();
    Ok(Value::Array(summaries))
}

/// Return one stored incident by identifier.
///
/// Values returned by [`LocalStore`] have already crossed the storage redaction
/// boundary. The handler does not re-read raw sensor inputs.
///
/// # Errors
///
/// Returns [`McpReadError::Storage`] if local storage fails, or
/// [`McpReadError::IncidentNotFound`] when the identifier is unknown.
pub fn get_incident(store: &LocalStore, incident_id: &str) -> Result<Value, McpReadError> {
    let incident = store
        .get_incident(incident_id)?
        .ok_or_else(|| McpReadError::IncidentNotFound(incident_id.to_owned()))?;
    serde_json::to_value(incident).map_err(|error| McpReadError::Storage(error.to_string()))
}

/// List bounded read-only risk projections for Hermes/Desktop clients.
///
/// Pagination is applied by local storage so list responses stay bounded before
/// risk projection.
///
/// # Errors
///
/// Returns [`McpReadError::Storage`] if local incident listing fails.
pub fn list_risks(store: &LocalStore, limit: usize, offset: usize) -> Result<Value, McpReadError> {
    let (total, incidents) = store.count_and_list_incidents_page(limit, offset)?;
    let items = incidents.iter().map(risk_item).collect::<Vec<_>>();
    let returned = items.len();
    Ok(json!({
        "schema_version": RISK_SCHEMA_VERSION,
        "read_only": true,
        "items": items,
        "page": {
            "limit": limit,
            "offset": offset,
            "returned": returned,
            "total": total,
            "has_more": offset.saturating_add(returned) < total,
        }
    }))
}

/// Return one read-only risk projection with bounded allowlisted evidence.
///
/// # Errors
///
/// Returns [`McpReadError::Storage`] if local storage fails, or
/// [`McpReadError::IncidentNotFound`] when the identifier is unknown.
pub fn get_risk(store: &LocalStore, risk_id: &str) -> Result<Value, McpReadError> {
    let incident = store
        .get_incident(risk_id)?
        .ok_or_else(|| McpReadError::IncidentNotFound(risk_id.to_owned()))?;
    let Value::Object(mut object) = risk_item(&incident) else {
        return Err(McpReadError::Storage(
            "risk projection shape error".to_owned(),
        ));
    };
    object.insert("schema_version".to_owned(), json!(RISK_SCHEMA_VERSION));
    object.insert("read_only".to_owned(), json!(true));
    object.insert(
        "evidence".to_owned(),
        Value::Array(risk_evidence(&incident)),
    );
    Ok(Value::Object(object))
}

/// List built-in detection rule metadata exposed through the read-only MCP surface.
#[must_use]
pub fn list_rules() -> Value {
    Value::Array(
        built_in_rule_metadata()
            .into_iter()
            .map(|rule| {
                json!({
                    "id": rule.id,
                    "name": rule.name,
                    "severity": rule.severity,
                    "source_kinds": rule.source_kinds,
                    "description": rule.description,
                    "read_only": true,
                    "compiled_active": true,
                })
            })
            .collect(),
    )
}

/// List read-only sensor metadata available in the current MVP.
#[must_use]
pub fn list_sensors() -> Value {
    json!([
        {
            "name": "linux-passive-fixture",
            "platform": "linux_fixture",
            "read_only": true,
            "scope": "root-scoped bounded reads of Hermes config and cron fixtures",
            "emits_rules": ["EDR-MCP-001", "EDR-CRON-001", "EDR-CONFIG-001"]
        }
    ])
}

/// List stored config-drift findings as compact, redacted operator records.
///
/// The output is intentionally projected to known-safe fields rather than
/// returning arbitrary event attributes wholesale.
///
/// # Errors
///
/// Returns [`McpReadError::Storage`] if local event listing fails.
pub fn get_config_drift(store: &LocalStore) -> Result<Value, McpReadError> {
    let events = store.list_events()?;
    let drift = events
        .iter()
        .filter(|event| event_rule_id(event).as_deref() == Some("EDR-CONFIG-001"))
        .map(config_drift_summary)
        .collect::<Vec<_>>();
    Ok(Value::Array(drift))
}

fn incident_summary(incident: &Incident) -> Value {
    json!({
        "id": safe_incident_identifier(incident.id.as_str()),
        "created_at_unix_ms": incident.created_at_unix_ms,
        "updated_at_unix_ms": incident.updated_at_unix_ms,
        "status": enum_label(incident.status),
        "severity": enum_label(incident.severity),
        "title": incident.title,
        "summary": incident.summary,
        "source_kind": enum_label(incident.source.kind),
        "sensor": incident.source.sensor,
        "integration": incident.source.integration,
        "event_count": incident.events.len(),
        "contains_sensitive_data": incident.redaction.contains_sensitive_data
            || incident.events.iter().any(|event| event.redaction.contains_sensitive_data),
    })
}

fn config_drift_summary(event: &Event) -> Value {
    json!({
        "event_id": safe_event_identifier(event.id.as_str()),
        "observed_at_unix_ms": event.observed_at_unix_ms,
        "severity": enum_label(event.severity),
        "rule_id": event_rule_id(event),
        "title": event.title,
        "path": event.attributes.get("path"),
        "baseline_path": event.attributes.get("baseline_path"),
        "drift_kind": event.attributes.get("drift_kind"),
        "current_fingerprint": event.attributes.get("current_fingerprint"),
        "baseline_fingerprint": event.attributes.get("baseline_fingerprint"),
        "sensor": event.source.sensor,
        "integration": event.source.integration,
        "contains_sensitive_data": event.redaction.contains_sensitive_data,
    })
}

fn event_rule_id(event: &Event) -> Option<String> {
    event
        .attributes
        .get("rule_id")
        .and_then(Value::as_str)
        .and_then(safe_identifier)
}

fn incident_rule_id(incident: &Incident) -> Option<String> {
    built_in_incident_rule_id(incident).map(str::to_owned)
}

fn risk_item(incident: &Incident) -> Value {
    let rule_id = incident_rule_id(incident);
    json!({
        "id": safe_incident_identifier(incident.id.as_str()),
        "severity": enum_label(incident.severity),
        "confidence": Value::Null,
        "status": enum_label(incident.status),
        "rule_id": rule_id,
        "title": risk_title(rule_id.as_deref()),
        "summary": risk_summary(incident.events.len()),
        "sensor": sensor_projection(&incident.source),
        "artifact": incident.events.iter().find_map(valid_event_artifact).unwrap_or_else(|| {
            let trust = incident.events.iter().find_map(event_trust_level);
            unknown_artifact(trust)
        }),
        "first_observed_at_unix_ms": incident.created_at_unix_ms,
        "last_observed_at_unix_ms": incident.updated_at_unix_ms,
        "event_count": incident.events.len(),
        "trace_ids": trace_ids(incident),
        "contains_sensitive_data": incident.redaction.contains_sensitive_data
            || incident.events.iter().any(|event| event.redaction.contains_sensitive_data),
    })
}

fn risk_title(rule_id: Option<&str>) -> &'static str {
    match rule_id {
        Some("EDR-MCP-001") => "MCP network activity after untrusted content",
        Some("EDR-CONFIG-001") => "Agent configuration drift detected",
        Some("EDR-CRON-001") => "Risky unattended automation detected",
        Some("EDR-PI-001") => "Privileged tool request after untrusted content",
        Some("EDR-MSG-001") => "Suspicious message delivery activity",
        Some("EDR-NET-001") => "Direct-IP egress activity",
        Some("EDR-SCOPE-001") => "Privilege or scope expansion activity",
        Some("EDR-PERSIST-001") => "Agent persistence change activity",
        Some("EDR-EXFIL-001") => "Sensitive access followed by outbound delivery",
        Some("EDR-MALWARE-001") => "Malware-like content supplied to AI runtime",
        Some(_) | None => "Security risk detected",
    }
}

fn risk_summary(event_count: usize) -> String {
    let noun = if event_count == 1 { "event" } else { "events" };
    format!(
        "Read-only projection of {event_count} redacted evidence {noun}. Review sensor and artifact provenance plus allowlisted indicators."
    )
}

fn sensor_projection(source: &skynet_edr_core::EventSource) -> Value {
    json!({
        "kind": enum_label(source.kind),
        "sensor": safe_identifier(&source.sensor).unwrap_or_else(|| "unknown".to_owned()),
        "integration": source.integration.as_deref().and_then(safe_identifier),
    })
}

fn event_artifact(event: &Event) -> Value {
    valid_event_artifact(event).unwrap_or_else(|| unknown_artifact(event_trust_level(event)))
}

fn valid_event_artifact(event: &Event) -> Option<Value> {
    let artifact = event.attributes.get("artifact")?;
    let artifact = serde_json::from_value::<ArtifactProvenance>(artifact.clone()).ok()?;
    if artifact
        .locator_hash
        .as_deref()
        .is_some_and(|hash| !valid_locator_hash(hash))
    {
        return None;
    }
    Some(json!({
        "kind": enum_label(artifact.kind),
        "provider": artifact.provider.as_deref().and_then(safe_identifier),
        "display_label": artifact_label(artifact.kind),
        "locator_hash": artifact.locator_hash,
        "trust_level": enum_label(artifact.trust_level),
    }))
}

fn artifact_label(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Email => "Email content",
        ArtifactKind::Url => "URL content",
        ArtifactKind::GitRepository => "Git repository",
        ArtifactKind::Code => "Code content",
        ArtifactKind::File => "File content",
        ArtifactKind::Message => "Message content",
        ArtifactKind::Mcp => "MCP content",
        ArtifactKind::Terminal => "Terminal output",
        ArtifactKind::Unknown => "Unclassified artifact",
    }
}

fn event_trust_level(event: &Event) -> Option<TrustLevel> {
    event
        .attributes
        .get("trust_level")
        .and_then(|value| serde_json::from_value::<TrustLevel>(value.clone()).ok())
}

fn unknown_artifact(trust_level: Option<TrustLevel>) -> Value {
    json!({
        "kind": "unknown",
        "provider": Value::Null,
        "display_label": "Unclassified artifact",
        "locator_hash": Value::Null,
        "trust_level": trust_level.map(enum_label),
    })
}

fn trace_ids(incident: &Incident) -> Value {
    let mut traces = Vec::new();
    for event in &incident.events {
        let Some(trace) = event
            .attributes
            .get("provenance")
            .and_then(|value| value.get("trace_id"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(trace) = safe_identifier(trace) else {
            continue;
        };
        if !traces.iter().any(|seen| seen == &trace) {
            traces.push(trace);
        }
        if traces.len() == 10 {
            break;
        }
    }
    json!(traces)
}

fn risk_evidence(incident: &Incident) -> Vec<Value> {
    incident
        .events
        .iter()
        .take(50)
        .map(|event| {
            json!({
                "event_id": safe_event_identifier(event.id.as_str()),
                "timestamp_unix_ms": event.observed_at_unix_ms,
                "severity": enum_label(event.severity),
                "event_type": event.attributes.get("event_type").and_then(Value::as_str).and_then(safe_identifier),
                "title": evidence_title(event.attributes.get("event_type").and_then(Value::as_str)),
                "sensor": sensor_projection(&event.source),
                "artifact": event_artifact(event),
                "trust_level": event_trust_level(event).map(enum_label),
                "rule_id": event_rule_id(event),
                "redaction": {
                    "contains_sensitive_data": event.redaction.contains_sensitive_data,
                    "redacted_count": event.redaction.redacted_fields.len(),
                },
                "indicators": event_indicators(event),
            })
        })
        .collect()
}

fn evidence_title(event_type: Option<&str>) -> &'static str {
    match event_type {
        Some("agent.tool.requested") => "Tool request evidence",
        Some("agent.tool.completed") => "Tool completion evidence",
        Some("agent.content.ingested") => "Content ingestion evidence",
        Some("agent.network.egress") => "Network egress evidence",
        Some("agent.file.accessed") => "File access evidence",
        Some("agent.mcp.tool.requested") => "MCP tool request evidence",
        Some("agent.config.changed") => "Configuration change evidence",
        Some("agent.automation.scheduled") => "Automation schedule evidence",
        Some("agent.approval.granted") => "Approval or scope change evidence",
        Some("agent.llm.call.requested") => "Model call request evidence",
        Some("agent.llm.call.completed") => "Model call completion evidence",
        Some(_) | None => "Security event evidence",
    }
}

fn event_indicators(event: &Event) -> Value {
    let bool_keys = [
        "network_indicator",
        "direct_ip",
        "delivery_indicator",
        "sensitive_access",
        "prompt_injection_indicator",
        "malware_indicator",
        "content_omitted",
        "result_omitted",
        "instruction_authority",
    ];
    let string_keys = ["command_class", "expected_disposition", "drift_kind"];
    let mut indicators = serde_json::Map::new();
    for key in bool_keys {
        if let Some(value) = event.attributes.get(key).and_then(Value::as_bool) {
            indicators.insert(key.to_owned(), json!(value));
        }
    }
    for key in string_keys {
        if let Some(value) = event
            .attributes
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| allowed_indicator_value(key, value))
        {
            indicators.insert(key.to_owned(), json!(value));
        }
    }
    Value::Object(indicators)
}

fn allowed_indicator_value(key: &str, value: &str) -> bool {
    match key {
        "command_class" => matches!(
            value,
            "network_egress" | "file_read" | "code_execution" | "other"
        ),
        "expected_disposition" => {
            matches!(value, "benign" | "suspicious" | "malicious" | "unknown")
        }
        "drift_kind" => matches!(value, "changed" | "created" | "deleted"),
        _ => false,
    }
}

fn safe_identifier(value: &str) -> Option<String> {
    const MAX_IDENTIFIER_CHARS: usize = 128;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_IDENTIFIER_CHARS {
        return None;
    }
    if trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-'))
    {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

fn valid_locator_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn enum_label<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}
