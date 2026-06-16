//! Read-only MCP integration primitives for Skynet-EDR.
//!
//! The crate exposes typed, side-effect-free handlers that map to the initial
//! local MCP tools. It deliberately avoids response or mutation operations: all
//! tool functions read already-redacted local state or static product metadata.

use serde::Serialize;
use serde_json::{json, Value};
use skynet_edr_core::{Event, Incident, LocalStore, ProductInfo, StorageError};

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
/// Returns [`McpReadError::Storage`] if local event or incident listing fails.
pub fn status(store: &LocalStore) -> Result<Value, McpReadError> {
    let product = ProductInfo::default();
    let server = McpServerInfo::default();
    let incidents = store.list_incidents()?;
    let events = store.list_events()?;

    Ok(json!({
        "product": product.name,
        "binary": product.binary_name,
        "run_mode": product.run_mode.as_str(),
        "server": server.name,
        "read_only": server.read_only,
        "tool_count": server.tools.len(),
        "incident_count": incidents.len(),
        "event_count": events.len(),
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

/// List built-in detection rule metadata exposed through the read-only MCP surface.
#[must_use]
pub fn list_rules() -> Value {
    json!([
        {
            "id": "EDR-MCP-001",
            "name": "MCP shell plus egress",
            "severity": "high_or_critical",
            "source_kinds": ["configuration"],
            "read_only": true,
            "description": "Detects MCP entries where shell execution is paired with network egress capability."
        },
        {
            "id": "EDR-CRON-001",
            "name": "Risky unattended Hermes automation",
            "severity": "medium_or_high",
            "source_kinds": ["scheduled_task"],
            "read_only": true,
            "description": "Detects broad unattended jobs that combine sensitive access with external delivery indicators."
        },
        {
            "id": "EDR-CONFIG-001",
            "name": "Agent config drift",
            "severity": "medium_or_high",
            "source_kinds": ["configuration"],
            "read_only": true,
            "description": "Detects changes between current and baseline agent runtime configuration."
        },
        {
            "id": "EDR-EXFIL-001",
            "name": "Secret access followed by egress",
            "severity": "critical",
            "source_kinds": ["file", "process", "network", "messaging"],
            "read_only": true,
            "description": "Correlates a sensitive file read with outbound network or delivery telemetry in the same agent session."
        }
    ])
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
        "id": incident.id.as_str(),
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
        "event_id": event.id.as_str(),
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
        .map(str::to_owned)
}

fn enum_label<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}
