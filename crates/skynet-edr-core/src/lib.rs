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
