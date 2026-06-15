//! Passive Linux fixture scanner for agent runtime configuration drift.
//!
//! The scanner is intentionally read-only and root-scoped. Tests exercise fake
//! fixtures so the daemon never needs privileged access or live Hermes state.

use std::{
    collections::{hash_map::DefaultHasher, BTreeMap},
    fs,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use serde_json::{json, Value};
use skynet_edr_core::{
    redact_attributes, Event, EventId, EventSource, LocalStore, RedactionMetadata, Severity,
    SourceKind,
};

const SENSOR_NAME: &str = "linux-passive-fixture";
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Local read-only HTTP API configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpApiConfig {
    /// Address the local API should bind to. Must be loopback.
    pub bind_addr: SocketAddr,
    /// Optional path to the local `SQLite` store.
    pub store_path: Option<PathBuf>,
    /// Reserved future flag. Must remain false for the read-only API.
    pub allow_mutations: bool,
}

impl Default for HttpApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787),
            store_path: None,
            allow_mutations: false,
        }
    }
}

impl HttpApiConfig {
    /// Validate that the local API cannot be exposed remotely or mutate state.
    ///
    /// # Errors
    ///
    /// Returns [`HttpApiConfigError`] when the bind address is not loopback or
    /// mutations are enabled before the API has an approval-gated design.
    pub fn validate(&self) -> Result<(), HttpApiConfigError> {
        let mut reasons = Vec::new();
        if !self.bind_addr.ip().is_loopback() {
            reasons.push("HTTP API bind address must be loopback");
        }
        if self.allow_mutations {
            reasons.push("HTTP API mutations are not implemented");
        }

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(HttpApiConfigError { reasons })
        }
    }
}

/// Local HTTP API configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpApiConfigError {
    reasons: Vec<&'static str>,
}

impl std::fmt::Display for HttpApiConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid HTTP API config: {}",
            self.reasons.join(", ")
        )
    }
}

impl std::error::Error for HttpApiConfigError {}

/// Minimal HTTP methods accepted by the read-only router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}

/// HTTP status values produced by the read-only router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStatus {
    /// Request succeeded.
    Ok,
    /// Route does not exist.
    NotFound,
    /// Method is not allowed for this API.
    MethodNotAllowed,
    /// Storage or serialization failed.
    InternalServerError,
}

impl HttpStatus {
    /// Return the numeric HTTP status code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::InternalServerError => 500,
        }
    }
}

/// Structured response returned by the read-only HTTP router.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpApiResponse {
    /// HTTP status.
    pub status: HttpStatus,
    /// Response content type.
    pub content_type: &'static str,
    /// JSON response body.
    pub body: Value,
}

/// Structured response returned by the local read-only HTML console router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleResponse {
    /// HTTP status.
    pub status: HttpStatus,
    /// Response content type.
    pub content_type: &'static str,
    /// HTML response body.
    pub body: String,
}

/// Read-only HTTP API handler error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpApiError {
    message: String,
}

impl std::fmt::Display for HttpApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for HttpApiError {}

/// Route one read-only HTTP API request without opening a socket.
///
/// The function is intentionally side-effect free except for reading the
/// already-redacted local store through the same read-only projection used by
/// the MCP visibility surface.
///
/// # Errors
///
/// Returns [`HttpApiError`] only for unexpected serialization failures. Storage
/// read errors are rendered as structured HTTP 500 responses.
pub fn handle_http_request(
    store: &LocalStore,
    method: HttpMethod,
    path: &str,
) -> Result<HttpApiResponse, HttpApiError> {
    let response = match path {
        "/api/status" => route_get(method, || skynet_edr_mcp::status(store)),
        "/api/incidents" => route_get(method, || skynet_edr_mcp::list_incidents(store)),
        "/api/rules" => route_static_get(method, skynet_edr_mcp::list_rules()),
        "/api/sensors" => route_static_get(method, skynet_edr_mcp::list_sensors()),
        "/api/config-drift" => route_get(method, || skynet_edr_mcp::get_config_drift(store)),
        _ => match path.strip_prefix("/api/incidents/") {
            Some(incident_id) if !incident_id.is_empty() => {
                route_get(method, || skynet_edr_mcp::get_incident(store, incident_id))
            }
            _ => json_response(
                HttpStatus::NotFound,
                json!({"error": "not_found", "read_only": true}),
            ),
        },
    };

    Ok(response)
}

/// Route one local read-only HTML console request without opening a socket.
///
/// The console is intentionally a thin localhost UI projection over the Phase 10
/// HTTP API router. It performs no sensor starts, response actions, config
/// writes, or direct raw-evidence reads; it renders only API output.
///
/// # Errors
///
/// Returns [`HttpApiError`] only when the underlying API router or JSON renderer
/// reports an unexpected serialization failure.
pub fn handle_console_request(
    store: &LocalStore,
    method: HttpMethod,
    path: &str,
) -> Result<ConsoleResponse, HttpApiError> {
    let response = match path {
        "/" | "/console" | "/console/" => console_get(method, || render_console_index(store)),
        "/console/rules" => console_api_page(store, method, "/api/rules", "Rules"),
        "/console/sensors" => console_api_page(store, method, "/api/sensors", "Sensors"),
        "/console/config-drift" => {
            console_api_page(store, method, "/api/config-drift", "Config drift")
        }
        _ => match path.strip_prefix("/console/incidents/") {
            Some(incident_id) if !incident_id.is_empty() => console_api_page(
                store,
                method,
                &format!("/api/incidents/{incident_id}"),
                "Redacted evidence",
            ),
            _ => console_response(
                HttpStatus::NotFound,
                "Not found",
                "not_found: this local console exposes read-only visibility pages only",
            ),
        },
    };

    Ok(response)
}

fn console_get(
    method: HttpMethod,
    render: impl FnOnce() -> Result<String, HttpApiError>,
) -> ConsoleResponse {
    if method == HttpMethod::Get {
        match render() {
            Ok(body) => ConsoleResponse {
                status: HttpStatus::Ok,
                content_type: "text/html; charset=utf-8",
                body,
            },
            Err(error) => console_response(
                HttpStatus::InternalServerError,
                "Console error",
                &format!("storage_read_failed: {error}"),
            ),
        }
    } else {
        console_response(
            HttpStatus::MethodNotAllowed,
            "Method not allowed",
            "method_not_allowed: the local console is read-only",
        )
    }
}

fn console_api_page(
    store: &LocalStore,
    method: HttpMethod,
    api_path: &str,
    title: &str,
) -> ConsoleResponse {
    console_get(method, || {
        let api_response = handle_http_request(store, HttpMethod::Get, api_path)?;
        if api_response.status == HttpStatus::Ok {
            let pretty =
                serde_json::to_string_pretty(&api_response.body).map_err(|error| HttpApiError {
                    message: format!("failed to render console JSON: {error}"),
                })?;
            Ok(html_page(
                title,
                &format!(
                    "<p class=\"badge\">Read-only API projection: {}</p><pre>{}</pre>",
                    escape_html(api_path),
                    escape_html(&pretty)
                ),
            ))
        } else {
            let body = api_response.body.to_string();
            Ok(html_page(
                title,
                &format!(
                    "<p class=\"badge\">Read-only API projection: {}</p><pre>{}</pre>",
                    escape_html(api_path),
                    escape_html(&body)
                ),
            ))
        }
    })
}

fn render_console_index(store: &LocalStore) -> Result<String, HttpApiError> {
    let status = handle_http_request(store, HttpMethod::Get, "/api/status")?;
    let incidents = handle_http_request(store, HttpMethod::Get, "/api/incidents")?;
    let timeline = render_incident_timeline(&incidents.body);
    let status_text = serde_json::to_string_pretty(&status.body).map_err(|error| HttpApiError {
        message: format!("failed to render console status: {error}"),
    })?;

    Ok(html_page(
        "Skynet-EDR Local Console",
        &format!(
            "<p class=\"badge\">Read-only localhost visibility</p>\
             <nav><a href=\"/console/rules\">Rules</a> · \
             <a href=\"/console/sensors\">Sensors</a> · \
             <a href=\"/console/config-drift\">Config drift</a></nav>\
             <section><h2>Status</h2><pre>{}</pre></section>\
             <section><h2>Incident timeline</h2>{timeline}</section>",
            escape_html(&status_text)
        ),
    ))
}

fn render_incident_timeline(incidents: &Value) -> String {
    let Some(items) = incidents.as_array() else {
        return "<p>No incident timeline available.</p>".to_owned();
    };
    if items.is_empty() {
        return "<p>No incidents recorded.</p>".to_owned();
    }

    let mut html = String::from("<ol>");
    for incident in items {
        let id = incident
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let title = incident
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("untitled incident");
        let severity = incident
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let updated = incident
            .get("updated_at_unix_ms")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        html.push_str(&format!(
            "<li><a href=\"/console/incidents/{}\">{}</a> \
             <span class=\"badge\">{}</span> \
             <span class=\"muted\">updated {}</span></li>",
            escape_html(id),
            escape_html(title),
            escape_html(severity),
            updated
        ));
    }
    html.push_str("</ol>");
    html
}

fn console_response(status: HttpStatus, title: &str, message: &str) -> ConsoleResponse {
    ConsoleResponse {
        status,
        content_type: "text/html; charset=utf-8",
        body: html_page(title, &format!("<pre>{}</pre>", escape_html(message))),
    }
}

fn html_page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>{}</title><style>body{{font-family:system-ui,sans-serif;max-width:960px;\
         margin:2rem auto;padding:0 1rem;background:#0b1020;color:#edf2f7}}\
         a{{color:#90cdf4}}pre{{white-space:pre-wrap;background:#111827;padding:1rem;\
         border:1px solid #2d3748;border-radius:0.5rem;overflow:auto}}\
         .badge{{color:#9ae6b4}}.muted{{color:#a0aec0}}</style></head>\
         <body><main><h1>{}</h1>{}</main></body></html>",
        escape_html(title),
        escape_html(title),
        body
    )
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn route_get(
    method: HttpMethod,
    read: impl FnOnce() -> Result<Value, skynet_edr_mcp::McpReadError>,
) -> HttpApiResponse {
    if method == HttpMethod::Get {
        read_response(read())
    } else {
        method_not_allowed_response()
    }
}

fn route_static_get(method: HttpMethod, value: Value) -> HttpApiResponse {
    if method == HttpMethod::Get {
        json_response(HttpStatus::Ok, value)
    } else {
        method_not_allowed_response()
    }
}

fn method_not_allowed_response() -> HttpApiResponse {
    json_response(
        HttpStatus::MethodNotAllowed,
        json!({"error": "method_not_allowed", "read_only": true}),
    )
}

fn read_response(result: Result<Value, skynet_edr_mcp::McpReadError>) -> HttpApiResponse {
    match result {
        Ok(value) => json_response(HttpStatus::Ok, value),
        Err(skynet_edr_mcp::McpReadError::IncidentNotFound(_)) => json_response(
            HttpStatus::NotFound,
            json!({"error": "not_found", "read_only": true}),
        ),
        Err(error) => json_response(
            HttpStatus::InternalServerError,
            json!({
                "error": "storage_read_failed",
                "message": error.to_string(),
                "read_only": true,
            }),
        ),
    }
}

fn json_response(status: HttpStatus, body: Value) -> HttpApiResponse {
    HttpApiResponse {
        status,
        content_type: "application/json",
        body,
    }
}

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
    } else if !is_controlled_sink_label(plan.controlled_sink_label.as_deref().unwrap_or_default()) {
        missing_controls.push("loopback or controlled sink label");
    }
    if plan.fake_honeytoken_labels.is_empty()
        || plan
            .fake_honeytoken_labels
            .iter()
            .any(|label| label.trim().is_empty())
    {
        missing_controls.push("fake honeytokens");
    } else if plan
        .fake_honeytoken_labels
        .iter()
        .any(|label| !is_obviously_fake_honeytoken_label(label))
    {
        missing_controls.push("fake honeytoken labels must be obviously fake");
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

fn is_controlled_sink_label(label: &str) -> bool {
    let lower = label.trim().to_ascii_lowercase();
    !lower.contains("://")
        && !lower.contains("webhook")
        && !lower.contains("discord.com")
        && !lower.contains("api.telegram.org")
        && (lower.contains("127.0.0.1")
            || lower.contains("localhost")
            || lower.contains("loopback")
            || lower.contains("sink"))
}

fn is_obviously_fake_honeytoken_label(label: &str) -> bool {
    let lower = label.trim().to_ascii_lowercase();
    lower.contains("fake") || lower.contains("honeytoken") || lower.contains("lab")
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
