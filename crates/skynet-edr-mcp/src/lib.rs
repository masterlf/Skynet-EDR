//! Read-only MCP integration primitives for Skynet-EDR.
//!
//! This crate does not start an MCP server yet. It defines stable metadata and
//! tool names so future server implementation can stay read-only by default.

use skynet_edr_core::ProductInfo;

/// Metadata for the future local Skynet-EDR MCP server.
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

/// Initial read-only MCP tool names planned for Hermes visibility.
pub const READ_ONLY_TOOLS: &[&str] = &[
    "skynet_status",
    "skynet_list_incidents",
    "skynet_get_incident",
    "skynet_list_recent_events",
    "skynet_list_rules",
    "skynet_list_sensors",
    "skynet_get_config_drift",
];

/// Return a concise status string suitable for a future MCP status tool.
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
