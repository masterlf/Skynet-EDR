//! MCP surface tests for the read-only integration skeleton.

use skynet_edr_mcp::{status_summary, McpServerInfo, READ_ONLY_TOOLS};

#[test]
fn mcp_surface_is_read_only_by_default() {
    let info = McpServerInfo::default();

    assert_eq!(info.name, "skynet-edr-mcp");
    assert!(info.read_only);
    assert_eq!(info.tools, READ_ONLY_TOOLS);
}

#[test]
fn planned_tool_names_are_status_and_investigation_only() {
    assert!(READ_ONLY_TOOLS.contains(&"skynet_status"));
    assert!(READ_ONLY_TOOLS.contains(&"skynet_list_incidents"));
    assert!(READ_ONLY_TOOLS.contains(&"skynet_get_config_drift"));
    assert!(READ_ONLY_TOOLS.iter().all(|tool| !tool.contains("disable")));
    assert!(READ_ONLY_TOOLS
        .iter()
        .all(|tool| !tool.contains("quarantine")));
}

#[test]
fn status_summary_is_operator_readable() {
    let summary = status_summary();

    assert!(summary.contains("Skynet-EDR"));
    assert!(summary.contains("read_only=true"));
    assert!(summary.contains("tools="));
}
