# Read-only MCP integration

Skynet-EDR exposes an initial read-only MCP surface for local operator visibility. The current Rust crate does not start a networked MCP server yet; it defines the stable tool metadata and side-effect-free handlers that a future server adapter can call.

## Security boundary

All Phase 8 tools are read-only:

- no response actions
- no incident mutation
- no rule enable/disable operation
- no file write, delete, quarantine, network block, or automation pause
- no raw fixture/config readback through MCP

Incident and event data returned by these handlers comes from `LocalStore`, which applies the core redaction boundary before persistence. The config-drift tool also projects only known-safe drift fields instead of returning arbitrary event attributes wholesale.

## Tools

| Tool | Purpose | Data source |
| --- | --- | --- |
| `skynet_status` | Product/server metadata, read-only mode, tool count, stored incident count, stored event count. | `ProductInfo`, `McpServerInfo`, `LocalStore` counts |
| `skynet_list_incidents` | Compact incident summaries for triage. Embedded event payloads are intentionally omitted. | `LocalStore::list_incidents` |
| `skynet_get_incident` | Full stored incident by ID, already redacted at storage boundary. | `LocalStore::get_incident` |
| `skynet_list_rules` | Built-in MVP detection rule metadata. | Static metadata |
| `skynet_list_sensors` | Current sensor metadata and scope. | Static metadata |
| `skynet_get_config_drift` | Compact config-drift findings from stored `EDR-CONFIG-001` events. | `LocalStore::list_events` projection |

## Current built-in rules exposed as metadata

- `EDR-MCP-001`: MCP shell plus egress.
- `EDR-CRON-001`: risky unattended Hermes automation.
- `EDR-CONFIG-001`: agent config drift.

## Current sensor metadata

- `linux-passive-fixture`: Linux fixture scanner using bounded root-scoped reads of Hermes config and cron fixtures. It is intentionally passive and emits the current MVP rule findings.

## Verification

Run the MCP crate tests:

```bash
cargo test -p skynet-edr-mcp --test mcp_surface
```

Run the full workspace gate before merging:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```
