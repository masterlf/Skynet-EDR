# Rust Workspace

Skynet-EDR starts as a small Rust workspace. The core must remain platform-independent; OS-specific collectors will be isolated later.

## Crates

| Crate | Type | Purpose |
|---|---|---|
| `skynet-edr-core` | library | Shared product metadata, platform-independent event/rule/incident primitives, and local SQLite/JSONL storage. |
| `skynet-edr-cli` | binary | Operator CLI. Supports status/version/help plus local store initialization, incident ingestion, incident listing/showing, and JSONL export. |
| `skynet-edr-daemon` | binary + library | Future long-running runtime monitor. Current skeleton exposes safe status only, starts no privileged sensors, includes a root-scoped passive Linux fixture scanner, models manual-only Linux lab safety plans, and provides a localhost-only read-only HTTP API router. |
| `skynet-edr-mcp` | library | Future read-only MCP integration for Hermes visibility. Current skeleton defines read-only tool names and status metadata. |

## Development commands

Run before every PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Security constraints

- No `unsafe` code.
- No real external calls in tests.
- No privileged sensor startup in skeleton binaries.
- Linux privileged sensor validation uses the manual-only disposable VM workflow in [Linux lab and privileged sensor manual test plan](LINUX_LAB_TESTING.md).
- Local HTTP visibility remains loopback-only and read-only; see [Local read-only HTTP API](LOCAL_HTTP_API.md).
- Linux package/install assets must remain passive-by-default, least-privileged, and aligned with [Linux installation guide](INSTALL.md) and [Packaging and release plan](PACKAGING.md).
- MCP starts read-only; response actions are future opt-in work.
- Platform-specific code must not enter `skynet-edr-core` directly.
