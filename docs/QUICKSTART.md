# Quickstart

This page is the shortest local path from package/source checkout to a verified Skynet-EDR MVP baseline.

For full package-manager commands, checksums, upgrades, and uninstall steps, use [Install](INSTALL.md). For operator posture after first boot, use [Operations](OPERATIONS.md).

## Prerequisites

- Linux `amd64` for the current packaged MVP.
- A release package from `https://github.com/masterlf/Skynet-EDR/releases`, or a Rust toolchain for source builds.
- A local shell with permission to install packages if testing `.deb`, `.rpm`, Arch, or service integration.
- Fake test data only. Do not use real secrets, live customer data, or real exfiltration targets in lab verification.

## Install or build

### Option A: release package

1. Download the package for your distribution from GitHub Releases.
2. Verify checksums as described in [Install](INSTALL.md#download-release-packages).
3. Install using the package-specific section in [Install](INSTALL.md):
   - [Debian/Ubuntu/Mint](INSTALL.md#install-from-deb-on-ubuntu-debian-or-mint)
   - [RHEL-compatible/Fedora](INSTALL.md#install-from-rpm-on-rhel-compatible-linux-or-fedora)
   - [Arch Linux](INSTALL.md#install-on-arch-linux)
   - [Custom tarball](INSTALL.md#custom-unpackaged-install)

### Option B: source checkout

```bash
cargo build --workspace --all-features
cargo test --workspace --all-features
```

The main CLI binary is `skynet-edr` from `skynet-edr-cli`; release packages install it on `PATH`.

## Initialize and inspect local state

Use the CLI storage commands documented in [Local storage and CLI](LOCAL_STORAGE.md):

```bash
skynet-edr status
skynet-edr store init
skynet-edr events list --limit 5
skynet-edr incidents list --limit 5
```

Expected first-run behavior is boring: no incidents unless you ingest fixtures or run a lab scenario. Boring is good. Boring pays fewer incident-response invoices.

## Ingest a redacted event fixture

The canonical event schema fixture is documented in [Canonical event schema](EVENT_SCHEMA.md#fixture). From a source checkout, run:

```bash
cargo test -p skynet-edr-core --test canonical_event_schema
```

For Hermes trace ingestion, use the workflow in [Hermes event ingestion](HERMES_EVENT_INGESTION.md#cli-usage). The ingestion path must preserve provenance, trust level, and redaction metadata.

## Run the read-only visibility surfaces

- CLI inspection: [Local storage and CLI](LOCAL_STORAGE.md#event-inspection-commands)
- Local HTTP visibility: [Local read-only HTTP API and console](LOCAL_HTTP_API.md#initial-routes)
- MCP visibility for Hermes: [Read-only MCP integration](MCP_READ_ONLY.md#tools)

These surfaces are read-only in the current MVP. They should expose redacted evidence and metadata, not become a remote-control plane.

## Verify documentation and quality gates

```bash
python3 packaging/scripts/check-docs.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

If packaging files changed, also run:

```bash
packaging/scripts/validate-packaging.sh
```

## Next reads

- Product model: [Concepts](CONCEPTS.md)
- System shape: [Architecture](ARCHITECTURE.md)
- Detection model: [Detections](DETECTIONS.md)
- Safe lab validation: [Linux lab testing](LINUX_LAB_TESTING.md)
