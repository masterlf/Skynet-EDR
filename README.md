# Skynet-EDR

**AI-Agent Detection and Response research project for autonomous AI runtimes.**

Skynet-EDR is an early-stage security project focused on detecting and responding to attacks against AI agents, especially prompt-injection-driven abuse, malicious MCP/tool behavior, credential access, and data-exfiltration chains.

The goal is not to build a magical prompt-injection detector. The goal is to build an **agent-aware runtime security layer** that correlates:

- trusted vs untrusted instruction sources
- prompts and retrieved content provenance
- tool calls and tool arguments
- MCP server configuration and execution
- access to secrets and sensitive files
- scheduled/background tasks
- outbound network traffic
- messaging or email-based exfiltration paths

In short: classic EDR observes processes, files, and network activity. Skynet-EDR aims to observe those signals **plus the AI-agent context that explains why they happened**.

## Why this matters

AI agents increasingly connect language models to real capabilities: shells, filesystems, browsers, SaaS APIs, messaging platforms, MCP servers, cron jobs, and cloud integrations. Prompt injection becomes dangerous when hostile content can influence those capabilities.

A typical attack chain may look like this:

```text
untrusted email / web page / PDF / repo file
→ prompt injection
→ tool call
→ secret or config access
→ outbound network or messaging exfiltration
```

Traditional HIDS/EDR may see a process or network event. LLM guardrails may see suspicious text. Skynet-EDR is intended to correlate both worlds.

## Research scope

The project research scope includes detection and alerting for:

1. Prompt-injection attempts in untrusted content.
2. Suspicious tool calls outside the user-approved task scope.
3. MCP entries using shell interpreters plus network egress tools.
4. Reads of high-value secrets such as `.env`, OAuth stores, SSH keys, cloud credentials, and agent config.
5. Secret access followed by outbound network traffic or message delivery.
6. Dangerous scheduled/background automation.
7. Unexpected configuration drift in agent profiles, skills, plugins, MCP servers, and cron jobs.
8. Direct-IP or unusual outbound egress from agent-related processes.

## Design principles

- **Provenance first:** distinguish authenticated user instructions from untrusted content.
- **Correlation over keyword matching:** alert on suspicious chains, not isolated scary words.
- **Least privilege:** reduce agent tool and credential blast radius.
- **Operator-friendly evidence:** every alert should include source, evidence, attempted action, affected asset, and recommended containment.
- **Privacy-aware telemetry:** redact secrets, minimize captured content, and prefer hashes/snippets where possible.
- **Detection before blocking:** v0.4.1 is passive; guard-mode blocking is future v0.6+ work and requires an exercised control point.

## Status

Skynet-EDR v0.4.1 is an installable passive Linux-first prerelease. The shipped live producer is Hermes; OpenClaw and other runtime references are adapter contracts or external-producer paths, not shipped live integrations. It detects and records redacted local evidence but does not block agent actions. Read the [MVP public support contract](docs/MVP_SUPPORT_MATRIX.md) before relying on a package, rule, or integration claim.

Current crates:

- `skynet-edr-core`: shared product metadata, canonical schema, redaction, local storage, spool ingestion, and sequence-capable correlation rules.
- `skynet-edr-cli`: `skynet-edr` command-line entry point for doctor/diagnostics, storage, event ingestion/export, and incident handling.
- `skynet-edr-daemon`: passive daemon/runtime monitor primitives, including the Linux fixture scanner, localhost-only read-only HTTP API router, and conservative `run --config` service path.
- `skynet-edr-mcp`: read-only MCP integration surface for Hermes visibility: status, incidents, rules, sensors, and config-drift findings.

See [Rust workspace](docs/WORKSPACE.md) for layout and commands.

## Install

Download the current MVP release packages from:

```text
https://github.com/masterlf/Skynet-EDR/releases
```

Linux `amd64` release assets include `.deb`, `.rpm`, Arch `.pkg.tar.zst`, a custom `.tar.gz`, and `checksums.txt`. See [Linux installation guide](docs/INSTALL.md) for checksum verification and install commands.

## Development

Rust quality gate:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Documentation

Start with the [documentation hub](docs/README.md). The documentation is organized by operator journey:

- [Install](docs/INSTALL.md) — release packages, checksums, install, upgrade, rollback, uninstall.
- [Quickstart](docs/QUICKSTART.md) — shortest local path to a verified MVP baseline.
- [Concepts](docs/CONCEPTS.md) — product model, vocabulary, MVP scope, and non-goals.
- [Architecture](docs/ARCHITECTURE.md) — components, deployment modes, and MVP recommendation.
- [Canonical event schema](docs/EVENT_SCHEMA.md) — `skynet.event.v0` envelope and validation requirements.
- [Integrations](docs/INTEGRATIONS.md) — Hermes, OpenClaw, MCP, API, and CLI integration map.
- [Hermes plugin telemetry](docs/HERMES_PLUGIN_TELEMETRY.md) — passive Hermes lifecycle hook plugin and sanitized logs.
- [Detections](docs/DETECTIONS.md) — detection philosophy, rule families, severity, and alert evidence.
- [Operations](docs/OPERATIONS.md) — local store, API/MCP posture, evidence handling, and troubleshooting.
- [MVP public support contract](docs/MVP_SUPPORT_MATRIX.md) — evidence-backed platform tiers, live/producer-dependent/dark capability status, and exclusions.
- [Release process](docs/RELEASE_PROCESS.md) and [packaging plan](docs/PACKAGING.md) — release gates, artifacts, publishing, and rollback.
- [Current roadmap](docs/ROADMAP.md), [changelog](CHANGELOG.md), and [v0.4.1 release notes](docs/releases/v0.4.1.md) — shipped scope and remaining limitations.

## Naming

The project is called **Skynet-EDR** because the core idea is runtime detection and response for AI agents. It borrows some concepts from HIDS, but the scope is broader than host monitoring: it includes AI-agent context, prompt provenance, MCP/tool behavior, secrets, automation, and egress.

## License

Apache-2.0, unless otherwise noted.
