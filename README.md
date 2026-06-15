# Skynet-EDR

**AI-Agent Detection and Response for autonomous AI runtimes.**

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

## Initial scope

The first research/MVP scope is detection and alerting for:

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
- **Detection before blocking:** start passive; block only high-confidence exfiltration patterns.

## Status

This repository now has an initial Rust workspace skeleton for the platform-independent core, CLI, daemon placeholder, and read-only MCP integration primitives.

Current crates:

- `skynet-edr-core`: shared product metadata and core runtime primitives.
- `skynet-edr-cli`: `skynet-edr` command-line entry point with an initial `status` command.
- `skynet-edr-daemon`: daemon/runtime monitor primitives, including the passive Linux fixture scanner and localhost-only read-only HTTP API router.
- `skynet-edr-mcp`: read-only MCP integration surface for Hermes visibility: status, incidents, rules, sensors, and config-drift findings.

See [Rust workspace](docs/WORKSPACE.md) for layout and commands.

The next implementation steps are to expand the core event schema, redaction engine, detection rules, and storage model.

## Development

Rust quality gate:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Documentation

- [Project goals](docs/GOALS.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Concept architecture](docs/ARCHITECTURE.md)
- [Initial detection ideas](docs/DETECTION_RULES.md)
- [Read-only MCP integration](docs/MCP_READ_ONLY.md)
- [Local read-only HTTP API](docs/LOCAL_HTTP_API.md)
- [Linux lab and privileged sensor manual test plan](docs/LINUX_LAB_TESTING.md)
- [Linux installation guide](docs/INSTALL.md)
- [Packaging and release plan](docs/PACKAGING.md)

## Naming

The project is called **Skynet-EDR** because the core idea is runtime detection and response for AI agents. It borrows some concepts from HIDS, but the scope is broader than host monitoring: it includes AI-agent context, prompt provenance, MCP/tool behavior, secrets, automation, and egress.

## License

Apache-2.0, unless otherwise noted.
