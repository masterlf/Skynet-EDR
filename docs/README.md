# Skynet-EDR documentation

This is the v0.2 documentation map for Skynet-EDR: an AI-agent Detection and Response system focused on prompt-injection-aware runtime telemetry, tool/MCP abuse, secret access, automation, and egress correlation.

The docs are intentionally split by operator journey. Start with the shortest path that matches what you need; the deeper design docs remain linked instead of copied around like documentation confetti. Very elegant, very un-French bureaucracy.

## Start here

| Need | Read |
|---|---|
| Install a release package | [Install](INSTALL.md) |
| Run the MVP quickly | [Quickstart](QUICKSTART.md) |
| Understand what Skynet-EDR is and is not | [Concepts](CONCEPTS.md) |
| Understand the system shape | [Architecture](ARCHITECTURE.md) |
| Produce or ingest events | [Canonical event schema](EVENT_SCHEMA.md) |
| Connect agent/runtime integrations | [Integrations](INTEGRATIONS.md) |
| Understand detections and alert evidence | [Detections](DETECTIONS.md) |
| Operate a local install | [Operations](OPERATIONS.md) |
| Build and publish packages | [Release process](RELEASE_PROCESS.md) |

## Documentation structure

### User and operator docs

- [Install](INSTALL.md) covers supported Linux scope, package install commands, checksum verification, upgrades, rollback, uninstall, and troubleshooting.
- [Quickstart](QUICKSTART.md) gives a minimal local verification path after install or source build.
- [Operations](OPERATIONS.md) covers local storage, API exposure, daemon/service posture, evidence handling, and routine checks.

### Product and security model

- [Concepts](CONCEPTS.md) defines the product model, current scope, non-goals, and v0.2 vocabulary.
- [Project goals](GOALS.md) records mission, non-goals, milestones, and success criteria.
- [Threat model](THREAT_MODEL.md) defines assets, trust boundaries, initial threats, assumptions, and response philosophy.
- [Quality and security engineering](QUALITY_AND_SECURITY_ENGINEERING.md) defines the engineering baseline for secure development.
- [Review policy](REVIEW_POLICY.md) records the current solo-maintainer PR posture and target review model.

### Architecture and implementation

- [Architecture](ARCHITECTURE.md) describes components, deployment modes, and the MVP recommendation.
- [Rust workspace](WORKSPACE.md) documents crates and development commands.
- [Implementation plan](IMPLEMENTATION_PLAN.md) is the long-form roadmap and historical design record. Treat it as background, not the front door.
- [Local storage and CLI](LOCAL_STORAGE.md) documents SQLite storage and event/incident commands.
- [Local read-only HTTP API and console](LOCAL_HTTP_API.md) documents localhost visibility routes.

### Event schema, integrations, and detections

- [Canonical event schema](EVENT_SCHEMA.md) is the source of truth for `skynet.event.v0` event envelopes.
- [Integrations](INTEGRATIONS.md) is the integration index for Hermes, OpenClaw, MCP visibility, and local HTTP surfaces.
- [Hermes plugin telemetry](HERMES_PLUGIN_TELEMETRY.md) documents the v0.3 passive Hermes lifecycle hook plugin, JSONL spool, and sanitized operational logs.
- [Hermes event ingestion](HERMES_EVENT_INGESTION.md) documents supported Hermes trace shapes and normalization.
- [OpenClaw integration](OPENCLAW_INTEGRATION.md) documents MVP adapter requirements.
- [Read-only MCP integration](MCP_READ_ONLY.md) documents safe MCP visibility tools.
- [Detections](DETECTIONS.md) is the detection and alerting index.
- [Initial detection rules](DETECTION_RULES.md) documents rule candidates and alert shape.

### Testing, packaging, and release

- [Linux lab testing](LINUX_LAB_TESTING.md) documents safe manual validation with fake honeytokens and controlled sinks.
- [Packaging plan](PACKAGING.md) documents package contents, build commands, validation gates, maintainer-script rules, signing, and rollback policy.
- [Release process](RELEASE_PROCESS.md) turns packaging and validation into a release checklist.
- [Security tooling options](SECURITY_TOOLING_OPTIONS.md) records the current and candidate security-tooling baseline.

## Versioning note

Current event schema: `skynet.event.v0`.

Current documentation structure target: v0.2. The docs may describe planned capabilities, but each page should clearly separate implemented behavior from roadmap intent. If a page blurs that line, fix the page before building on it.

## Documentation checks

Run the local documentation gate with:

```bash
python3 packaging/scripts/check-docs.py
```

The check validates required v0.2 documentation entry points and local Markdown links. It intentionally does not crawl external links; release notes and security documentation should not depend on network luck. Mai pen rai, but deterministic.
