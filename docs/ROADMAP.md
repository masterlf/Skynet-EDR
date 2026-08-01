# Current Roadmap

This page is the authoritative milestone map. [Implementation plan](IMPLEMENTATION_PLAN.md) remains the long-form architecture and historical design record.

## Shipped baseline: v0.4.1

v0.4.1 is a passive Linux-first prerelease. Within the narrow evidence-backed scope in the [MVP public support contract](MVP_SUPPORT_MATRIX.md), it provides:

- canonical event schema and local redacted storage;
- Hermes trace and canonical JSONL spool ingestion;
- passive Hermes lifecycle-hook telemetry;
- specific secret-egress and safe malware-test correlation;
- read-only CLI, local HTTP, console, and MCP visibility;
- Linux `x86_64`/`amd64` release artifacts.

It does **not** provide inline pause, approval, blocking, or active containment.

## Current milestone: v0.4.1 reliable passive prerelease

The v0.4.1 milestone completes the P1 reliability and continuous-coverage work on top of v0.4.0:

- deterministic sequence-capable correlation and the reviewed high-signal AI-agent rule pack;
- `skynet-edr doctor` and private, redaction-safe diagnostics collection;
- authenticated bounded continuous ingestion with privacy-safe EXFIL/MALWARE detection;
- completed-outcome telemetry for exact successful Hermes cron create/update operations;
- explicit fail-dark treatment for unsupported config, persistence, and approval-scope outcomes;
- clean-container Ubuntu `.deb` and tarball install/remove/purge evidence without service start;
- public download, checksum, extraction, and version verification;
- green Rust, Python, documentation, SAST, secret-scanning, dependency, and packaging gates;
- release notes that separate implemented behavior from limitations.

The release remains passive and is published as a prerelease. It has no production support commitment; signing, provenance, SBOM policy, broader platform validation, repeatable runtime upgrade/rollback proof, and a bounded Hermes compatibility contract remain open.

## Next milestone: v0.5.0 Passive Public MVP

v0.5.0 remains passive. It will turn the v0.4.1 prerelease baseline into a
clearer public evaluation milestone without adding a control plane. Planned
work includes durable local alert/evidence presentation and release-facing
support documentation; it does not include outbound webhook, email, or SIEM
delivery, inline pause, approval, blocking, or containment.

## v0.6+ candidate: guard mode design

Guard mode requires a real pre-execution control point in each supported agent runtime. Its design must define:

- authenticated operator policy and approval contracts;
- deterministic timeout and fail-closed behavior;
- narrow pause/deny scopes and rollback;
- audit evidence that cannot expose secrets;
- degradation behavior when Skynet-EDR is unavailable;
- explicit compatibility contracts for Hermes and other runtimes.

No user-facing surface may claim guard mode before those controls are implemented and exercised end to end. Guard mode is not part of v0.5.0.

## Later milestones

- opt-in pre-approved containment after guard mode is proven;
- stronger Linux sensors, with privileged sensors isolated behind explicit configuration;
- Windows and macOS sensor backends while keeping the core schema and rule model platform-independent;
- fleet management and richer investigation workflows only after local correctness is stable.
