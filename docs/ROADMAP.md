# Current Roadmap

This page is the authoritative milestone map. [Implementation plan](IMPLEMENTATION_PLAN.md) remains the long-form architecture and historical design record.

## Shipped baseline: v0.3.0

v0.3.0 is a passive Linux-first prerelease. It provides:

- canonical event schema and local redacted storage;
- Hermes trace and canonical JSONL spool ingestion;
- passive Hermes lifecycle-hook telemetry;
- specific secret-egress and safe malware-test correlation;
- read-only CLI, local HTTP, console, and MCP visibility;
- Linux packages and release artifacts.

It does **not** provide inline pause, approval, blocking, or active containment.

## Current milestone: v0.4.1 reliable passive prerelease

The v0.4.1 milestone completes the P1 reliability and continuous-coverage work on top of v0.4.0:

- deterministic sequence-capable correlation and the reviewed high-signal AI-agent rule pack;
- `skynet-edr doctor` and private, redaction-safe diagnostics collection;
- authenticated bounded continuous ingestion with privacy-safe EXFIL/MALWARE detection;
- completed-outcome telemetry for exact successful Hermes cron create/update operations;
- explicit fail-dark treatment for unsupported config, persistence, and approval-scope outcomes;
- clean-host package install/remove, upgrade, restart-persistence, and rollback evidence;
- public download, checksum, extraction, and version verification;
- green Rust, Python, documentation, SAST, secret-scanning, dependency, and packaging gates;
- release notes that separate implemented behavior from limitations.

The release remains passive and is published as a prerelease until production gates such as signing, provenance, SBOM policy, and broader platform validation are complete.

## Next milestone: guard mode design

Guard mode requires a real pre-execution control point in each supported agent runtime. Its design must define:

- authenticated operator policy and approval contracts;
- deterministic timeout and fail-closed behavior;
- narrow pause/deny scopes and rollback;
- audit evidence that cannot expose secrets;
- degradation behavior when Skynet-EDR is unavailable;
- explicit compatibility contracts for Hermes and other runtimes.

No user-facing surface may claim guard mode before those controls are implemented and exercised end to end.

## Later milestones

- opt-in pre-approved containment after guard mode is proven;
- stronger Linux sensors, with privileged sensors isolated behind explicit configuration;
- Windows and macOS sensor backends while keeping the core schema and rule model platform-independent;
- fleet management and richer investigation workflows only after local correctness is stable.
