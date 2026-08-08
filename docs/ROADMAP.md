# Current Roadmap

This page is the authoritative milestone map. [Implementation plan](IMPLEMENTATION_PLAN.md) remains the long-form architecture and historical design record.

## Shipped baseline: v0.5.0

v0.5.0 is a passive Linux-first prerelease. Within the narrow evidence-backed scope in the [MVP public support contract](MVP_SUPPORT_MATRIX.md), it provides:

- canonical event schema and local redacted storage;
- Hermes trace and canonical JSONL spool ingestion;
- passive Hermes lifecycle-hook telemetry;
- specific secret-egress and safe malware-test correlation;
- read-only CLI, local HTTP, console, and MCP handler-library visibility;
- Linux `x86_64`/`amd64` release artifacts.

It does **not** provide inline pause, approval, blocking, or active containment.

## Current milestone: v0.5.0 Passive Public MVP

The v0.5.0 milestone carries forward the v0.4.1 reliability baseline and adds the bounded S3 Hermes enrollment path:

- deterministic sequence-capable correlation and the reviewed high-signal AI-agent rule pack;
- `skynet-edr doctor` and private, redaction-safe diagnostics collection;
- authenticated bounded continuous ingestion with privacy-safe EXFIL/MALWARE detection;
- completed-outcome telemetry for exact successful Hermes cron create/update operations;
- explicit fail-dark treatment for unsupported config, persistence, and approval-scope outcomes;
- clean-container Ubuntu `.deb` and tarball install/remove/purge evidence without service start;
- public download, checksum, extraction, and version verification;
- green Rust, Python, documentation, SAST, secret-scanning, dependency, and packaging gates;
- release notes that separate implemented behavior from limitations.
- exact Ubuntu 24.04 amd64/systemd, Hermes 0.19.0, default-profile enrollment compatibility;
- package-owned payload validation, exact process/producer attestation, and a correlated persisted harmless canary;
- private root-owned enrollment state with non-destructive retained quarantine and manual recovery;
- explicit account-wide user-manager restart authorization and blast-radius documentation.

The release remains passive and is published as a prerelease. It has no production support commitment; signing, provenance, SBOM policy, broader platform validation, and repeatable runtime upgrade/rollback proof remain open. Release promotion is conditioned on the exact release SHA passing the disposable clean-host S3 gate.

## Next milestone: S4 hardening

S4 will address descriptor-relative hardening against hostile concurrent root replacement and crash-idempotent quarantine cleanup policy. It does not include outbound webhook, email, or SIEM delivery, inline pause, approval, blocking, or containment.

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
