# Changelog

## Unreleased

## 0.6.0-alpha.1 - 2026-08-09

- Added one compact server-redacted `skynet.alert.notice.v1` stdout line for each incident newly committed by continuous ingestion; duplicate replay emits no second notice.
- Made post-commit notice failure preserve the incident and producer ACK while incrementing `alert_delivery_errors_total` and degrading ingestion health.
- Extended release-version consistency checks to canonical SemVer prereleases and verified package metadata handling for the prerelease.

## 0.5.1 - 2026-08-09

- Added listing-only DEB inspection policy and banned privileged package extraction on live or persistent hosts.
- Added a read-only, fail-closed verifier for exact filesystem tuples, service-user access, real systemd process identity, installed executable identity, and status/risks/rules API contracts.
- Promoted the disposable Ubuntu DEB/systemd vertical smoke into PR and release workflows, including writable-state proof and an injected root-owned-state regression.
- Added a package-manager-only DEB deployment and rollback runbook; RPM, Arch, non-systemd, automatic repair, and database restore remain outside this hotfix's qualified boundary.

## 0.5.0 - 2026-08-06

- Added fail-closed, transactional Hermes 0.19.0 enrollment for the exact Ubuntu 24.04 amd64/systemd/default-profile compatibility cell, including package-owned payload validation and exact producer attestation.
- Added private root-owned enrollment state, non-destructive quarantine, durable manual-recovery evidence, and fail-closed drift handling without automatic purge.
- Bound successful enrollment to fresh process identities, protocol-v3 producer health, independent runtime nonces, and an exact persisted harmless canary receipt.
- Documented the account-wide systemd user-manager restart blast radius, the S3 trust boundary, and the mandatory exact-release-SHA disposable clean-host promotion gate.

## 0.4.1 - 2026-07-30

- Hardened authenticated continuous ingestion with exact per-event projection, pseudonymized correlation identities, transactional bounded EXFIL/MALWARE correlation, trigger-anchored linear two-step sequence evaluation, and collision-safe acknowledgements.
- Added bounded Hermes parameter/result classification metadata without persisting raw tool input or output.
- Added an outcome-gated Hermes cron scheduling producer; config, persistence, and approval-scope rules remain explicitly dark until Hermes exposes authoritative post-mutation outcomes.
- Added release-tag/package-version consistency validation and exercised clean-container Ubuntu DEB and tarball install/remove/purge lifecycle checks without service start. Runtime upgrade, restart-persistence, rollback, service, and API-health behavior remain unproven.

## 0.4.0 - 2026-07-24

- Added fail-closed operator doctor and private redaction-safe diagnostics bundles.
- Added deterministic canonical sequence correlation and eight AI-agent rule families.
- Aligned Hermes MCP/direct-IPv4 event emission with attack-gated sequence predicates.
- Restricted the passive-only response boundary to alert emission without approval, pause, or blocking.
- Persisted built-in sequence incidents from Hermes/OpenClaw spool ingestion before checkpoint advancement.
- Added clean-container package smoke checks and strict public release verification.
- Hardened security workflows, reviewed release notes, and immutable single-workflow publication.

## 0.3.0

- Added the passive Linux-first daemon, local API visibility, a read-only MCP handler/library baseline only (no transport, server, registration, or operator-runnable Hermes integration), packaging, and AI-agent adapter baseline.

## 0.2.0

- Added packaged Hermes Agent telemetry with bounded local logs and canonical JSONL spool output.
- Added bounded live spool ingestion with durable checkpointing and malformed-line accounting.
