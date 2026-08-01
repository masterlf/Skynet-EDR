# Changelog

## Unreleased

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
