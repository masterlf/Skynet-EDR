# MVP public support contract

## Audience and purpose

This page is the public contract for the installable Skynet-EDR `v0.4.1` prerelease at source baseline `f128bfb505bc77bff1a4322bba185ba79f7d642b`. It separates implemented behavior from package availability, adapter requirements, and roadmap intent. It is for evaluation and lab use, not a production support commitment.

## Product boundary

Skynet-EDR is a passive, local-first, Linux `x86_64`/`amd64` prerelease. It accepts and stores redacted local security evidence, applies bounded correlation, and exposes local read-only visibility. It detects and records; it does not block, pause, approve, quarantine, contain, or otherwise change an agent action.

The product does not replace endpoint EDR, SIEM, IAM, DLP, runtime guardrails, or an incident-response service. Operators remain responsible for validating incidents, controlling runtime access, preserving evidence, and taking any response action.

## Linux package support

| Tier | Scope | Evidence at this baseline | Contract |
|---|---|---|---|
| Tier 1 | Ubuntu 24.04 `x86_64`/`amd64`; `.deb` and custom tarball package paths | Clean-container install/remove/purge checks without service start | Evaluation support for the proven package lifecycle only. Daemon operation, producer enrollment, upgrade, rollback, and response outcomes still require operator validation in the target environment. |
| Tier 2 | Published `x86_64`/`amd64` artifacts outside Tier 1: Debian, Linux Mint, RHEL-compatible Linux, Fedora, Arch, and custom tarball targets | Artifact publication exists; no corresponding native runtime proof at this baseline | Lab/advanced-user availability only. It is not a verified runtime-support promise. |

Unsupported or unproven: `arm64`/`aarch64`, musl/Alpine, non-systemd hosts, Windows, macOS, and any distribution or architecture not listed above. RPM and Arch artifacts do not establish RHEL/Fedora/Arch runtime compatibility. The tarball installer does not provision the `skynet-edr-ingest` group or sysusers/tmpfiles state needed for authenticated continuous ingress; do not infer ingress readiness from a successful tarball installation.

Published checksums provide integrity checking, but this prerelease has no package signatures, signed checksum manifest, SBOM, provenance attestation, or bounded Hermes compatibility range.

## Runtime and integration coverage

| Surface or capability | Status | Contract |
|---|---|---|
| Canonical schema, redaction, local SQLite storage, CLI, loopback read-only HTTP visibility | Live | Implemented local surfaces subject to their documented validation and availability limits. |
| Hermes lifecycle plugin and authenticated AF_UNIX ingestion | Live producer | The only shipped live producer path. It is passive and depends on explicit local enrollment, producer-supplied facts, successful ingestion, and bounded queues/checkpoints. |
| Autonomous Hermes enrollment | Unproven / blocked | A fail-closed transaction, package-owned privileged adapter, and deterministic boundary fixtures exist for Ubuntu 24.04 amd64/systemd plus Hermes 0.19.0, but no disposable clean-host real-Hermes/systemd gate has passed. No host may yet be claimed autonomously `ENROLLED`; all other Hermes versions/platform cells are unsupported. |
| `EDR-MCP-001`, `EDR-PI-001`, `EDR-MSG-001`, `EDR-NET-001`, `EDR-CRON-001` | Live, narrow | Exact Hermes producer shapes only; cron coverage is limited to authoritative successful built-in `cronjob` create/update outcomes. |
| `EDR-EXFIL-001`, `EDR-MALWARE-001` | Live, narrow | Exact reviewed event shapes, joins, ordering, and bounded correlation only. Absence of an incident is not proof that an action was safe. |
| Canonical JSONL from another producer and normalized Hermes trace import | Producer-dependent | The engine can evaluate documented input, but coverage exists only when an external producer supplies valid redacted events. |
| OpenClaw, Codex, Claude Code, and similar runtimes | Producer-dependent or unsupported | No shipped live producer is provided for these runtimes. OpenClaw documentation is an adapter contract and fixture model, not a live integration. |
| Read-only MCP handlers | Implemented handler surface, not a network server | The crate provides metadata and side-effect-free handlers; it does not start a networked MCP server. |
| Alert destinations such as webhook or email | Unsupported | Schema/rendering metadata is not an alert-delivery implementation. |
| `EDR-CONFIG-001`, `EDR-SCOPE-001`, `EDR-PERSIST-001` through the shipped Hermes producer | Dark | Required authoritative post-mutation evidence is not available, so the producer intentionally does not emit the triggering events. |
| `EDR-SECRET-001` standalone secret-access detection | Unsupported | It is a roadmap candidate; no standalone shipped correlator exists. |

"Live" means the exact shipped path can produce and evaluate the stated narrow shape. "Producer-dependent" means evaluation requires an external conforming producer. "Dark" means a rule may exist but the named shipped producer intentionally cannot prove its trigger. "Unsupported" means no shipped implementation is available for that capability.

## Data, trust, and availability limits

Redaction is deterministic and pattern-bounded. It reduces exposure before persistence and read-only output, but it is not a universal guarantee that every secret or sensitive datum can never appear. Producers, event timestamps, joins, and runtime roles are not independently attested by AF_UNIX authorization. Bounded queues, fallback storage, parsing limits, classifier truncation, failed ingestion, and unavailable local services can reduce visibility; a negative result is not a safety verdict.

Agent hook execution remains fail-open so Skynet-EDR does not disrupt the observed runtime. Schema validation, redaction metadata, and security/configuration boundaries fail closed when required information is malformed or ambiguous.

## Post-MVP exclusions

The following require a separate design, threat model, implementation, and
end-to-end validation before they can be claimed: guard or enforcement mode;
automated containment; privileged/kernel/eBPF sensors; fleet or remote
administration; external/outbound webhook, email, or SIEM delivery; supported
non-Hermes producers; Windows or macOS sensors; signed supply-chain artifacts;
and production support/SLA commitments. This exclusion does not rule out the
planned v0.5.0 passive local durable alert/evidence presentation.

For rule-level detail, see [Detections](DETECTIONS.md#rule-to-producer-coverage-matrix). For installation evidence and caveats, see [Install](INSTALL.md) and [Fail-closed Hermes enrollment](HERMES_ENROLLMENT.md). For future work, see [Current roadmap](ROADMAP.md).
