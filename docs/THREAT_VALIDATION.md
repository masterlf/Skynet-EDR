# Threat Validation Suite

The repository-owned Threat Validation Suite is a deterministic, synthetic-only quality gate for Skynet-EDR v0.6.0-beta.1. It consolidates the existing S2/M4a corpus instead of creating a second fixture universe.

## Run it

From the repository root, with locked Rust dependencies already available:

```bash
python3 packaging/scripts/threat-validation.py --output target/threat-validation/evidence.json
```

The runner sets Cargo offline mode and executes only fixed local commands. It needs no network, secrets, root privileges, live services, or host mutation. To check only the manifest/matrix contract without claiming execution evidence:

```bash
python3 packaging/scripts/threat-validation.py --validate-only --output target/threat-validation/contract.json
```

Validate-only evidence has status `not_tested`; it is never detection proof. Caller-selected custom manifests are accepted only in this mode because the fixed Rust and producer gates execute the repository-owned default manifest. `--scenario ID` rejects unknown IDs and limits reported results, although the bounded shared engine/producer gates still replay the complete corpus so cross-scenario regressions cannot be hidden.

## Evidence

The JSON output schema is `skynet.threat-validation-evidence.v1`. It records the suite version, exact manifest SHA-256, deterministic scenario ordering, fixed gate exit status, expected outcome, and `passed`, `failed`, `skipped`, or `not_tested` per scenario. It deliberately omits timestamps, hostnames, temporary paths, raw events, diagnostics, and environment data, so identical inputs and successful checks produce byte-identical evidence.

A `passed` scenario means its bounded offline fixture met its declared expectation. A `skipped` scenario is an explicit coverage gap. A green suite is not proof that arbitrary attacks are prevented or detected.

## Add a scenario

1. Add one case to `crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json`; never rename or reuse an existing `case_id`.
2. Use only clearly synthetic data, `.invalid` destinations, documentation-only IP ranges, and fake markers. Do not add executable malware, credentials, public egress, or dangerous commands.
3. Declare one category: `malicious`, `benign`, or `hostile-malformed`.
4. Declare exact `expected_outcome`, `expected_match`, incident count/severity, `rule_id`, engine, producer path, evidence strength, limitations, compatibility, and execution mode.
5. Link the ID in `docs/coverage/v0.6.0-beta.1.json` and set only one approved matrix status.
6. Add or update a failing validator/engine regression first, then run the suite twice and compare hashes.

The runner fails closed on duplicate JSON keys, duplicate IDs, unknown fields/categories/outcomes/execution modes, incoherent category/outcome/match/count tuples, replay cases without executable engine and producer evidence, unsafe declarations, custom manifests in executed mode, unknown scenario selections, unknown matrix statuses, omitted links, and live/skipped status drift.

## Interpretation and limits

- `DETECTED_AND_TESTED`: the exact shipped narrow path has positive and benign-near-miss fixture evidence.
- `PARTIAL`: some engine evidence exists, but the full shipped producer/runtime path is absent.
- `NOT_TESTED`: no qualifying execution evidence is claimed by this suite.
- `NOT_COVERED`: no shipped path provides the capability.

All product behavior remains passive. The suite does not block, prevent, contain, quarantine, approve, or mutate agent actions. It invokes plugin callbacks directly, not the real Hermes dispatcher ABI; it does not test packages, service management, production timing distributions, unbounded inputs, every classifier bypass, or external producers. See the versioned [public protection matrix](PROTECTION_MATRIX_v0.6.0-beta.1.md).
