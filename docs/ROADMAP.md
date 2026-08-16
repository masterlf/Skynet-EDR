# Roadmap to a Third-Party-Usable MVP

This page is the authoritative product milestone map. The [implementation plan](IMPLEMENTATION_PLAN.md) remains architecture and historical design context; release notes describe shipped versions; Kanban boards are dispatch records, not product truth.

**Roadmap snapshot:** 2026-08-16

**Shipped baseline:** `v0.6.0`

**Product MVP target:** `v0.7.0`

## Executive decision

`v0.6.0` is a credible passive **engineering MVP and stable SemVer evaluation release**. It is not yet a third-party-usable product MVP.

The shortest defensible path is `v0.7.0`: one external operator can install, enroll, exercise, understand, operate, restore, and remove Skynet-EDR on one exact supported host/runtime cell using only public artifacts and documentation.

The MVP remains deliberately narrow:

- Ubuntu 24.04 `amd64`/`x86_64` with systemd;
- the native `.deb` package path;
- Hermes Agent `0.20.0`, default profile, as the only supported live producer;
- passive detection, local redacted evidence, and read-only investigation;
- the existing seven narrow evidence-backed detections;
- no prevention, guard mode, containment, remote control plane, or outbound alert integration.

No additional detection rule is required for this MVP. The remaining risk is not a shortage of rules; it is the absence of an independently proven public user journey.

The release remains passive and is published as a prerelease. It has no production support commitment; signing, provenance, SBOM policy, broader platform validation, and repeatable runtime upgrade/rollback proof remain open. Release promotion is conditioned on the exact release SHA passing the disposable clean-host package/systemd, browser, threat-validation, and Hermes enrollment gates.

The shipped `v0.6.0` authority remains historical evidence. The current alpha.1 candidate advances only the exact Hermes 0.20 enrollment cell and release identity; it does not claim that the remaining third-party product-MVP exit gates below have passed.

## Current milestone: v0.7.0-alpha.1 autonomous enrollment prerelease

| Product gate | Verified current state | MVP consequence |
|---|---|---|
| Public release | `v0.6.0` is published from commit `edcf304f7ee53b9df38cfb8cac9f2bfb4871cb24`; current `main` is newer maintenance commit `81ce989e920accbaeb953c2e0ef668e4dfea9d8a` | Release identity exists; future candidates must bind reviewed source, tag, artifacts, and installed bytes again |
| Package path | Disposable Ubuntu 24.04 DEB/systemd, process identity, state access, and loopback API gates pass | Ubuntu 24.04 DEB is the only Tier 1 MVP package path |
| Other artifacts | RPM, Arch, and tarball artifacts are published without corresponding native runtime qualification | They remain explicitly unqualified or are omitted from the MVP release; publication is not support |
| Detection quality | Seven narrow rule paths are `DETECTED_AND_TESTED`; hostile malformed cases and benign near misses are versioned | Sufficient floor for MVP; claims remain narrow |
| Detection gaps | Three producer-dark rules and standalone secret access remain `NOT_COVERED`; real Hermes discovery/dispatcher ABI is `NOT_TESTED` | No claim expansion; at least one rule must gain real-host end-to-end evidence |
| Hermes enrollment | The strict transaction is ported to exact Hermes 0.20.0/default-profile behavior | Alpha.1 promotion requires exact package-owned clean-host apply/verify/unenroll proof with sealed evidence |
| Live producer health | The signed Hermes 0.20.0 release passed discovery, gateway health, and real-dispatch feasibility | Candidate acceptance still binds the exact package/plugin generation and fresh process/source evidence |
| Triage | SQLite incidents and Risk Explorer are authoritative local investigation surfaces | A local MVP does not require webhook, email, SIEM, or a dedicated alert outbox |
| Local notices | Post-commit stdout/journald notices are best effort; SQLite remains authoritative | Documentation and acceptance must prevent operators from treating journald as guaranteed delivery |
| Operations | Store retention/pruning and qualified backup/restore are absent; upgrade/rollback evidence is maintainer-controlled | Bounded store lifecycle and clean-host restore proof block MVP |
| Supply chain | Public checksums exist; signatures, signed checksums, SBOM, and provenance are absent | MVP requires an SBOM and one public cryptographic origin-verification path beyond unsigned checksums |
| Independent use | No non-builder has completed the whole journey using only public material | Independent acceptance blocks `v0.7.0` |

## MVP support contract

The initial product MVP supports exactly this cell:

| Dimension | MVP value |
|---|---|
| Host OS | Ubuntu 24.04 LTS |
| Architecture | `amd64` / `x86_64` |
| Init/service manager | systemd |
| Package | native `.deb` |
| Live producer | Hermes Agent `0.20.0` |
| Hermes profile | `default` |
| Operating mode | passive, local-first, read-only investigation |
| Deployment shape | one Linux host, one reviewed Hermes account |

A later patch/minor release may widen this matrix only after equivalent evidence exists. “Artifact available” must never be translated into “runtime supported.”

## Product MVP exit journey

`v0.7.0` is complete only when a non-builder can perform this journey on a clean host:

1. Discover the product and understand its supported and unsupported claims.
2. Download the exact release artifact, SBOM, coverage matrix, and cryptographic origin evidence.
3. Verify the artifact without private keys, private infrastructure, or maintainer-only files.
4. Install the DEB without compiling source.
5. Run a guided, dry-run-capable, idempotent enrollment for the supported Hermes account.
6. Verify exact plugin generation, real Hermes dispatch, authenticated ingestion, fresh producer health, and local service health.
7. Execute a deterministic safe simulation through the real Hermes hook and dispatcher.
8. Observe the expected persisted incident in Risk Explorer with redacted, actionable evidence.
9. Collect redacted diagnostics and understand that SQLite/Risk Explorer, not journald, is the authoritative incident source.
10. Exercise bounded retention, backup, upgrade, rollback, and restore.
11. Unenroll and uninstall without leaving an active plugin, service, socket, or unmanaged package-owned generation.

A failure at any step is a roadmap gate, not a documentation footnote.

## Reconciliation of previous plans

Earlier plans used `M0–M6`, `S0–S8`, `S3–S7`, and several incompatible meanings of `S4`. Their useful outcomes are retained below, but those labels are retired from the active public roadmap.

| Previous workstream | Rebased status |
|---|---|
| Product contract and release baseline | Delivered through `v0.6.0` |
| Minimal detection/redaction floor | Delivered for seven narrow synthetic scenarios; real Hermes dispatcher proof remains open |
| S3 enrollment | Transaction model and fixtures exist; external qualification never passed and the target Hermes version is stale |
| S4 alerting/triage | Durable incidents and Risk Explorer exist; best-effort notices exist; a dedicated outbox is not MVP scope |
| S5 operations/supply chain | Partially open: retention, restore qualification, SBOM, and origin proof remain |
| S6 full detection validation | Sufficient synthetic floor exists; real-host journey remains open |
| S7 independent beta | Not completed; becomes the `v0.7.0-rc.1` exit gate |
| Hostile concurrent UID 0 replacement and crash-idempotent enrollment-quarantine purge | Post-MVP hardening; root compromise is outside the initial product-MVP threat boundary |

No shipped outcome may be relabeled as new work. No historical S-label may be reused for an internal PR slice.

## Delivery roadmap

### R0 — Authority reset and scope freeze

**Outcome:** one current roadmap and one testable support cell.

**Work:**

- make this page the sole active milestone authority;
- preserve historical plans as history, not competing execution instructions;
- freeze `v0.7.0` to Ubuntu 24.04 amd64/systemd, DEB, Hermes 0.20.0, and default profile;
- publish the versioned coverage matrix as a release asset, not only a repository page;
- keep producer-dark and unsupported detections visibly `NOT_COVERED`;
- decide whether RPM, Arch, and tarball remain explicitly unqualified artifacts or are omitted from the MVP release;
- publish a short known-limitations document covering passive behavior, narrow detection claims, best-effort notices, and the single support cell.

**Exit gate:** documentation validation finds no contradictory active milestone, enrollment-support, platform-support, or detection-coverage claim.

**Budget:** 1–2 developer-days.

### Feasibility spike — Hermes 0.20 producer and real dispatcher

**Outcome:** prove that the target support cell is technically valid before porting enrollment.

This spike is mandatory because the existing enrollment transaction never passed its original Hermes 0.19.0 clean-host gate, and the current Hermes 0.20.0 browser lane proves activation rather than enrollment or dispatch.

**Work on a disposable clean host:**

- install exact Hermes Agent 0.20.0 with the default profile;
- determine whether the expected gateway producer exists and can become healthy without undocumented non-default setup;
- prove that Hermes discovers, loads, and dispatches to the plugin through the real host ABI;
- send at least one harmless real-hook event through AF_UNIX to a disposable daemon/store;
- record the Hermes 0.19.0-to-0.20.0 enrollment and dispatcher contract delta;
- classify failures as `host-preparation`, `Hermes-ABI`, `plugin-identity`, or `producer-health`.

**Exit gate:** a real host dispatch reaches authenticated ingestion and the target default-profile cell is viable.

**Stop condition:** if the default-profile producer cannot become healthy, or real dispatcher semantics invalidate the existing producer contract, stop and redesign the support cell. Do not begin enrollment implementation by optimism.

**Budget:** 1–2 developer-days.

### `v0.7.0-alpha.1` — Autonomous enrollment on the supported cell

**Outcome:** a clean host can enroll and unenroll Hermes 0.20.0 using public package bytes.

**Work:**

- rebase the existing strict enrollment transaction onto the proven Hermes 0.20.0 contract;
- preserve check/apply/verify/unenroll, dry-run behavior, idempotence, bounded deadlines, redaction, rollback evidence, and fail-closed drift handling;
- verify exact stable package/plugin generation with no alpha, development, or stale user-copy identity;
- make `verify` depend on real dispatch and healthy producer evidence, not copied files or an enable return code;
- exercise no-restart, explicitly authorized restart, repeat apply, repeat verify, and unenroll paths;
- keep account-wide user-manager restart impact explicit.

**Exit gate:** exact public candidate bytes pass disposable clean-host `check → apply → verify → unenroll`; a second apply is a no-op; unenroll restores the recorded pre-enrollment state.

`S3_ADAPTER_BLOCK` may be removed only after this exact-artifact gate passes.

**Budget:** 3–6 developer-days after the feasibility spike. If the spike classifies the work as re-engineering rather than a bounded port, re-plan before implementation.

### `v0.7.0-alpha.2` — Real detection and investigation journey

**Outcome:** one supported attack simulation becomes an actionable incident through the real product path.

**Work:**

- provide a deterministic safe simulation for one existing high-value rule;
- traverse real Hermes hook and dispatcher, plugin, authenticated AF_UNIX transport, SQLite commit, correlator, API, and Risk Explorer browser path;
- prove a secret-shaped synthetic marker is absent from producer output, SQLite, notices, diagnostics, and browser rendering;
- preserve rule ID, severity, timeline, provenance, confidence boundary, and recommended operator action;
- update the public coverage evidence to distinguish this real-host path from synthetic fixture evidence;
- keep the other six rules at their exact existing evidence level rather than generalizing from one journey.

**Exit gate:** the safe simulation produces exactly the expected incident and no forbidden synthetic marker survives any stored or displayed surface.

**Budget:** 3–5 developer-days.

### `v0.7.0-beta.1A` — Bounded local operations

**Outcome:** the product can be operated without silent disk exhaustion or an untested recovery story.

**Work:**

- define one bounded event/incident retention policy;
- provide a dry-run that identifies exactly what a prune would remove, followed by transactional apply behavior;
- expose disk/store pressure as explicit degraded health before failure;
- produce and verify a consistent backup while the service is operated according to the documented procedure;
- restore that backup on a clean host and prove incidents remain queryable in Risk Explorer;
- exercise `v0.6.0 → v0.7.0 candidate` upgrade and package rollback with preserved evidence;
- document downgrade compatibility boundaries and stop conditions.

**Exit gate:** prune dry-run and apply agree, pressure is visible, restore works on a clean host, and upgrade/rollback preserve a readable authoritative store.

**Budget:** 4–6 developer-days.

### `v0.7.0-beta.1B` — Public supply-chain verification

**Outcome:** a third party can authenticate the origin and inspect the composition of every MVP artifact.

This tranche has no Hermes dependency and should run in parallel after R0.

**Work:**

- generate an SPDX or CycloneDX SBOM for every shipped artifact;
- publish one cryptographic origin-verification path beyond unsigned checksums, such as a signed checksum manifest or verifiable provenance attestation;
- bind source commit, workflow, artifacts, checksums, SBOM, and origin evidence;
- provide a public verification command or script that fails closed;
- prevent rebuild or byte substitution after candidate acceptance.

**Exit gate:** an unaffiliated operator can verify origin and SBOM using only public material, and the verified candidate bytes are the bytes later published.

**Budget:** 2–4 developer-days, parallelizable.

### `v0.7.0-rc.1` — Independent non-builder acceptance

**Outcome:** one independent operator completes the whole product journey.

**Independence contract:** the acceptor has no commit access, private runbook, maintainer shell session, or unpublished artifact. The maintainer may observe but must not repair the host during the run.

**Work:**

- freeze the exact release candidate source and artifact identities;
- run the complete public journey on a clean host;
- record elapsed time, failed steps, documentation ambiguity, false positives, and recovery outcomes without collecting private event content;
- correct release-blocking defects only, then repeat the affected journey leg;
- require the acceptor to acknowledge the known-limitations and coverage documents;
- independently review the final exact SHA, artifact set, and acceptance evidence.

**Exit gate:** the acceptor completes download, origin/SBOM verification, install, enrollment, real safe incident, triage, diagnostics, retention, backup/restore, upgrade/rollback, unenroll, and uninstall using only public material.

**Budget:** 2–4 developer-days, excluding the independent operator's scheduling delay.

### `v0.7.0` — Third-party-usable passive MVP

Publish only when every binary gate above is closed. The accepted candidate artifact set must be the set published; no post-acceptance rebuild, silent waiver, or maintainer-only repair is allowed.

Stable SemVer identity remains a pre-1.0 MVP statement, not a production SLA or universal detection guarantee.

## Critical path and effort

```text
R0 authority reset
  ↓
Hermes 0.20 feasibility spike
  ↓
v0.7.0-alpha.1 enrollment
  ↓
v0.7.0-alpha.2 real detection journey
  ↓
v0.7.0-beta.1A local operations
  ↓
v0.7.0-rc.1 independent acceptance
  ↓
v0.7.0 MVP

v0.7.0-beta.1B supply chain
  └──────── runs in parallel after R0 and must close before RC acceptance
```

Estimated sequential path: **14–25 developer-days**.

Estimated total effort including the parallel supply-chain tranche: **16–29 developer-days**.

These are bounded planning ranges, not a calendar promise. The feasibility spike is intentionally first because it can invalidate the support-cell assumption cheaply. If it reveals re-engineering, the estimate is withdrawn and the roadmap must be revised before another writer starts.

## Explicit non-goals for `v0.7.0`

- new detection rules or wider claims for existing rules;
- dedicated alert outbox, JSONL replay, webhook, email, or SIEM delivery;
- inline approval, blocking, guard mode, or automatic containment;
- privileged/kernel/eBPF sensors;
- RPM/Arch runtime support, additional Linux distributions, non-systemd hosts, `arm64`, Windows, or macOS;
- OpenClaw, Codex, Claude Code, or another live producer;
- SaaS, fleet management, multi-tenancy, RBAC, or remote administration;
- hostile concurrent UID 0 replacement resistance;
- automatic crash-idempotent deletion of enrollment quarantine evidence;
- production support, SLA, commercial support, or universal prompt-injection detection.

These may be valuable later. Pulling them into the MVP would increase blast radius without proving the basic third-party journey.

## Delivery controls

Each tranche must have:

- one user-visible outcome;
- one primary writer, branch, worktree, and PR;
- RED evidence for defects before production changes;
- exact public/candidate artifact identity;
- explicit non-goals and rollback notes;
- a bounded runtime and retry budget;
- independent exact-SHA review before promotion.

Automatic stop conditions:

- two failures in the same declared failure class;
- a required new daemon, remote service, control plane, or outbound secret path;
- support-cell expansion;
- a database migration unrelated to the approved store-lifecycle tranche;
- a claim that relies only on fixtures, a maintainer-controlled host, matching version strings, or copied plugin bytes;
- any attempt to treat best-effort journald output as guaranteed alert delivery.

## MVP definition of done

- [ ] One authoritative roadmap and known-limitations document.
- [ ] One exact Ubuntu 24.04 amd64/systemd + Hermes 0.20.0/default-profile support cell.
- [ ] Public-artifact autonomous enrollment and clean unenrollment.
- [ ] Real Hermes dispatcher evidence.
- [ ] One real safe detection-to-Risk-Explorer journey.
- [ ] Redaction proof across storage, notices, diagnostics, and browser output.
- [ ] Bounded store lifecycle with visible pressure.
- [ ] Tested clean-host backup/restore and upgrade/rollback.
- [ ] SBOM and public cryptographic origin verification.
- [ ] Public coverage matrix with synthetic, real-host, partial, untested, and uncovered evidence distinguished.
- [ ] Independent non-builder clean-host acceptance.
- [ ] Return-to-clean-host uninstall proof.
- [ ] Exact accepted artifacts published without rebuild.

Until every item is checked with evidence, the truthful label remains **stable evaluation release**, not **third-party-usable product MVP**.
