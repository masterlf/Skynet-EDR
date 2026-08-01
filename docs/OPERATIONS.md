# Operations

This page is the v0.4 operator index for running and validating Skynet-EDR after installation.

Use [Install](INSTALL.md) for package installation and rollback commands. Use [Quickstart](QUICKSTART.md) for the shortest first-run path.

## Operating posture

The current MVP is passive and Linux-first. It emphasizes redacted local evidence, read-only visibility, and high-signal correlation. It should not be treated as a remote containment platform or a replacement for mature EDR/SIEM controls.

## Runtime surfaces

| Surface | Default posture | Documentation |
|---|---|---|
| CLI | Local operator commands | [Local storage and CLI](LOCAL_STORAGE.md) |
| SQLite store | Local event and incident persistence | [Local storage and CLI](LOCAL_STORAGE.md#sqlite-store) |
| Daemon/service | Passive runtime path | [Install](INSTALL.md#what-is-installed) |
| AF_UNIX ingestion | Authenticated, bounded producer transport | [Continuous ingestion operations](#continuous-ingestion-operations) |
| Local HTTP API | Localhost-only read-only visibility | [Local read-only HTTP API and console](LOCAL_HTTP_API.md) |
| MCP handler crate | Implemented read-only handler surface; no network MCP server | [Read-only MCP integration](MCP_READ_ONLY.md) |

## First-run checks

After installing or building, run:

```bash
skynet-edr status
sudo -u skynet-edr skynet-edr store init --db /var/lib/skynet-edr/skynet.sqlite
skynet-edr doctor
skynet-edr diagnostics collect --output ./skynet-edr-diagnostics
```

`skynet-edr doctor` checks the packaged operator layout by default:

- `/etc/skynet-edr/config.toml` exists and is readable;
- the local store exists at `/var/lib/skynet-edr/skynet.sqlite` and opens successfully;
- readiness is available through either a loopback-only local API endpoint or a plugin spool file;
- config/API readiness fails closed when the API bind or supplied API target is not loopback.

The doctor command intentionally does not require `rules.d` or `agents.d` directories. Those directories may exist in package layouts for future policy/adaptor drops, but current readiness is based on config, store, and local daemon/API or plugin-spool availability.

`skynet-edr diagnostics collect` creates a private bundle directory (`0700`) and writes private files (`0600`). By default it includes versions, a redacted config summary, and store counts only; it does not export raw events or create a missing database. Operator-supplied logs or service status can be added with `--log-file` and `--service-status-file`; their contents are redacted before writing.

## Continuous ingestion operations

The packaged continuous path accepts one length-prefixed `skynet.event.v0` event per authenticated AF_UNIX connection. Before persistence it applies the exact continuous-ingest event/source/trust/attribute projection; unknown, mistyped, raw-bearing, or non-allowlisted shapes are permanently rejected without an event, incident, or receipt. A successful transaction stores the projected event, evaluates the built-in sequence rules plus bounded `EDR-EXFIL-001` and `EDR-MALWARE-001` correlators, stores derived incidents before the receipt, then returns a versioned acknowledgement. It is not guard mode and never approves, delays, blocks, or rewrites an agent action.

### Deploy and enroll a producer

The package creates the `skynet-edr` service account, the `skynet-edr-ingest` group, and `/run/skynet-edr-ingest` as `0750 skynet-edr:skynet-edr-ingest`. The daemon creates `ingest.sock` as `0660`, owned by the daemon and assigned to the configured socket group. Two independent checks are required:

1. socket directory/file DAC: the producer must be a member of `skynet-edr-ingest`;
2. peer authentication: the producer's numeric UID must appear in `ingest.allowed_uids`.

Group membership alone does not authorize ingestion. UID `0` is rejected even if listed in `allowed_uids`; root requires the separate, explicitly reviewed `allow_root = true` setting.

For each reviewed Hermes account, record its stable numeric UID, add the account to the socket group, and update `/etc/skynet-edr/config.toml`:

```bash
id hermes-user
sudo usermod -aG skynet-edr-ingest hermes-user
```

```toml
[ingest]
enabled = true
socket = "/run/skynet-edr-ingest/ingest.sock"
socket_group = "skynet-edr-ingest"
allowed_uids = [1000] # reviewed numeric producer UID; do not copy blindly
allow_root = false
required_reported_roles = ["gateway"] # operational self-report gate; omit/[] is generic
max_frame_bytes = 262144
max_connections = 16
read_timeout_ms = 1000
write_timeout_ms = 1000
candidate_limit = 2048
```

Assign attribution per unit, never through `systemctl --user set-environment` or another global user-manager environment. First identify the exact reviewed unit names. Then create separate drop-ins:

```bash
systemctl --user edit <gateway-unit>
# [Service]
# Environment=HERMES_RUNTIME_ROLE=gateway

systemctl --user edit <dashboard-unit>
# [Service]
# Environment=HERMES_RUNTIME_ROLE=dashboard

systemctl --user daemon-reload
```

After change approval, restart only those two reviewed units in the approved window. A deliberately configured `SKYNET_EDR_RUNTIME_INSTANCE` may remain stable; otherwise the generated fallback instance changes when its process restarts. Do not require an unconditional instance change. Verify fresh status after restart:

```bash
systemctl --user restart <gateway-unit> <dashboard-unit> # approved targeted restart only
curl --fail --silent http://127.0.0.1:8787/api/status
```

A correctly configured per-unit dashboard role cannot satisfy the required reported gateway role. This is operational enrollment evidence only: `runtime_role` and `instance_id` are self-reported by a kernel-authorized UID. A same-UID compromise, a root process in the current shared trust domain, or a mistaken/global role assignment can forge attribution. `role_identity_assurance="authorized_uid_self_reported"` states this boundary; it is not security-grade process or role attestation.

Restart the producer's login session so its supplementary groups are refreshed, then restart the daemon and each reviewed Hermes gateway/dashboard service during an approved maintenance window. Installing plugin bytes is not proof that an already-running process loaded them, and the plugin installer intentionally does not restart its parent or any service. Use the deployment's normal service manager (for example, after confirming the exact unit names with `systemctl --user list-units 'hermes*'`, restart only the reviewed units). This runbook documents those actions; it does not authorize an unattended service restart.

Verify the effective boundary without reading producer data:

```bash
getent group skynet-edr-ingest
id hermes-user
stat -c '%U %G %a %n' /run/skynet-edr-ingest /run/skynet-edr-ingest/ingest.sock
sudo -u hermes-user test -S /run/skynet-edr-ingest/ingest.sock
```

Expected packaged ownership/modes are `skynet-edr:skynet-edr-ingest 750` for the directory and `skynet-edr:skynet-edr-ingest 660` for the socket. Startup fails closed instead of replacing a symlink, a non-socket, an active listener, or a stale socket owned by another UID.

### Health, counters, and backlog lag

When the local read-only API is enabled, `GET /api/status` includes an `ingestion` object. `state` is `disabled` when no listener was started. Active state is `healthy` only while the listener is live, at least one producer heartbeat is fresh, every configured `required_reported_roles` entry has at least one fresh/available/no-backlog instance, no fresh producer reports degraded transport or backlog, and no recent daemon degradation is active. It is `degraded` otherwise. Stale optional/transient `worker` or `unknown` instances remain visible during retention but do not poison health while a required gateway instance is fresh. With no configured requirements, no producers or all-stale producers remains degraded. Storage errors, frame timeouts, correlation overflow, capacity rejection, listener/peer-credential errors, producer transport degradation, and non-zero backlog degrade the state.

```bash
curl --fail --silent http://127.0.0.1:8787/api/status
```

The object exposes bounded process-lifetime aggregates plus at most 64 complete source identities keyed by kernel-authenticated numeric UID, fixed self-reported runtime role, and bounded non-sensitive process instance. Legacy v1 reporting remains a separate `(UID, legacy)` identity. All source identities inactive for five minutes are evicted lazily before projection or version-2 producer-health insertion, so normal process restarts cannot consume the 64 slots forever; the map and retention state reset on daemon restart:

- connections: accepted, unauthorized, capacity-rejected, listener errors, and peer-credential errors;
- frames: received, oversized, invalid, and timed out;
- outcomes: persisted, duplicate, event-ID collision, incident-integrity collision, correlation overflow, and storage errors;
- listener liveness, required-role enrollment state, producer heartbeat timestamp/age and transport state (`available`, `degraded`, `stale`, or `unknown`), plus checkpoint/backlog and fixed counters;
- separate daemon-observed last accepted and last committed hook-event timestamps/ages. `hook_event_state` is `fresh`, `stale`, or `not_observed` from daemon receive time; it is not inferred from heartbeat traffic. `hook_event_freshness_affects_state=false` is explicit: an idle runtime with no expected user activity is not degraded solely because no hook event has occurred. Operators must compare event ages with known activity when investigating telemetry coverage.

The authenticated producer sends a strict version-2 control frame periodically and after delivery work. Legacy version-1 reports remain visible as `legacy`, but never satisfy a configured required role. Unknown fields, labels, paths, payloads, commands, and strings outside the fixed transport enum are rejected. `/api/status` never projects socket/spool paths, event content, command text, or secrets. A report is stale 30 seconds after the daemon received it. Transient daemon errors degrade current state for the same 30-second health window; the cumulative counters and fixed-category last-error fields remain visible after current state recovers. Runtime counters, source entries, liveness, and timestamps reset on daemon restart; durable events, receipts, incidents, collision fingerprints, producer fallback, and its checkpoint do not. Until a producer reports again after restart its transport is `unknown`, so status cannot claim end-to-end health.

The Hermes producer writes process-lifetime transport counter snapshots to its sanitized log only when values change:

```text
transport_counters queue_drops=N socket_failures=N fallback_full=N fallback_records=N
```

`queue_drops` means the bounded in-memory queue dropped the newest event rather than block Hermes. `socket_failures` includes unavailable transport or an invalid/non-terminal ACK. `fallback_full` means the bounded fallback retained older pending records and refused the newest record. `fallback_records` counts successful durable fallback appends; it is not current backlog depth.

The source entry reports `backlog_bytes` as versioned fallback size minus its producer-owned checkpoint and reports `backlog_age_ms` from the pending fallback file age without opening event content. Operators can independently verify the same byte lag while troubleshooting:

```bash
python3 - <<'PY'
from pathlib import Path

state = Path.home() / ".local/state/skynet-edr/hermes"
spool = state / "events-v1.jsonl"
checkpoint = state / "events-v1.offset"
size = spool.stat().st_size if spool.exists() else 0
try:
    offset = int(checkpoint.read_text(encoding="ascii")) if checkpoint.exists() else 0
except (OSError, UnicodeDecodeError, ValueError):
    offset = 0
print(f"fallback_pending_bytes={max(0, size - min(offset, size))}")
PY
```

### Versioned fallback and historical backlog policy

The current producer owns only `events-v1.jsonl`, `events-v1.offset`, and its process-shared lock. Appends and checkpoint replacements are flushed to the file and parent directory. Pending records are replayed in order; while any fallback remains, new events append behind it. The checkpoint advances only after a version-1 terminal ACK for the matching event ID: `persisted`, `duplicate`, `collision`, or `rejected_permanent`. A `collision` ACK is emitted only after bounded fingerprint-only collision evidence commits. Timeouts, connection failures, malformed ACKs, and `retry_later` leave the record pending.

The default pending-byte cap is 64 MiB and the hard configurable ceiling is 256 MiB. Acknowledged prefixes may be compacted before enforcing the cap. If pending data alone reaches the cap, the oldest pending records are retained and newer records are dropped and counted as `fallback_full`.

The daemon never scans producer home directories and continuous ingestion never opens the historical unversioned `events.jsonl`. Treat that file as a separate legacy backlog. Import a specifically reviewed historical spool only with the explicit `skynet-edr events ingest-spool` command and a separate checkpoint. Do not run a manual import against `events-v1.jsonl` while the Hermes producer is active; first quiesce or disable that producer so its replay and compaction cannot race the importer.

### Failure and restart behavior

- If the daemon is unavailable or returns a retryable outcome, the producer attempts a durable versioned fallback append. Replay can delay observations; an abrupt producer-process exit can still lose records that existed only in the in-memory queue.
- The producer worker replays small bounded batches before new delivery and during idle periods. Duplicate event IDs from an uncertain ACK are idempotent only when source identity and payload match; a mismatch is a permanent collision. Durable collision evidence is bounded to the first fingerprint-only row for each colliding event identifier and authenticated source, so payload variants cannot amplify evidence storage.
- A generic storage or correlation transaction failure rolls back event, incident, and receipt together and returns `retry_later` when an ACK can be written. A derived incident-ID collision also rolls back that transaction, then records one fingerprint-only row per deterministic incident/source key in a separate transaction. Successful diagnostic persistence returns terminal `rejected_permanent` with reason `incident_collision`, increments `incident_integrity_collision_total`, and exposes the fixed `incident_collision` health category; diagnostic persistence failure returns `retry_later` and commits neither trigger nor receipt.
- Candidate overflow evaluates a bounded subset that always retains the triggering projected event, then persists that event and receipt atomically with one deterministic, event-deduplicated `Continuous correlation degraded` incident, increments `correlation_truncated_total`, and degrades status. Replaying the same trigger does not duplicate the alert, while a distinct later overflow remains visible. Truncation is incomplete visibility and is never treated as a clean no-match. Increase limits only after investigating event volume and memory/storage impact.
- Producer timestamps and trace/session joins are assertions, not attestations. Correlation keys are pseudonymized before storage, trace takes precedence over session, and equal timestamps use event-ID order. UID authorization does not prove process identity or event truth. Passive incidents do not prevent the observed action; fallback delay, queue/fallback drops, classifier truncation, and candidate overflow can make coverage incomplete.
- The systemd unit restarts a failed daemon after five seconds. Its in-memory counters and source health reset; the SQLite store and producer-owned fallback remain. Listener-thread liveness is explicit in `/api/status`; verify liveness, fresh producer reports, and counter movement after a restart.

### Harmless transport canary

Run this as an enrolled, non-root producer. It sends one informational synthetic event, performs no tool action or network egress, and should not match a rule. It verifies socket DAC, peer UID authorization, frame handling, transaction commit, and terminal ACK; it does not verify Hermes hook registration or fallback replay.

```bash
python3 - <<'PY'
import json, socket, struct, time, uuid

now = int(time.time() * 1000)
event_id = f"evt_ops_canary_{uuid.uuid4().hex}"
event = {
    "schema_version": "skynet.event.v0",
    "event_id": event_id,
    "event_type": "agent.session.started",
    "observed_at_unix_ms": now,
    "received_at_unix_ms": now,
    "severity": "informational",
    "source": {"kind": "sensor", "sensor": "skynet-edr-hermes-plugin", "integration": "hermes"},
    "provenance": {
        "producer": "hermes-agent",
        "collector": "skynet-edr-hermes-plugin",
        "source_event_id": event_id,
        "trace_id": f"trace_{event_id}",
    },
    "trust_level": "sensor_observation",
    "title": "Harmless local continuous-ingestion canary",
    "attributes": {"plugin_version": "0.4.1", "argument_count": 0, "keyword_count": 0},
    "redaction": {"contains_sensitive_data": False, "redacted_fields": []},
}
payload = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(2)
    client.connect("/run/skynet-edr-ingest/ingest.sock")
    client.sendall(struct.pack(">I", len(payload)) + payload)
    ack = client.makefile("rb").readline(4097)
response = json.loads(ack)
assert response == {"event_id": event_id, "status": "persisted", "version": 1}, response
print(json.dumps(response, sort_keys=True))
PY
```

Confirm `events_persisted_total` increased by one and no incident was opened for the canary. Re-running the script creates a new event; replaying the exact same payload should return `duplicate`.

### Continuous-ingestion rollback

For a transport-only rollback that preserves evidence capture:

1. set `ingest.enabled = false` in the reviewed config and restart the daemon in an approved window;
2. leave the current Hermes plugin enabled if bounded `events-v1.jsonl` capture is desired during the outage, and monitor `fallback_full`;
3. do not delete the socket path manually; package tmpfiles handling and the daemon's safe stale-socket checks own it;
4. before any plugin downgrade, stop or disable the producer, preserve its private versioned fallback/checkpoint as evidence, and confirm the target version's spool contract;
5. after restoring the reviewed config/version, re-enroll UIDs if needed, run the harmless canary, and verify fallback pending bytes trend to zero.

Package-version rollback commands are in [Install](INSTALL.md#upgrade-and-rollback). Do not restore an older SQLite database over a live service, and do not claim fallback drain until the producer checkpoint reaches the versioned fallback size.

For source checkouts, also run:

```bash
cargo test --workspace --all-features
python3 packaging/scripts/check-docs.py
```

## Evidence handling

Operational evidence must be redacted before it is stored or exposed through CLI/API/MCP output. Do not use real secrets in demos or lab validation.

Safe lab guidance:

- [Linux lab testing](LINUX_LAB_TESTING.md#fake-honeytokens-only)
- [Linux lab testing](LINUX_LAB_TESTING.md#evidence-handling)
- [Threat model](THREAT_MODEL.md#assets)

## Local API and console

The local HTTP API is intended for local visibility only. Keep it bound to localhost unless a later design explicitly adds authentication, authorization, transport security, and threat-model updates.

See [Local read-only HTTP API and console](LOCAL_HTTP_API.md#security-boundary).

## MCP operations

The MVP MCP integration is read-only. Use it to inspect status, incidents, rule metadata, sensor metadata, and config drift. Do not grant it write/containment authority without a separate design and tests.

See [Read-only MCP integration](MCP_READ_ONLY.md#tools).

## Troubleshooting

Start with package and install issues in [Install](INSTALL.md#troubleshooting). For runtime data questions, inspect:

- [Local storage and CLI](LOCAL_STORAGE.md#event-inspection-commands)
- [Local storage and CLI](LOCAL_STORAGE.md#incident-triage-commands)
- [Local read-only HTTP API and console](LOCAL_HTTP_API.md#verification)
- [Hermes event ingestion](HERMES_EVENT_INGESTION.md#verification)

## Upgrade and rollback

Use the upgrade and rollback guidance in [Install](INSTALL.md#upgrade-and-rollback). Package contents and release validation are described in [Release process](RELEASE_PROCESS.md) and [Packaging plan](PACKAGING.md).

## Security operations checklist

Before trusting an operational setup:

- release checksums verified;
- package installed from expected source;
- local store initialized with correct filesystem permissions;
- read-only API exposed only as intended;
- MCP integration remains read-only;
- test fixtures use fake honeytokens only;
- alert output is redacted;
- logs do not contain raw secrets;
- daemon home access is disabled and ingest producers are UID-allowlisted;
- documentation checks and relevant Rust gates pass.
