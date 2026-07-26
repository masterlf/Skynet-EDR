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
| MCP server | Read-only visibility for agent runtimes | [Read-only MCP integration](MCP_READ_ONLY.md) |

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

The packaged continuous path accepts one length-prefixed `skynet.event.v0` event per authenticated AF_UNIX connection. It is passive: a successful transaction stores the redacted event, evaluates the built-in canonical sequence rules, stores any resulting incidents and a receipt, then returns a versioned acknowledgement. It is not guard mode and never approves, delays, blocks, or rewrites an agent action.

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
max_frame_bytes = 262144
max_connections = 16
read_timeout_ms = 1000
write_timeout_ms = 1000
candidate_limit = 2048
```

Restart the producer's login session so its supplementary groups are refreshed, then restart the daemon during an approved maintenance window. This runbook documents those actions; it does not authorize an unattended service restart.

Verify the effective boundary without reading producer data:

```bash
getent group skynet-edr-ingest
id hermes-user
stat -c '%U %G %a %n' /run/skynet-edr-ingest /run/skynet-edr-ingest/ingest.sock
sudo -u hermes-user test -S /run/skynet-edr-ingest/ingest.sock
```

Expected packaged ownership/modes are `skynet-edr:skynet-edr-ingest 750` for the directory and `skynet-edr:skynet-edr-ingest 660` for the socket. Startup fails closed instead of replacing a symlink, a non-socket, an active listener, or a stale socket owned by another UID.

### Health, counters, and backlog lag

When the local read-only API is enabled, `GET /api/status` includes an `ingestion` object. `state` is `disabled` when no listener was started, `healthy` only while the listener is live and every observed producer has a fresh available transport report with no backlog or degrading condition, and `degraded` otherwise. Storage errors, frame timeouts, correlation overflow, capacity rejection, listener/peer-credential errors, stale reports, producer transport degradation, and non-zero backlog all degrade the state.

```bash
curl --fail --silent http://127.0.0.1:8787/api/status
```

The object exposes bounded process-lifetime aggregates plus a source-aware `sources` array keyed only by the kernel-authenticated numeric UID:

- connections: accepted, unauthorized, capacity-rejected, listener errors, and peer-credential errors;
- frames: received, oversized, invalid, and timed out;
- outcomes: persisted, duplicate, event-ID collision, correlation overflow, and storage errors;
- listener liveness and, per source, last event received/committed timestamps, producer checkpoint bytes, pending backlog bytes/age, malformed/dropped/duplicate/collision totals, fixed-category last error plus timestamp, producer-report timestamp, and transport state (`available`, `degraded`, `stale`, or `unknown`).

The authenticated producer sends a strict version-1 control frame periodically and after delivery work. Unknown fields, labels, paths, payloads, commands, and strings outside the fixed transport enum are rejected. `/api/status` never projects socket/spool paths, event content, command text, or secrets. A report is stale 30 seconds after the daemon received it. Runtime counters, source entries, liveness, and timestamps reset on daemon restart; durable events, receipts, incidents, collision fingerprints, producer fallback, and its checkpoint do not. Until a producer reports again after restart its transport is `unknown`, so status cannot claim end-to-end health.

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

- If the daemon is unavailable or returns a retryable outcome, the producer attempts a durable versioned fallback append. An abrupt producer-process exit can still lose records that existed only in the in-memory queue.
- The producer worker replays small bounded batches before new delivery and during idle periods. Duplicate event IDs from an uncertain ACK are idempotent only when source identity and payload match; a mismatch is a permanent collision.
- A storage or correlation transaction failure rolls back event, incident, and receipt together and returns `retry_later` when an ACK can be written.
- Candidate overflow persists the triggering redacted event and receipt atomically with one deterministic, event-deduplicated `Continuous correlation degraded` incident, increments `correlation_truncated_total`, and degrades status. Replaying the same trigger does not duplicate the alert, while a distinct later overflow remains visible. It never treats the skipped evaluation as a clean no-match. Increase limits only after investigating event volume and memory/storage impact.
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
    "event_type": "agent.session.canary",
    "observed_at_unix_ms": now,
    "received_at_unix_ms": now,
    "severity": "informational",
    "source": {"kind": "sensor", "sensor": "operations-canary", "integration": "manual-local"},
    "provenance": {
        "producer": "operations-canary",
        "collector": "skynet-edr-daemon",
        "tenant": "local-canary",
        "source_event_id": event_id,
        "trace_id": f"trace_{event_id}",
    },
    "trust_level": "sensor_observation",
    "title": "Harmless local continuous-ingestion canary",
    "attributes": {"canary": True},
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
