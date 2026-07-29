# Skynet-EDR Hermes Plugin

Passive Hermes Agent telemetry plugin for Skynet-EDR v0.4.

The plugin observes Hermes lifecycle hooks and emits canonical `skynet.event.v0`
JSONL events. It is intentionally non-blocking: it does not approve, deny, or
modify model/tool execution.

## Captured hooks

- `on_session_start`
- `on_session_end`
- `pre_llm_call`
- `pre_tool_call`
- `post_tool_call`


## Default output

The hook path serializes into a bounded in-memory queue only. A producer-owned
worker sends length-prefixed canonical events to the daemon AF_UNIX socket. If
the daemon is unavailable, the worker writes a bounded, private, versioned
fallback and advances its checkpoint only after a terminal daemon ACK:

```text
~/.local/state/skynet-edr/hermes/events-v1.jsonl
~/.local/state/skynet-edr/hermes/events-v1.offset
~/.local/state/skynet-edr/hermes/skynet-edr-plugin.log
```

The fallback, checkpoint, and log are user-private where supported.

## Environment variables

| Variable | Purpose |
|---|---|
| `SKYNET_EDR_HERMES_PLUGIN_ENABLED=0` | Disable emission without uninstalling the plugin. |
| `SKYNET_EDR_STATE_DIR` | Override the user-local state directory. |
| `SKYNET_EDR_INGEST_SOCKET` | Override the AF_UNIX ingest socket. |
| `SKYNET_EDR_SOCKET_TIMEOUT_MS` | Bound connect/write/ACK time in the worker. |
| `SKYNET_EDR_EVENT_QUEUE_SIZE` | Bound the in-memory handoff queue. |
| `SKYNET_EDR_SPOOL_PATH` | Override the versioned fallback JSONL path. |
| `SKYNET_EDR_CHECKPOINT_PATH` | Override the fallback replay checkpoint. |
| `SKYNET_EDR_FALLBACK_MAX_BYTES` | Bound fallback storage (hard ceiling: 256 MiB). |
| `SKYNET_EDR_LOG_PATH` | Override sanitized plugin log path. |
| `SKYNET_EDR_TENANT` | Tenant/workspace label in event provenance. |
| `SKYNET_EDR_MAX_FIELD_CHARS` | Bound safe preview strings. |
| `SKYNET_EDR_MAX_LOG_BYTES` | Rotate log to `.1` after this size. |
| `HERMES_SESSION_ID` / `HERMES_SESSION` | Optional Hermes trace/session ID; otherwise a process-local UUID fallback is used. |
| `HERMES_RUNTIME_ROLE` | Fixed self-reported operational role for this process (`gateway`, `dashboard`, `worker`, or `unknown`); configure per unit, never globally. |
| `SKYNET_EDR_RUNTIME_INSTANCE` | Optional stable bounded process-instance label; otherwise a fresh fallback is generated when the process starts. |

## Security posture

- No outbound network; transport is local AF_UNIX only.
- Hook callbacks perform no socket or file I/O. Queue-full behavior drops the
  newest record rather than blocking Hermes. The producer worker writes aggregate
  queue/socket/fallback counters to the sanitized operational log.
- No LLM calls from the plugin.
- No inline blocking in v0.4.
- Raw tool parameters and raw tool output are omitted; only lengths and
  indicators are stored.
- Newly emitted parameter previews are always `[OMITTED:tool_params]`.
  Sensitive-pattern metadata records that fixed omission without raw values or
  reason-specific preview markers.
- Legacy canonical import rejects duplicate or ambiguous redaction paths and
  unsafe attribute keys before persistence. Keys use bounded ASCII
  `[A-Za-z0-9][A-Za-z0-9_-]*`; paths use exactly one `attributes.` prefix and a
  single top-level key. The complete canonical attribute payload must already be
  unchanged by storage sanitization; sensitive names require an already-redacted
  value and coherent Secret metadata. Unsafe keys are rejected, never silently
  renamed.
- Hook failures are logged and swallowed so Hermes remains usable.
- Exact successful active built-in `cronjob` `create`/`update` outcomes emit a
  fixed `agent.automation.scheduled` event. Raw prompts, results, and job IDs are
  never copied into that event.
- Config, persistence, and approval-scope mutation rules remain explicitly dark:
  terminal and generic file-write success do not prove Hermes parsed, accepted,
  or loaded a config, and the approval callback fires before scope persistence.

## Risk Explorer

This package includes a visible, authenticated Hermes **Web Dashboard** Risk Explorer (`dashboard/plugin.js`) at `/skynet-edr/risks`, backed by the read-only proxy in `dashboard/plugin_api.py`. The Web Dashboard (`hermes dashboard`, normally port 9119) is the primary operator UI. The native Desktop disk plugin (`desktop/plugin.js`) remains a secondary companion surface.

The dashboard manifest registers exactly `skynet-edr`, shows the **Skynet-EDR** navigation tab with the Shield icon, and carries a computed SRI `sha384` digest. Hermes Agent v0.19.0 does not forward that field to the browser, so this release does not claim browser-enforced SRI on v0.19.0; release packaging still verifies `dashboard/plugin.js` through `SHA256SUMS`, and browser SRI applies with Hermes loaders that forward manifest integrity. The UI uses the authenticated dashboard SDK client (`SDK.fetchJSON`) only. It polls every 10 seconds and calls only `GET /api/plugins/skynet-edr/status`, `GET /api/plugins/skynet-edr/risks`, and `GET /api/plugins/skynet-edr/risks/{id}`. The backend forwards those reads to the fixed loopback Skynet-EDR API, denies redirects, and encodes opaque risk IDs before forwarding. Neither UI nor proxy exposes SQLite, shell/subprocess, response actions, mutation methods, caller-controlled upstream URLs, or direct unscoped network requests.

Install with `skynet-edr-install-hermes-plugin`; it copies telemetry and Web Dashboard files to `~/.hermes/plugins/skynet-edr/` and the secondary Desktop page to `~/.hermes/desktop-plugins/skynet-edr/plugin.js`. Enable the Hermes plugin allow-list entry, restart `hermes dashboard` (backend routes mount at startup), then open `/skynet-edr/risks`. The Desktop renderer can hot reload its disk plugin.

Both Risk Explorer surfaces display only validated `skynet.risk.v1` redacted projections from Skynet-EDR. Risk titles/summaries and evidence titles are deterministic labels generated from allowlisted rule IDs, event types, and scalar metadata; stored incident titles/summaries and stored event titles are not projected. Artifact labels are fixed by typed artifact kind, and arbitrary stored attributes are not displayed. Hostile values are rendered only as React text: there is no raw HTML, Markdown, active link, `innerHTML`, or direct URL/path rendering. The UI fails closed with generic errors when identity, enums, bounds, pagination, read-only flags, or deterministic labels do not match the expected schema.

## Continuous ingestion authorization

The packaged daemon never reads producer home directories. To authorize a
Hermes user, add that account to `skynet-edr-ingest` for socket DAC access and
add its numeric UID to `ingest.allowed_uids` in `/etc/skynet-edr/config.toml`.
Restart the user's session after changing supplementary groups, then restart the
daemon. Root is denied unless `ingest.allow_root = true` is explicitly reviewed.

When enabled, registration starts exactly one background worker and attempts an immediate health frame before waiting for hook activity. Configure `HERMES_RUNTIME_ROLE` in separate per-unit systemd user drop-ins for the reviewed gateway and dashboard units; do not use a global user-manager environment. `ingest.required_reported_roles = ["gateway"]` is an operational enrollment gate: a correctly configured dashboard report cannot satisfy it. The runtime role and instance are still self-reported by an authorized UID, not process attestation. Same-UID compromise, an enabled root producer in the shared trust domain, or mistaken/global assignment can forge attribution. See [Continuous ingestion operations](../../../docs/OPERATIONS.md#continuous-ingestion-operations) for approved reload/restart and verification steps.

The legacy `skynet-edr events ingest-spool` command remains available for
explicit manual import. The daemon does not poll the plugin's historical
`events.jsonl`; continuous fallback uses only `events-v1.jsonl` and its
producer-owned checkpoint.
