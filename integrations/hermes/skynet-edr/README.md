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

By default the plugin writes user-local files:

```text
~/.local/state/skynet-edr/hermes/events.jsonl
~/.local/state/skynet-edr/hermes/skynet-edr-plugin.log
```

Both the spool and log are created with user-only permissions where supported.

## Environment variables

| Variable | Purpose |
|---|---|
| `SKYNET_EDR_HERMES_PLUGIN_ENABLED=0` | Disable emission without uninstalling the plugin. |
| `SKYNET_EDR_STATE_DIR` | Override the user-local state directory. |
| `SKYNET_EDR_SPOOL_PATH` | Override JSONL event spool path. |
| `SKYNET_EDR_LOG_PATH` | Override sanitized plugin log path. |
| `SKYNET_EDR_TENANT` | Tenant/workspace label in event provenance. |
| `SKYNET_EDR_MAX_FIELD_CHARS` | Bound safe preview strings. |
| `SKYNET_EDR_MAX_LOG_BYTES` | Rotate log to `.1` after this size. |
| `HERMES_SESSION_ID` / `HERMES_SESSION` | Optional Hermes trace/session ID; otherwise a process-local UUID fallback is used. |

## Security posture

- No outbound network.
- No LLM calls from the plugin.
- No inline blocking in v0.4.
- Raw tool parameters and raw tool output are omitted; only lengths and
  indicators are stored.
- Sensitive parameter previews are replaced as whole fields with
  `[REDACTED:secret]` or `[REDACTED:local_context]`; otherwise parameter
  previews are `[OMITTED:tool_params]`.
- Hook failures are logged and swallowed so Hermes remains usable.

## Risk Explorer

This package includes a visible, authenticated Hermes **Web Dashboard** Risk Explorer (`dashboard/plugin.js`) at `/skynet-edr/risks`, backed by the read-only proxy in `dashboard/plugin_api.py`. The Web Dashboard (`hermes dashboard`, normally port 9119) is the primary operator UI. The native Desktop disk plugin (`desktop/plugin.js`) remains a secondary companion surface.

The dashboard manifest registers exactly `skynet-edr`, shows the **Skynet-EDR** navigation tab with the Shield icon, and carries a computed SRI `sha384` digest. Hermes Agent v0.19.0 does not forward that field to the browser, so this release does not claim browser-enforced SRI on v0.19.0; release packaging still verifies `dashboard/plugin.js` through `SHA256SUMS`, and browser SRI applies with Hermes loaders that forward manifest integrity. The UI uses the authenticated dashboard SDK client (`SDK.fetchJSON`) only. It polls every 10 seconds and calls only `GET /api/plugins/skynet-edr/status`, `GET /api/plugins/skynet-edr/risks`, and `GET /api/plugins/skynet-edr/risks/{id}`. The backend forwards those reads to the fixed loopback Skynet-EDR API, denies redirects, and encodes opaque risk IDs before forwarding. Neither UI nor proxy exposes SQLite, shell/subprocess, response actions, mutation methods, caller-controlled upstream URLs, or direct unscoped network requests.

Install with `skynet-edr-install-hermes-plugin`; it copies telemetry and Web Dashboard files to `~/.hermes/plugins/skynet-edr/` and the secondary Desktop page to `~/.hermes/desktop-plugins/skynet-edr/plugin.js`. Enable the Hermes plugin allow-list entry, restart `hermes dashboard` (backend routes mount at startup), then open `/skynet-edr/risks`. The Desktop renderer can hot reload its disk plugin.

Both Risk Explorer surfaces display only validated `skynet.risk.v1` redacted projections from Skynet-EDR. Risk titles/summaries and evidence titles are deterministic labels generated from allowlisted rule IDs, event types, and scalar metadata; stored incident titles/summaries and stored event titles are not projected. Artifact labels are fixed by typed artifact kind, and arbitrary stored attributes are not displayed. Hostile values are rendered only as React text: there is no raw HTML, Markdown, active link, `innerHTML`, or direct URL/path rendering. The UI fails closed with generic errors when identity, enums, bounds, pagination, read-only flags, or deterministic labels do not match the expected schema.

## Ingesting into Skynet-EDR

Manual ingestion:

```bash
skynet-edr events ingest-spool \
  --db /var/lib/skynet-edr/skynet.sqlite \
  --spool ~/.local/state/skynet-edr/hermes/events.jsonl \
  --checkpoint ~/.local/state/skynet-edr/hermes/events.offset
```

Daemon polling can use the same paths in `/etc/skynet-edr/config.toml` under
`[spool]`, provided the daemon user can read the user-local spool. Keep this an
explicit operator decision; do not grant broad home-directory access blindly.
