# Skynet-EDR Hermes Plugin

Passive Hermes Agent telemetry plugin for Skynet-EDR v0.3.

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
- No inline blocking in v0.3.
- Raw tool output is omitted; only lengths and indicators are stored.
- Sensitive parameter previews are replaced as whole fields with
  `[REDACTED:secret]` or `[REDACTED:local_context]`.
- Hook failures are logged and swallowed so Hermes remains usable.

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
