# Hermes Plugin Telemetry

Skynet-EDR v0.3 ships a passive Hermes Agent plugin. The plugin is the preferred
non-invasive live telemetry path for Hermes hosts.

## Positioning

The plugin is a sensor, not an inline control point. It does not block, approve,
rewrite, or delay Hermes actions in v0.3. Blocking/policy enforcement remains a
future guard-mode feature.

```text
Hermes lifecycle hooks
        ↓
skynet-edr Hermes plugin
        ↓
canonical skynet.event.v0 JSONL spool + sanitized plugin log
        ↓
skynet-edr daemon/CLI ingest-spool
        ↓
local events, incidents, API, MCP visibility
```

## Installed files

Packages place the plugin template and installer here:

```text
/usr/share/skynet-edr/hermes-plugin/skynet-edr/plugin.yaml
/usr/share/skynet-edr/hermes-plugin/skynet-edr/__init__.py
/usr/share/skynet-edr/hermes-plugin/skynet-edr/README.md
/usr/bin/skynet-edr-install-hermes-plugin
```

Install it for the current Hermes user:

```bash
skynet-edr-install-hermes-plugin
```

This copies the plugin into:

```text
~/.hermes/plugins/skynet-edr/
```

If Hermes uses opt-in plugins, enable it and restart Hermes:

```bash
hermes plugins enable skynet-edr
```

## Hooks

The v0.3 plugin registers:

| Hook | Purpose |
|---|---|
| `on_session_start` | Emits session start telemetry. |
| `on_session_end` | Emits session end telemetry. |
| `pre_llm_call` | Emits a content-omitted LLM-call telemetry event. |
| `pre_tool_call` | Emits tool intent metadata, including network/sensitive indicators. |
| `post_tool_call` | Emits tool-result metadata and prompt-injection/malware-test indicators. |

## Default user-local outputs

```text
~/.local/state/skynet-edr/hermes/events.jsonl
~/.local/state/skynet-edr/hermes/skynet-edr-plugin.log
```

Both are created as private user files where the platform allows chmod.

## Logging

The operational log is sanitized. It records plugin lifecycle, hook failures,
and event-write acknowledgements such as event ID, event type, and severity. It
must not contain raw tool parameters, raw tool output, local secret paths, or
credential values.

The log rotates to `.1` when it exceeds `SKYNET_EDR_MAX_LOG_BYTES`.

## Environment variables

| Variable | Purpose |
|---|---|
| `SKYNET_EDR_HERMES_PLUGIN_ENABLED=0` | Disable emission without uninstalling. |
| `SKYNET_EDR_STATE_DIR` | Override base state directory. |
| `SKYNET_EDR_SPOOL_PATH` | Override event JSONL spool path. |
| `SKYNET_EDR_LOG_PATH` | Override plugin log path. |
| `SKYNET_EDR_TENANT` | Tenant/workspace label. |
| `SKYNET_EDR_MAX_FIELD_CHARS` | Bound safe preview field size. |
| `SKYNET_EDR_MAX_LOG_BYTES` | Rotate sanitized log above this size. |
| `HERMES_SESSION_ID` / `HERMES_SESSION` | Optional Hermes-provided trace/session ID used for event correlation; absent these, the plugin generates a process-local UUID fallback. |

## Detection limits

The v0.3 plugin records indicators, not verdicts. `network_indicator` catches
common direct egress forms such as `curl`, `wget`, URLs, `/dev/tcp`, `nc`, and
`ncat`. It does not yet fully classify indirect egress inside arbitrary Python,
SDK, cloud-client, `scp`, `rsync`, `ftp://`, or `s3://` payloads. Treat missed
network indicators as a coverage limitation, not proof of safety.

## Manual ingestion

```bash
skynet-edr events ingest-spool \
  --db /var/lib/skynet-edr/skynet.sqlite \
  --spool ~/.local/state/skynet-edr/hermes/events.jsonl \
  --checkpoint ~/.local/state/skynet-edr/hermes/events.offset
```

## Daemon polling

The daemon can poll the plugin spool through `[spool]` in
`/etc/skynet-edr/config.toml`, but only if the `skynet-edr` service account can
read the user-local spool. That access is an explicit operator decision because
broad home-directory reads increase privacy and credential exposure.

Example for a dedicated lab user:

```toml
[spool]
enabled = true
db = "/var/lib/skynet-edr/skynet.sqlite"
path = "/home/skynet/.local/state/skynet-edr/hermes/events.jsonl"
checkpoint = "/var/lib/skynet-edr/hermes-plugin.offset"
```

## Security boundaries

- No outbound network from the plugin.
- No LLM calls from the plugin.
- No raw tool output in telemetry.
- Sensitive parameters are replaced as whole fields before writing.
- Hook exceptions are logged and swallowed so Hermes remains usable.
- Events are canonical `skynet.event.v0` records and are treated as hostile input
  by Skynet-EDR ingestion.

## v0.4 direction

A later guard-mode plugin can use `pre_tool_call` as an optional policy decision
point:

```text
allow / warn / require approval / deny
```

That is intentionally out of scope for v0.3.
