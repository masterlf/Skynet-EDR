# Hermes Plugin Telemetry

Skynet-EDR v0.4 ships a passive Hermes Agent plugin. The plugin is the preferred
non-invasive live telemetry path for Hermes hosts.

## Positioning

The plugin is a sensor, not an inline control point. It does not block, approve,
rewrite, or delay Hermes actions in v0.4. Blocking/policy enforcement remains a
future guard-mode feature.

```text
Hermes lifecycle hooks
        ↓
skynet-edr Hermes plugin
        ↓
bounded in-memory queue → producer-owned AF_UNIX forwarder
        ↓
authenticated daemon transaction (event + correlation + receipt)
        ↘ private events-v1.jsonl fallback on retryable failure
        ↓
local events, incidents, API, MCP visibility
```

The same authenticated socket accepts strict, bounded `producer_health` control frames. Version 2 adds only an allowlisted runtime role (`gateway`, `dashboard`, `worker`, or `unknown`) and a 64-byte lowercase alphanumeric/hyphen process-instance identifier to the version-1 checkpoint/backlog counters and fixed transport state. Kernel DAC and `SO_PEERCRED` remain authoritative; role and instance are attribution within an already-authorized UID, never authentication. Legacy version-1 frames remain observable but cannot satisfy an explicitly required role. Paths, labels, event payloads, commands, PIDs, and secrets are neither accepted nor exposed.

## Installed files

Packages place the plugin template and installer here:

```text
/usr/share/skynet-edr/hermes-plugin/skynet-edr/plugin.yaml
/usr/share/skynet-edr/hermes-plugin/skynet-edr/__init__.py
/usr/share/skynet-edr/hermes-plugin/skynet-edr/dashboard/manifest.json
/usr/share/skynet-edr/hermes-plugin/skynet-edr/dashboard/plugin.js
/usr/share/skynet-edr/hermes-plugin/skynet-edr/dashboard/plugin_api.py
/usr/share/skynet-edr/hermes-plugin/skynet-edr/desktop/plugin.js
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
~/.hermes/desktop-plugins/skynet-edr/plugin.js
```

If Hermes uses opt-in plugins, enable it and restart every reviewed Hermes gateway/dashboard runtime so the Python backend is mounted. Installing bytes is not enrollment proof: an already-running process continues using the code it loaded previously. The installer deliberately does not restart its parent or any service. The Desktop renderer can hot-reload the disk plugin, but the backend allow-list and Python hook process still need their normal approved reload/restart path:

```bash
hermes plugins enable skynet-edr
```

## Hooks

The v0.4 plugin registers:

| Hook | Purpose |
|---|---|
| `on_session_start` | Emits session start telemetry. |
| `on_session_end` | Emits session end telemetry. |
| `pre_llm_call` | Emits a content-omitted LLM-call telemetry event. |
| `pre_tool_call` | Emits tool intent metadata, including network/sensitive indicators. |
| `post_tool_call` | Emits tool-result metadata and prompt-injection/malware-test indicators. |

## Risk Explorer boundaries

The Hermes dashboard backend exposes only `GET /risks`, `GET /risks/{risk_id}`, and optional `GET /status` under Hermes' plugin API mount. It proxies to the fixed loopback Skynet-EDR listener at `127.0.0.1:8787` unless `SKYNET_EDR_API_PORT` is set to a valid numeric port. It denies redirects, maps upstream 404 risk detail misses to generic `risk_not_found`, and has no SQLite access, shell/subprocess use, caller-controlled upstream URL, or mutation route.

The Desktop plugin is a read-only UI client for `/skynet-edr/risks`. It uses the backend `ctx.rest('/risks?...')` and `ctx.rest('/risks/<encoded-id>')`, polls no faster than every 10 seconds, renders text only, and does not auto-link URLs or render HTML.

Telemetry events now include optional safe artifact metadata when derivable. Labels are fixed/coarse (`URL content`, `File content`, `Terminal output`), provider values are allowlisted, and locator hashes are computed only from isolated safe locators such as URLs without credentials/query/fragment. Invalid URL ports suppress only the locator hash; the passive telemetry event is still emitted. Raw tool parameters are not persisted: `attributes.params_preview` is either a fixed redaction marker for known sensitive patterns or `[OMITTED:tool_params]`. Command text, prompts, message bodies, full URLs, repository names, local paths, and secrets are not stored as artifact labels. During ingestion, `attributes.artifact` is a reserved synthetic key: only the validated top-level artifact may populate stored artifact metadata.

## Default user-local outputs

```text
~/.local/state/skynet-edr/hermes/events-v1.jsonl
~/.local/state/skynet-edr/hermes/events-v1.offset
~/.local/state/skynet-edr/hermes/skynet-edr-plugin.log
```

The fallback, checkpoint, lock, and log are created as private user state where the platform supports the required ownership and mode checks. The versioned fallback is not the legacy unversioned `events.jsonl`.

## Logging

The operational log is sanitized. It records plugin lifecycle and hook failures,
but the normal hook path does not write event acknowledgements. It must not
contain raw tool parameters, raw tool output, local secret paths, or credentials.

The log rotates to `.1` when it exceeds `SKYNET_EDR_MAX_LOG_BYTES`.

## Environment variables

| Variable | Purpose |
|---|---|
| `SKYNET_EDR_HERMES_PLUGIN_ENABLED=0` | Disable emission without uninstalling. |
| `SKYNET_EDR_STATE_DIR` | Override base state directory. |
| `SKYNET_EDR_INGEST_SOCKET` | Override local AF_UNIX ingest socket. |
| `SKYNET_EDR_EVENT_QUEUE_SIZE` | Bound in-memory event queue. |
| `SKYNET_EDR_SOCKET_TIMEOUT_MS` | Bound worker socket operations. |
| `SKYNET_EDR_SPOOL_PATH` | Override versioned fallback JSONL path. |
| `SKYNET_EDR_CHECKPOINT_PATH` | Override producer-owned replay checkpoint. |
| `SKYNET_EDR_FALLBACK_MAX_BYTES` | Bound fallback bytes (hard ceiling 256 MiB). |
| `SKYNET_EDR_LOG_PATH` | Override plugin log path. |
| `SKYNET_EDR_TENANT` | Tenant/workspace label. |
| `SKYNET_EDR_MAX_FIELD_CHARS` | Bound safe preview field size. |
| `SKYNET_EDR_MAX_LOG_BYTES` | Rotate sanitized log above this size. |
| `HERMES_RUNTIME_ROLE` | Fixed runtime role: `gateway`, `dashboard`, `worker`, or `unknown`; any other value fails safely to `unknown`. |
| `SKYNET_EDR_RUNTIME_INSTANCE` | Optional non-sensitive lowercase alphanumeric/hyphen instance ID (1–64 bytes); invalid values use a process-local random identifier. |
| `HERMES_SESSION_ID` / `HERMES_SESSION` | Optional Hermes-provided trace/session ID used for event correlation; absent these, the plugin generates a process-local UUID fallback. |

## Detection limits

The v0.4 plugin records indicators, not verdicts. `network_indicator` catches
common egress forms such as `curl`, `wget`, URLs, `/dev/tcp`, `nc`, and `ncat`.
For those recognized network operations, the plugin sets `direct_ip=true` when
it validates an explicit IPv4 destination host in an HTTP(S) URL, `/dev/tcp`, or
a simple `curl`, `wget`, `nc`, or `ncat` invocation, then emits
`agent.network.egress`; an IPv4 literal elsewhere in a URL path or payload does
not qualify. Generic network egress is not enough for `EDR-NET-001`. Unknown tool names are classified
as MCP tools and emit `agent.mcp.tool.requested`, allowing `EDR-MCP-001` to consume
the packaged telemetry. The plugin does not yet fully classify IPv6 literals or
indirect egress inside arbitrary Python, SDK, cloud-client,
`scp`, `rsync`, `ftp://`, or `s3://` payloads. Treat missed network indicators
as a coverage limitation, not proof of safety.

## Legacy manual ingestion

```bash
skynet-edr events ingest-spool \
  --db /var/lib/skynet-edr/skynet.sqlite \
  --spool ~/.local/state/skynet-edr/hermes/events-v1.jsonl \
  --checkpoint ~/.local/state/skynet-edr/hermes/manual-import.offset
```

## Continuous daemon ingestion

The packaged daemon listens on a private AF_UNIX socket and does not read user
homes (`ProtectHome=true`). Kernel socket DAC and `SO_PEERCRED` are separate
checks: add a reviewed producer to `skynet-edr-ingest` and allowlist its numeric
UID. Root remains denied unless explicitly enabled.

```toml
[ingest]
enabled = true
socket = "/run/skynet-edr-ingest/ingest.sock"
socket_group = "skynet-edr-ingest"
allowed_uids = [1000] # replace with the reviewed producer UID
allow_root = false
```

The worker replays only its producer-owned `events-v1.jsonl`, in order, and advances `events-v1.offset` only after a versioned terminal ACK for the matching event ID. The daemon never polls producer homes or the historical `events.jsonl`. Queue, socket, and fallback failures are bounded but can drop newest telemetry; they do not block Hermes. For enrollment, counter semantics, backlog measurement, failure/restart behavior, the harmless canary, and rollback, use [Continuous ingestion operations](OPERATIONS.md#continuous-ingestion-operations).

## Security boundaries

- No outbound network from the plugin.
- No LLM calls from the plugin.
- No raw tool parameters or raw tool output in telemetry.
- Sensitive parameter previews are replaced as whole fields before writing;
  otherwise parameter previews are omitted with `[OMITTED:tool_params]`.
- Hook exceptions are logged and swallowed so Hermes remains usable.
- Events are canonical `skynet.event.v0` records and are treated as hostile input
  by Skynet-EDR ingestion.

## Future guard-mode direction

A later guard-mode plugin can use `pre_tool_call` as an optional policy decision
point:

```text
allow / warn / require approval / deny
```

That is intentionally out of scope for the passive v0.3 and v0.4 milestones.
