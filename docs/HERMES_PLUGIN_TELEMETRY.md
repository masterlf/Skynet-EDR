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
local events, incidents, API, MCP handler library
```

The authenticated socket accepts strict, bounded protocol-v3 `producer_health` and `canonical_event` envelopes. Both require an allowlisted runtime role (`gateway`, `dashboard`, `worker`, or `unknown`), the exact lowercase 64-hex installed plugin generation, and an independent cryptographic lowercase 64-hex nonce generated in memory for each plugin process import. The event nested in `canonical_event` remains an unchanged `skynet.event.v0` payload. Kernel DAC and a single accept-time `SO_PEERCRED` capture remain the authorization boundary. The daemon obtains the socket peer's kernel `SO_PEERPIDFD`, verifies it matches the positive credential PID, anchors process-start evidence to an opened `/proc/<pid>` directory, and revalidates both before accepting each v3 frame. Missing kernel support, malformed evidence, peer exit, or changed process identity is rejected without creating an eligible source. Status exposes only the bounded PID/start-tick evidence, never process paths or command lines.

The exact v3 source key is `(authenticated UID, runtime role, plugin generation, runtime nonce)`. A source becomes S3-eligible only after valid v3 health for that exact key and valid kernel identity evidence; event receipt alone is not eligibility. Only a durably `persisted` event advances that source's commit sequence. Duplicate and collision outcomes remain observable without advancing it. Version-1 health, version-2 role/instance health, and raw canonical events remain compatible and observable but are explicitly ineligible for S3. Role, generation, nonce, and event truth are producer assertions inside the authorized UID boundary: same-UID compromise or a malicious root process in the trust domain can still forge them.

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


## Mutation outcome semantics

Mutation-specific events are emitted only from documented after-action hooks with
exact allowlists. A request event is not treated as proof that endpoint state
changed.

For cron scheduling, the only accepted tool name is case-sensitive `cronjob` and
the only accepted actions are case-sensitive `create` and `update`. The
`post_tool_call` result must be an exact string no longer than 16,384 characters,
decode to a JSON object with boolean `success=true`, contain no top-level `error`,
and carry a bounded active `job` object whose identifier matches the create
identifier when present, with `enabled=true`, `state="scheduled"`, and a valid
timezone-aware ISO-8601 `next_run_at`. When Hermes supplies observer status
metadata, `status` must be `ok`
and `error_type` must be absent. Only then does the plugin emit
`agent.automation.scheduled` with the fixed attribute
`persistence_indicator=true`. `list`, `run`, `pause`, `resume`, `remove`, unknown
or near-name tools/actions, failed/malformed/oversized results, and intent-only
hooks do not emit a schedule-mutation event. Duplicate JSON keys, non-standard
JSON constants, and integers exceeding the runtime parser limit also fail dark
without aborting the hook. Prompts, schedules, job identifiers,
delivery targets, scripts, model configuration, and result content are examined
only as bounded in-memory evidence where needed and are not copied into that
event.

`EDR-CONFIG-001`, `EDR-PERSIST-001`, and `EDR-SCOPE-001` remain deliberately dark
for the shipped Hermes plugin. Hermes currently exposes no dedicated structured
config-save outcome to the agent-loop plugin. A successful terminal process or
generic file write does not prove that Hermes parsed, accepted, or loaded the
configuration, so the plugin does not mislabel either as `agent.config.changed`.
The documented `post_approval_response` callback fires after a prompted choice
but before Hermes applies session/permanent approval state; it therefore does not
prove completed scope expansion and is not emitted as `agent.approval.granted`.

## Risk Explorer boundaries

The Hermes dashboard backend exposes only `GET /risks`, `GET /risks/{risk_id}`, `GET /rules`, and optional `GET /status` under Hermes' plugin API mount. It proxies to fixed allowlisted paths on the loopback Skynet-EDR listener at `127.0.0.1:8787` unless `SKYNET_EDR_API_PORT` is set to a valid numeric port. It denies redirects, maps upstream 404 risk detail misses to generic `risk_not_found`, and has no SQLite access, shell/subprocess use, caller-controlled upstream URL, or mutation route. The dashboard validates daemon version, status, risk, ingestion-health, and compiled-rule projections before rendering text. Engine availability and telemetry ingestion health remain separate indicators; the shipped mode is passive.

The Desktop plugin is a read-only UI client for `/skynet-edr/risks`. It uses the backend `ctx.rest('/risks?...')` and `ctx.rest('/risks/<encoded-id>')`, polls no faster than every 10 seconds, renders text only, and does not auto-link URLs or render HTML.

Telemetry events now include optional safe artifact metadata when derivable. Labels are fixed/coarse (`URL content`, `File content`, `Terminal output`), provider values are allowlisted, and locator hashes are computed only from isolated safe locators such as URLs without credentials/query/fragment. Invalid URL ports suppress only the locator hash; the passive telemetry event is still emitted. Raw tool parameters are not persisted: newly emitted `attributes.params_preview` is always `[OMITTED:tool_params]`. When bounded classification detects a sensitive pattern, redaction metadata records that fixed omission without exposing a reason-specific preview marker. Command text, prompts, message bodies, full URLs, repository names, local paths, and secrets are not stored as artifact labels. Canonical attribute keys are fail-closed before legacy persistence: they are 1–128-byte ASCII identifiers (`[A-Za-z0-9][A-Za-z0-9_-]*`), may not contain content changed by redaction, and the complete attribute payload must already be a fixed point of storage sanitization. Sensitive names are accepted only with an already-redacted value and coherent Secret metadata. Redaction paths use exactly one `attributes.` prefix plus one such top-level key. Duplicate, dotted, repeated-prefix, overlong, control-bearing, or synthetic-attribute redaction targets are rejected rather than renamed. During ingestion, `attributes.artifact` is a reserved synthetic key: only the validated top-level artifact may populate stored artifact metadata.

## Default user-local outputs

```text
~/.local/state/skynet-edr/hermes/events-v1.jsonl
~/.local/state/skynet-edr/hermes/events-v1.offset
~/.local/state/skynet-edr/hermes/skynet-edr-plugin.log
```

The fallback, checkpoint, lock, and log are created as private user state where the platform supports the required ownership and mode checks. The versioned fallback is not the legacy unversioned `events.jsonl`. Fallback replay preserves order but may delay telemetry; queue drops, fallback-cap drops, classifier truncation, and candidate overflow mean visibility can be incomplete.

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
| `SKYNET_EDR_PLUGIN_GENERATION` | Required lowercase 64-hex installed plugin generation for protocol-v3 transport. |
| `SKYNET_EDR_RUNTIME_INSTANCE` | Legacy version-2-only non-sensitive instance label; ignored by protocol v3 and ineligible for S3 attribution. |
| `HERMES_SESSION_ID` / `HERMES_SESSION` | Optional Hermes-provided trace/session ID used for event correlation; absent these, the plugin generates a process-local UUID fallback. |

## Detection limits

The v0.4 plugin records indicators, not verdicts. Tool parameters and results are examined by a deterministic structured walker bounded to depth 4, 64 visited items/identities, 4,096 Unicode scalar values per string, and 16,384 examined scalar values per hook side. Only complete bounded strings under exact selected keys are classified; cycles, aliases, unsupported objects, and exceeded limits set `classification_truncated=true` without stringifying hostile objects. A negative indicator on a truncated event is not a safety claim.

`network_indicator` catches
common egress forms such as `curl`, `wget`, URLs, `/dev/tcp`, `nc`, and `ncat`.
For those recognized network operations, the plugin sets `direct_ip=true` when
it validates an explicit IPv4 destination host in an HTTP(S) URL, `/dev/tcp`, or
a simple `curl`, `wget`, `nc`, or `ncat` invocation. Only direct-IP process-class
operations emit `agent.network.egress`; messaging delivery and file-class
operations remain `agent.tool.requested`. An IPv4 literal elsewhere in a URL
path or payload does not qualify. Generic network egress is not enough for
`EDR-NET-001`. Unknown tool names are classified
as MCP tools and emit `agent.mcp.tool.requested`, allowing `EDR-MCP-001` to consume
the packaged telemetry. The plugin does not yet fully classify IPv6 literals or
indirect egress inside arbitrary Python, SDK, cloud-client,
`scp`, `rsync`, `ftp://`, or `s3://` payloads. Safe malware-test markers require
ASCII token boundaries; adjacent prefix/suffix near-matches are not classified.
Unicode case-folding confusables are also rejected. Treat missed network
indicators as a coverage limitation, not proof of safety. Cron outcomes depend on
the exact built-in Hermes `cronjob` result contract; a compromised or overridden
producer can forge these self-reported observations. Config, persistence, and
approval-scope mutation coverage remains absent rather than inferred from intent,
terminal output, generic file-write output, or a pre-persistence approval callback.
Trace/session identifiers and observed timestamps are producer asserted and
pseudonymized by continuous ingestion before storage. Socket UID authorization
permits the producer but does not attest process identity or event truth. The
plugin and correlators are passive: they do not prevent delivery, egress, tool
execution, scheduling, or approval-scope changes.

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

The worker sends an immediate v3 health frame when the enabled plugin registers, before waiting for hook activity, then sends bounded periodic heartbeats and reports after delivery work. It wraps outbound canonical events in the matching v3 source identity and replays only its producer-owned `events-v1.jsonl`, in order. Missing or invalid v3 generation/nonce, unavailable socket transport, and retryable or malformed ACKs preserve the canonical event in the private durable fallback; `events-v1.offset` advances only after a versioned terminal ACK for the matching event ID. The daemon never polls producer homes or the historical `events.jsonl`. Queue, socket, and fallback failures are bounded but can drop newest telemetry; they do not block Hermes. For enrollment, counter semantics, backlog measurement, failure/restart behavior, the harmless canary, and rollback, use [Continuous ingestion operations](OPERATIONS.md#continuous-ingestion-operations).

## Security boundaries

- No outbound network from the plugin.
- No LLM calls from the plugin.
- No raw tool parameters or raw tool output in telemetry.
- Newly emitted parameter previews are always the fixed
  `[OMITTED:tool_params]` marker; sensitive-pattern metadata records that
  omission without exposing raw values or reason-specific preview markers.
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
