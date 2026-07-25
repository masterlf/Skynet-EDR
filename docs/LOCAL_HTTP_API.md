# Local Read-Only HTTP API and Console

Skynet-EDR exposes a minimal local HTTP API surface for operator visibility. The API is designed as a localhost-only projection over already-redacted local state.

Phase 11 adds a tiny HTML console router on top of the same Phase 10 API projection. It is a read-only visibility surface, not a response console.

## Security boundary

- Default bind address: `127.0.0.1:8787`.
- Non-loopback bind addresses fail validation.
- Only `GET` is accepted.
- `POST`, `PUT`, `PATCH`, and `DELETE` return `405 method_not_allowed`.
- No response actions, containment actions, sensor starts, config writes, or approval mutations are exposed.
- Local store data is read through the same read-only projection used by the MCP visibility surface.
- Daemon startup performs one explicit writable initialization/migration phase for the configured active SQLite store before spool ingestion and before listener startup, then drops that writable handle. That writable phase converts the local store to rollback-journal (`DELETE`) mode and checkpoints existing WAL stores so committed rows are preserved before read-only serving begins.
- The HTTP listener startup preflights the configured SQLite store read-only and fails closed on missing, empty, WAL-mode, or incompatible schema without creating a DB, WAL, SHM, schema, or indexes. Active HTTP requests inspect the SQLite header before opening SQLite, then use a read-only, `query_only` connection. `/api/status`, `/api/v1/risks`, and `/api/v1/risks/<id>` are the bounded Risk Explorer paths.
- The v0.4 local operator store intentionally prefers a verifiable no-sidecar read path over WAL reader/writer concurrency. Readers produce no `-wal`/`-shm` sidecars; short writer/read contention may return a generic unavailable response rather than weakening the read-only posture.
- Legacy investigation endpoints such as `/api/incidents`, `/api/incidents/<id>`, and `/api/config-drift` remain compatibility visibility surfaces and may materialize stored collections or full stored incidents; they should not be treated as fully bounded Risk Explorer APIs.
- Missing incidents return `404 not_found`, not a storage error.

This API is an operator visibility interface, not a control plane.

## Initial routes

| Route | Method | Purpose |
|---|---:|---|
| `/api/status` | `GET` | Product/runtime status and local store counts. |
| `/api/incidents` | `GET` | Compact incident summaries. |
| `/api/incidents/<id>` | `GET` | One redacted stored incident. |
| `/api/rules` | `GET` | Built-in rule metadata. |
| `/api/sensors` | `GET` | Available sensor metadata. |
| `/api/config-drift` | `GET` | Redacted config drift findings. |
| `/api/v1/risks?limit=<n>&offset=<n>` | `GET` | Bounded Hermes/Desktop risk list projection. |
| `/api/v1/risks/<id>` | `GET` | One risk detail with allowlisted evidence only. The `<id>` path segment is split while still encoded, then percent-decoded once as opaque incident-id data. |

## Risk API v1

Risk responses use `schema_version: skynet.risk.v1` and always include `read_only: true`. Pagination defaults are `limit=50` and `offset=0`; `limit` is constrained to `1..=100` and `offset` to `0..=10000`. Malformed, duplicate, unknown, or out-of-range query parameters return structured `400 bad_request` with `read_only: true`.

Risk detail IDs are bounded before and after decoding (`<=768` encoded bytes and `<=256` decoded Unicode scalar values). Malformed percent escapes, invalid UTF-8, and literal raw `/` in the opaque-id tail return structured `400 bad_request`. Encoded `/`, `?`, `#`, unicode, and `:` are accepted only as opaque ID data after route selection; they are never interpreted as route separators or filesystem paths.

Risk list pagination is bounded in SQLite using `updated_at_unix_ms DESC, id ASC` order before risk projection. The API still caps `limit` at 100 and `offset` at 10,000.

Risk detail evidence is an allowlisted projection: event id, timestamp, severity, event type, deterministic event label derived from canonical event type, sensor, explicit typed artifact metadata or conservative unknown artifact fallback, trust level, rule id, redaction count, and known boolean/enum triage indicators. Risk titles are deterministic labels derived from allowlisted rule IDs, and risk summaries are generated from trusted scalar metadata only. Artifact labels are recomputed from fixed `ArtifactKind` constants; stored `display_label` is not trusted. Provider, locator hash, trust level, event type, rule id, sensor, integration, and trace IDs are validated before exposure. It does not expose arbitrary attributes, raw details, stored incident titles/summaries, stored event titles, message/email bodies, prompt text, command text, raw URLs, repository locators, local paths, credentials, or hostile content.

## Console routes

The console routes return `text/html; charset=utf-8` and are rendered from the API router output, with JSON evidence HTML-escaped before display.

| Route | Method | Purpose |
|---|---:|---|
| `/console` | `GET` | Local console home with status and incident timeline. |
| `/console/incidents/<id>` | `GET` | Redacted evidence view for one incident. |
| `/console/rules` | `GET` | Rules status page. |
| `/console/sensors` | `GET` | Sensors status page. |
| `/console/config-drift` | `GET` | Config-drift status page. |

The console has no JavaScript dependency, no response-action routes, and no direct raw evidence reads.

Unknown routes return `404 not_found`.

## Current implementation note

Phase 10 implements the validated configuration and side-effect-free request router. Phase 11 adds the side-effect-free HTML console router; a future listener can attach both routers to the same validated localhost-only bind without changing route semantics.

## Verification

Primary tests:

```bash
cargo test -p skynet-edr-daemon --test http_api --all-features
```

Full Rust gate:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```
