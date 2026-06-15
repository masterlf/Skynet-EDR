# Local Read-Only HTTP API

Skynet-EDR exposes a minimal local HTTP API surface for operator visibility. The API is designed as a localhost-only projection over already-redacted local state.

## Security boundary

- Default bind address: `127.0.0.1:8787`.
- Non-loopback bind addresses fail validation.
- Only `GET` is accepted.
- `POST`, `PUT`, `PATCH`, and `DELETE` return `405 method_not_allowed`.
- No response actions, containment actions, sensor starts, config writes, or approval mutations are exposed.
- Local store data is read through the same read-only projection used by the MCP visibility surface.
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

Unknown routes return `404 not_found`.

## Current implementation note

Phase 10 implements the validated configuration and side-effect-free request router. The next console/server phase can attach this router to a tiny localhost listener without changing route semantics.

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
