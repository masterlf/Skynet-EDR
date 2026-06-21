# Integrations

This page is the v0.3 integration index. It points to the runtime-specific docs and states the shared contract all integrations must respect.

The common event contract is [Canonical event schema](EVENT_SCHEMA.md). Integration code should normalize into `skynet.event.v0` instead of making the correlation engine learn every runtime dialect. Cute architecture trick: fewer dialects, fewer gremlins.

## Integration principles

- Normalize before correlation.
- Preserve provenance and trust level.
- Redact before persistence, alerting, API output, or MCP output.
- Treat tool output and retrieved content as data, not instruction authority.
- Prefer read-only visibility for operator integrations until containment semantics are explicit and tested.
- Fail closed when required schema fields, redaction metadata, or trust classification are missing.

## Supported and planned surfaces

| Surface | Status | Purpose | Details |
|---|---|---|---|
| Hermes plugin telemetry | v0.3 live passive path | Observe Hermes lifecycle hooks, emit canonical JSONL, and write sanitized plugin logs | [Hermes plugin telemetry](HERMES_PLUGIN_TELEMETRY.md) |
| Hermes trace ingestion | MVP/import path | Normalize Hermes/AI-agent traces into canonical events | [Hermes event ingestion](HERMES_EVENT_INGESTION.md) |
| Read-only MCP visibility | MVP path | Let Hermes inspect Skynet status, incidents, rules, sensors, and config drift | [Read-only MCP integration](MCP_READ_ONLY.md) |
| OpenClaw adapter | Adapter contract | Map OpenClaw-style observations into canonical event properties | [OpenClaw integration](OPENCLAW_INTEGRATION.md) |
| Local HTTP API and console | MVP visibility | Localhost-only read-only visibility for status/events/incidents | [Local read-only HTTP API and console](LOCAL_HTTP_API.md) |
| CLI storage/import/export | MVP operator path | Initialize local store and inspect events/incidents | [Local storage and CLI](LOCAL_STORAGE.md) |

## Required event properties

Every integration that emits security events must provide or derive:

- `schema_version`
- `event_id`
- `event_type`
- observed timestamp
- severity
- source metadata
- provenance metadata
- trust level
- operator-facing title
- redaction metadata

See [Canonical event schema](EVENT_SCHEMA.md#required-fields) for field-level requirements.

## Hermes ingestion

Hermes integration should focus on trace shapes that explain agent behavior:

- user/developer/runtime messages with authority labels;
- retrieved or untrusted content;
- tool request/completion events;
- MCP configuration and MCP tool activity;
- file/config/secret access;
- network, messaging, and scheduled/background actions.

Implementation details and verification are in [Hermes event ingestion](HERMES_EVENT_INGESTION.md#verification).

## MCP visibility

The current MCP direction is read-only. Skynet-EDR may expose status and redacted evidence to an agent runtime, but MCP output remains untrusted data from the consuming agent's perspective. Do not turn the MVP MCP server into a containment interface without new threat modeling and tests.

See [Read-only MCP integration](MCP_READ_ONLY.md#security-boundary).

## Local HTTP visibility

The local HTTP API and console are localhost-only read surfaces. They exist for operator visibility, not remote administration.

See [Local read-only HTTP API and console](LOCAL_HTTP_API.md#security-boundary).

## Adapter acceptance checklist

Before calling an integration ready:

- events validate against [Canonical event schema](EVENT_SCHEMA.md#validation-requirements);
- fixtures cover malformed or hostile input;
- sensitive fields are redacted before storage;
- event provenance distinguishes authenticated user instruction from untrusted content and tool output;
- local API/MCP/CLI output does not leak raw secrets;
- detection behavior is covered through [Detections](DETECTIONS.md) and relevant tests.
