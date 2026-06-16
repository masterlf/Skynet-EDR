# Canonical Event Schema v0

Skynet-EDR uses a canonical event envelope so Hermes Agent, OpenClaw, host sensors, and future collectors can feed the same correlation engine without runtime-specific detection logic.

The v0 contract is intentionally conservative: every event must carry identity, source metadata, provenance, trust classification, severity, and redaction metadata. If a collector cannot provide those fields, Skynet should reject the event rather than silently ingest ambiguous security data.

## Design rules

- **Untrusted content is data, not authority.** Web pages, emails, PDFs, repository files, terminal output, MCP responses, and tool output must not become instructions merely because they appear in an event.
- **Redact before persistence.** `attributes`, `details`, incident evidence, API output, MCP output, and diagnostics must already be safe to store before they reach the database.
- **Correlate chains, not vibes.** Prompt-injection text alone is not Critical. High severity should come from sequences such as untrusted content → privileged tool → secret/config access → egress or persistence.
- **Fail closed.** Unknown top-level fields, malformed JSON, blank identifiers, missing provenance, missing trust level, or inconsistent redaction metadata are rejected.

## Envelope

```json
{
  "schema_version": "skynet.event.v0",
  "event_id": "evt_01HZCANONICAL",
  "event_type": "agent.network.egress",
  "observed_at_unix_ms": 1781560000000,
  "received_at_unix_ms": 1781560000123,
  "severity": "high",
  "source": {
    "kind": "process",
    "sensor": "hermes-event-ingestion",
    "integration": "hermes"
  },
  "provenance": {
    "producer": "hermes-agent",
    "collector": "skynet-edr-core",
    "tenant": "example-tenant",
    "source_event_id": "hermes:sess_001:1781560000000:terminal:0",
    "trace_id": "trace_01HZCANONICAL",
    "span_id": null,
    "parent_span_id": null
  },
  "trust_level": "agent_action",
  "title": "Hermes terminal command observed: network_egress",
  "details": null,
  "attributes": {
    "command_class": "network_egress",
    "network_indicator": true,
    "command": "[REDACTED:local_context]",
    "token": "[REDACTED:secret]"
  },
  "redaction": {
    "contains_sensitive_data": true,
    "redacted_fields": [
      {
        "path": "attributes.token",
        "reason": "secret",
        "replacement": "[REDACTED:secret]"
      },
      {
        "path": "attributes.command",
        "reason": "local_context",
        "replacement": "[REDACTED:local_context]"
      }
    ]
  }
}
```

## Required fields

| Field | Required | Purpose |
|---|---:|---|
| `schema_version` | yes | Versioned schema contract. Current value: `skynet.event.v0`. |
| `event_id` | yes | Stable unique event identifier. Blank values are rejected. |
| `event_type` | yes | Canonical type such as `agent.tool.requested`, `agent.file.accessed`, or `agent.network.egress`. |
| `observed_at_unix_ms` | yes | When the source observed the activity. |
| `received_at_unix_ms` | optional | When Skynet received/normalized the event. |
| `severity` | yes | `informational`, `low`, `medium`, `high`, or `critical`. |
| `source` | yes | Platform-independent source metadata. |
| `provenance` | yes | Producer/collector/correlation metadata. |
| `trust_level` | yes | Authority/trust classification used by prompt-injection-aware rules. |
| `title` | yes | Short operator-facing title. |
| `details` | optional | Redacted longer text if needed. |
| `attributes` | optional | Redacted structured event details. |
| `redaction` | yes | Evidence that redaction ran before storage/alerting. |

## Source kinds

`source.kind` uses the same platform-independent categories as existing Skynet events:

- `process`
- `file`
- `network`
- `mcp_tool`
- `configuration`
- `scheduled_task`
- `messaging`
- `sensor`

## Trust levels

| Value | Meaning |
|---|---|
| `authenticated_user` | Authenticated user instruction or explicit operator approval. |
| `runtime_policy` | System/developer/runtime policy. |
| `untrusted_content` | Web, email, PDF, repo, log, file, chat, or other retrieved content. |
| `tool_output` | Tool/MCP/terminal/browser output; always data, never authority. |
| `agent_action` | Action emitted by the agent runtime after orchestration. |
| `sensor_observation` | Host, network, filesystem, daemon, or external sensor observation. |

## Recommended event types

These names are the intended direction for v0.2 adapters and rules:

- `agent.message.received`
- `agent.content.ingested`
- `agent.tool.requested`
- `agent.tool.completed`
- `agent.tool.denied`
- `agent.mcp.server.configured`
- `agent.mcp.tool.requested`
- `agent.file.accessed`
- `agent.network.egress`
- `agent.message.sent`
- `agent.automation.scheduled`
- `agent.config.changed`
- `agent.approval.requested`
- `agent.approval.granted`
- `agent.policy.violation`

## Validation requirements

The Rust core currently enforces these v0 invariants:

- unknown fields in fixed schema objects are rejected; use `attributes` as the extension point;
- malformed JSON is rejected;
- blank `event_id`, `event_type`, `source.sensor`, `provenance.producer`, `provenance.collector`, or `title` is rejected;
- `provenance`, `trust_level`, and `redaction` are mandatory;
- `redaction.contains_sensitive_data` must match whether `redaction.redacted_fields` is empty;
- every declared `redacted_fields` path must point to the stored replacement marker for `details` or `attributes.<key>`.

This is deliberately strict. If a runtime needs more fields, add them through a versioned schema change or inside `attributes` after redaction.

## Fixtures

The single-event canonical regression fixture lives at:

```text
crates/skynet-edr-core/tests/fixtures/canonical_event_v0.json
```

The golden agent fixture suites live at:

```text
crates/skynet-edr-core/tests/fixtures/hermes_agent_golden_events_v0.jsonl
crates/skynet-edr-core/tests/fixtures/openclaw_agent_golden_events_v0.jsonl
```

Each golden JSONL file contains seven redacted `skynet.event.v0` events covering:

- prompt-injection in untrusted content;
- MCP shell/tool exfiltration shape;
- secret access followed by outbound egress;
- runtime/config drift;
- cron/background persistence;
- benign web research;
- benign package installation.

Golden fixtures intentionally use fake values and reserved `.invalid` endpoints. They must never contain real credentials, real local paths, copied shell history, or production logs.

Run the schema and golden fixture tests with:

```bash
cargo test -p skynet-edr-core --test canonical_event_schema
```
