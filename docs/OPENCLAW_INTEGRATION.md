# OpenClaw Integration

OpenClaw support should use the same canonical event contract as Hermes support. Skynet-EDR detection logic must remain runtime-independent: OpenClaw adapters normalize runtime activity into `skynet.event.v0`, and the core rule/correlation engine evaluates those events exactly like Hermes events.

See [Canonical Event Schema](EVENT_SCHEMA.md) for the envelope definition.

## MVP adapter requirements

An OpenClaw adapter should emit redacted events for:

- authenticated user messages and operator approvals;
- untrusted content ingested from web, files, repositories, email, chat, terminal output, or MCP/tool output;
- tool requested/completed/denied events;
- MCP server configuration and MCP tool calls;
- file/secret access where the runtime can observe it;
- outbound network, browser, messaging, or email actions;
- scheduled/background automation;
- runtime configuration, memory, skill, plugin, and profile drift.

## Required event properties

Every OpenClaw event must include:

- `schema_version = "skynet.event.v0"`;
- stable `event_id`;
- canonical `event_type`;
- `source.kind` and `source.sensor`;
- `provenance.producer = "openclaw"` or a more specific OpenClaw component;
- `provenance.collector` identifying the Skynet adapter;
- `trust_level` distinguishing authority from untrusted data;
- `redaction` metadata proving sensitive content was handled before storage.

## Boundary rules

- OpenClaw adapter code should not contain detection rules.
- MCP/tool/terminal output is always untrusted data.
- Runtime-specific fields belong in `attributes` after redaction.
- If a required field is unavailable, the adapter should fail clearly rather than emitting ambiguous security telemetry.

## Verification

Initial OpenClaw integration is considered usable when a third party can:

1. install Skynet-EDR;
2. enable the OpenClaw adapter from public docs;
3. ingest a benign OpenClaw fixture;
4. ingest a malicious fixture showing secret access followed by egress;
5. see the expected redacted incident without raw secret leakage.
