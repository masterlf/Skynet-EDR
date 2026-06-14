# Local Storage and CLI MVP

Skynet-EDR stores redacted endpoint and agent-runtime security data locally before any export or future alert forwarding. The MVP storage surface is deliberately small and auditable.

## SQLite store

The CLI initializes a local SQLite database with:

- `events`: redacted event JSON plus indexed event ID, observation time, severity, source kind, and title.
- `incidents`: redacted incident JSON plus indexed incident ID, timestamps, status, severity, and title.

SQLite is local-first: it avoids an external service dependency, supports endpoint forensic timelines, and keeps the MVP usable on isolated systems.

Initialize a database:

```bash
skynet-edr store init --db ./skynet-edr.sqlite
```

## Ingesting incident JSON

The current CLI ingests one incident JSON document and persists both the incident and its embedded events. Inputs are expected to conform to the platform-independent `Incident` schema. The local storage boundary re-applies the core redaction engine before writing SQLite rows or producing JSONL so caller mistakes do not persist obvious secrets. This is a safety net, not permission to send raw secrets casually.

```bash
skynet-edr events ingest --db ./skynet-edr.sqlite --incident-json ./incident.json
```

This command is intentionally explicit about `--incident-json`; future sensor adapters can add streaming event ingestion without changing the incident schema.

## Event inspection commands

List stored events:

```bash
skynet-edr events list --db ./skynet-edr.sqlite
```

Show one event as pretty JSON:

```bash
skynet-edr events show evt_123 --db ./skynet-edr.sqlite
```

Export all stored events as JSONL:

```bash
skynet-edr events export --db ./skynet-edr.sqlite --format jsonl
```

## Incident triage commands

List stored incidents:

```bash
skynet-edr incidents list --db ./skynet-edr.sqlite
```

Show one incident as pretty JSON:

```bash
skynet-edr incidents show inc_123 --db ./skynet-edr.sqlite
```

Export all incidents as JSONL for SIEM, offline review, or scripted processing:

```bash
skynet-edr incidents export --db ./skynet-edr.sqlite --format jsonl
```

## Security assumptions

- Redaction happens before storage; local storage does not attempt UI-side masking after secrets have already landed.
- Stored payloads preserve complete typed JSON for auditability while duplicating a few indexed fields for efficient local queries.
- JSONL export writes one complete incident per line so downstream tools can process records incrementally.
- The MVP fails loudly on malformed JSON, missing options, unsupported export formats, or unknown commands.
