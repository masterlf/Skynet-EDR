# Operations

This page is the v0.4 operator index for running and validating Skynet-EDR after installation.

Use [Install](INSTALL.md) for package installation and rollback commands. Use [Quickstart](QUICKSTART.md) for the shortest first-run path.

## Operating posture

The current MVP is passive and Linux-first. It emphasizes redacted local evidence, read-only visibility, and high-signal correlation. It should not be treated as a remote containment platform or a replacement for mature EDR/SIEM controls.

## Runtime surfaces

| Surface | Default posture | Documentation |
|---|---|---|
| CLI | Local operator commands | [Local storage and CLI](LOCAL_STORAGE.md) |
| SQLite store | Local event and incident persistence | [Local storage and CLI](LOCAL_STORAGE.md#sqlite-store) |
| Daemon/service | Passive runtime path | [Install](INSTALL.md#what-is-installed) |
| AF_UNIX ingestion | Authenticated, bounded producer transport | [Hermes plugin telemetry](../integrations/hermes/skynet-edr/README.md#continuous-ingestion-authorization) |
| Local HTTP API | Localhost-only read-only visibility | [Local read-only HTTP API and console](LOCAL_HTTP_API.md) |
| MCP server | Read-only visibility for agent runtimes | [Read-only MCP integration](MCP_READ_ONLY.md) |

## First-run checks

After installing or building, run:

```bash
skynet-edr status
sudo -u skynet-edr skynet-edr store init --db /var/lib/skynet-edr/skynet.sqlite
skynet-edr doctor
skynet-edr diagnostics collect --output ./skynet-edr-diagnostics
```

`skynet-edr doctor` checks the packaged operator layout by default:

- `/etc/skynet-edr/config.toml` exists and is readable;
- the local store exists at `/var/lib/skynet-edr/skynet.sqlite` and opens successfully;
- readiness is available through either a loopback-only local API endpoint or a plugin spool file;
- config/API readiness fails closed when the API bind or supplied API target is not loopback.

The doctor command intentionally does not require `rules.d` or `agents.d` directories. Those directories may exist in package layouts for future policy/adaptor drops, but current readiness is based on config, store, and local daemon/API or plugin-spool availability.

`skynet-edr diagnostics collect` creates a private bundle directory (`0700`) and writes private files (`0600`). By default it includes versions, a redacted config summary, and store counts only; it does not export raw events or create a missing database. Operator-supplied logs or service status can be added with `--log-file` and `--service-status-file`; their contents are redacted before writing.

For source checkouts, also run:

```bash
cargo test --workspace --all-features
python3 packaging/scripts/check-docs.py
```

## Evidence handling

Operational evidence must be redacted before it is stored or exposed through CLI/API/MCP output. Do not use real secrets in demos or lab validation.

Safe lab guidance:

- [Linux lab testing](LINUX_LAB_TESTING.md#fake-honeytokens-only)
- [Linux lab testing](LINUX_LAB_TESTING.md#evidence-handling)
- [Threat model](THREAT_MODEL.md#assets)

## Local API and console

The local HTTP API is intended for local visibility only. Keep it bound to localhost unless a later design explicitly adds authentication, authorization, transport security, and threat-model updates.

See [Local read-only HTTP API and console](LOCAL_HTTP_API.md#security-boundary).

## MCP operations

The MVP MCP integration is read-only. Use it to inspect status, incidents, rule metadata, sensor metadata, and config drift. Do not grant it write/containment authority without a separate design and tests.

See [Read-only MCP integration](MCP_READ_ONLY.md#tools).

## Troubleshooting

Start with package and install issues in [Install](INSTALL.md#troubleshooting). For runtime data questions, inspect:

- [Local storage and CLI](LOCAL_STORAGE.md#event-inspection-commands)
- [Local storage and CLI](LOCAL_STORAGE.md#incident-triage-commands)
- [Local read-only HTTP API and console](LOCAL_HTTP_API.md#verification)
- [Hermes event ingestion](HERMES_EVENT_INGESTION.md#verification)

## Upgrade and rollback

Use the upgrade and rollback guidance in [Install](INSTALL.md#upgrade-and-rollback). Package contents and release validation are described in [Release process](RELEASE_PROCESS.md) and [Packaging plan](PACKAGING.md).

## Security operations checklist

Before trusting an operational setup:

- release checksums verified;
- package installed from expected source;
- local store initialized with correct filesystem permissions;
- read-only API exposed only as intended;
- MCP integration remains read-only;
- test fixtures use fake honeytokens only;
- alert output is redacted;
- logs do not contain raw secrets;
- daemon home access is disabled and ingest producers are UID-allowlisted;
- documentation checks and relevant Rust gates pass.
