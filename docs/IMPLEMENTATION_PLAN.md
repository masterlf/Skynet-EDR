# Implementation Plan

## Executive recommendation

Skynet-EDR should be built as a **Linux-first, cross-platform agent runtime security monitor**.

Recommended stack:

- **Rust** for the core daemon, CLI, event pipeline, rule engine, and high-performance sensors.
- **Python** for early Hermes integration, prototypes, tests, and optional detection experiments.
- **YAML/TOML** for human-readable policy and detection rules.
- **SQLite** for local event storage and incident timelines.
- **JSONL** for portable event export and SIEM integration.
- **TypeScript/React** only later, if a dashboard becomes useful.

The short version: **Rust core, Python adapters, YAML rules, SQLite storage.**

This gives us Linux-grade system visibility first, while keeping a realistic path to Windows and macOS.

---

## Why Rust as the main language?

### Benefits

Rust is the best fit for the core because Skynet-EDR will eventually need to handle:

- long-running daemon behavior
- file/process/network telemetry
- safe parsing of untrusted data
- cross-platform binaries
- low memory footprint
- strong concurrency
- minimal runtime dependencies
- Linux eBPF integration paths
- Windows/macOS system APIs later

Security tooling benefits from memory safety. We should not build an EDR-like agent in a language where the detector becomes the vulnerable endpoint. Petit détail, but important.

### Cross-platform story

Rust has credible paths for all target platforms:

- Linux: `aya`, `nix`, audit logs, procfs, nftables logs, journald, fanotify/inotify.
- Windows: `windows` crate, ETW, Event Log, Sysmon ingestion, Windows Filtering Platform later.
- macOS: FSEvents, Unified Logging, Network Extension / EndpointSecurity later, possibly via FFI.

### Packaging

Rust also makes distribution easier:

- static-ish Linux binaries
- systemd service packages
- Homebrew formula for macOS
- Windows service binary later
- GitHub Releases with signed artifacts

---

## Why not Python-only?

Python is excellent for prototypes and integrations, especially with Hermes. But Python-only is weaker for the long-term EDR agent because:

- packaging system daemons is messier
- endpoint telemetry APIs often need native bindings
- performance and memory profile are less predictable
- tamper resistance is harder
- cross-platform service management is less clean

Python should still be used where it shines:

- Hermes plugin/prototype collector
- rule experiments
- integration tests
- incident enrichment
- LLM-assisted classifiers, if added later

---

## Why not Go?

Go is also viable. It has good cross-platform support and simple deployment. But Rust is preferable here because:

- stronger memory-safety guarantees without GC
- better fit for low-level Linux/eBPF work
- more precise control for endpoint sensors
- increasingly strong security-tooling ecosystem

Go would be acceptable for a simpler SaaS-style collector. For an endpoint/agent runtime security tool, Rust is the sharper blade.

---

## Product architecture

```text
                ┌─────────────────────────┐
                │      AI Agent Runtime    │
                │ Hermes / Codex / Claude  │
                └────────────┬────────────┘
                             │
              Agent events / logs / hooks
                             │
┌────────────────────────────▼────────────────────────────┐
│                    Skynet-EDR Core                       │
│                                                          │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│  │  Sensors     │ → │ Normalizer   │ → │ Correlator   │  │
│  └──────────────┘   └──────────────┘   └──────┬───────┘  │
│                                                │          │
│  ┌──────────────┐   ┌──────────────┐   ┌──────▼───────┐  │
│  │ Rule Engine  │ ← │ Local Store  │ ← │ Event Bus    │  │
│  └──────┬───────┘   └──────────────┘   └──────────────┘  │
│         │                                                │
│  ┌──────▼───────┐                                        │
│  │ Response     │  alert / pause / require approval       │
│  └──────────────┘                                        │
└──────────────────────────────────────────────────────────┘
```

---

## Component plan

## 1. Core daemon

Language: **Rust**

Binary name: `skynet-edr`

Responsibilities:

- run as a service/daemon
- load config and rules
- receive events from sensors
- normalize and redact events
- store events locally
- correlate suspicious chains
- emit alerts
- expose local CLI/API for status and incidents

Suggested crates:

- `tokio` for async runtime
- `serde`, `serde_json`, `serde_yaml`, `toml` for config/events
- `tracing`, `tracing-subscriber` for logs
- `clap` for CLI
- `sqlx` or `rusqlite` for SQLite
- `anyhow`, `thiserror` for errors
- `regex`, `aho-corasick` for fast pattern matching
- `reqwest` for outbound alert webhooks, if needed

---

## 2. CLI

Language: **Rust**

Initial commands:

```bash
skynet-edr init
skynet-edr config check
skynet-edr scan
skynet-edr scan --hermes-home ~/.hermes
skynet-edr incidents list
skynet-edr incidents show <id>
skynet-edr rules test
skynet-edr daemon
```

The CLI and daemon should share the same Rust library crate.

---

## 3. Event schema

Format: **JSON / JSONL**

All sensors should produce normalized events like:

```json
{
  "timestamp": "2026-06-14T06:00:00Z",
  "source": "hermes_tool_call",
  "trust_level": "trusted_user|system|untrusted_content|unknown",
  "session_id": "...",
  "profile": "default",
  "event_type": "tool_call|file_access|network_egress|config_change|mcp_entry|alert",
  "actor": "agent|user|process|mcp_server",
  "action": "read_file",
  "target": "~/.hermes/.env",
  "metadata": {},
  "redactions": []
}
```

The event schema should be versioned from day one:

```json
{"schema_version": "0.1"}
```

---

## 4. Rule engine

Language: **Rust core**, rules in **YAML**

Start simple. Do not implement a giant SIEM language in v0.

Example rule:

```yaml
id: EDR-MCP-001
name: MCP shell command with network egress
severity: critical
match:
  event_type: mcp_entry
  command_regex: "(?i)^(bash|sh|zsh|cmd|powershell)(\\.exe)?$"
  args_regex: "(?i)(curl|wget|nc|ncat|socat|/dev/tcp|Invoke-WebRequest|Invoke-RestMethod)"
condition: all
response:
  - alert
  - require_approval
```

Later, consider:

- CEL for expressions
- Rego/OPA if policy complexity grows
- Sigma-style export for SIEM mapping

Do not start with OPA unless needed. It adds power but also complexity.

---

## 5. Storage

Use **SQLite** locally.

Tables:

- `events`
- `incidents`
- `rules`
- `entities`
- `config_snapshots`
- `network_observations`

Why SQLite:

- no external dependency
- easy local forensic timeline
- good enough for endpoint telemetry volume in MVP
- portable across Linux/macOS/Windows

Also support JSONL export:

```bash
skynet-edr incidents export --format jsonl
```

---

## 6. Linux-first sensors

Priority: **Linux first**.

### Phase 1 Linux sensors — no kernel magic

Start with simple, reliable sensors:

1. Hermes config scanner
   - `~/.hermes/config.yaml`
   - `~/.hermes/profiles/*/config.yaml`
   - MCP entries
   - toolsets
   - webhooks

2. Hermes cron scanner
   - `~/.hermes/cron/jobs.json`
   - detect broad toolsets and risky prompts

3. File/config drift scanner
   - hash snapshots of config, skills, plugins, cron
   - detect suspicious additions

4. Log/session scanner
   - parse Hermes logs/session DB where feasible
   - detect suspicious tool call patterns

5. Process execution scanner
   - start with auditd logs if available
   - fallback to shell history/log parsing where available

6. Network egress scanner
   - parse nftables/iptables logs if configured
   - parse conntrack/ss snapshots as fallback

This avoids requiring root/eBPF for the first useful version.

### Phase 2 Linux sensors — stronger telemetry

Add optional privileged sensors:

- auditd integration
- fanotify/inotify for sensitive paths
- eBPF with `aya`
- process exec monitoring
- socket/connect monitoring
- DNS query observation

Do this only after the passive MVP is useful.

---

## 7. Hermes integration

Initial Hermes support can be hybrid:

### Rust scanner

The Rust daemon scans Hermes state:

- config
- profiles
- cron jobs
- skills
- plugins
- logs
- session metadata where safe

### Python helper / plugin later

A Python adapter can emit richer Hermes-native events:

- tool call start/end
- tool arguments after redaction
- prompt provenance labels
- current session and source channel
- task/cron metadata

This Python piece should be optional. The core should not depend on Hermes internals forever.

---

## 8. Windows support plan

Priority: after Linux MVP.

Use Rust core with Windows-specific sensors behind feature flags.

Possible telemetry sources:

- Windows Event Log
- Sysmon logs
- ETW
- PowerShell script block logs
- Windows Filtering Platform later
- filesystem watcher for config/secret paths

Initial Windows MVP:

- config scanning
- file drift monitoring
- Sysmon/Event Log ingestion
- process command-line detection
- network connection event ingestion if Sysmon is present

Avoid writing a kernel driver. That is a swamp. A very expensive swamp with mosquitoes.

---

## 9. macOS support plan

Priority: after Linux and basic Windows.

Possible telemetry sources:

- FSEvents for file/config changes
- Unified Logging ingestion
- EndpointSecurity framework later
- Network Extension later

Initial macOS MVP:

- config scanning
- file drift monitoring
- process/log ingestion where available
- network egress via logs or optional local proxy mode

EndpointSecurity is powerful but requires entitlements and packaging complexity. Treat it as later-stage.

---

## 10. Alerting

Initial alert targets:

- stdout / CLI
- JSONL file
- webhook
- email
- Discord/Telegram via configured webhook or Hermes bridge later

Alert format must include:

- severity
- rule ID
- source
- origin
- evidence snippet, redacted
- attempted action
- affected assets
- network destination
- action taken
- recommended next steps

---

## 11. Repository structure

Recommended initial layout:

```text
skynet-edr/
├── Cargo.toml
├── crates/
│   ├── skynet-core/
│   ├── skynet-cli/
│   ├── skynet-sensors/
│   ├── skynet-rules/
│   └── skynet-store/
├── integrations/
│   └── hermes/
│       ├── README.md
│       └── python/
├── rules/
│   ├── mcp.yml
│   ├── secrets.yml
│   ├── prompt-injection.yml
│   └── network.yml
├── docs/
│   ├── GOALS.md
│   ├── THREAT_MODEL.md
│   ├── ARCHITECTURE.md
│   ├── DETECTION_RULES.md
│   └── IMPLEMENTATION_PLAN.md
├── examples/
│   ├── config.toml
│   └── events/
└── tests/
```

For the first code milestone, one Rust workspace is enough. Do not over-split until modules stabilize.

---

## 12. Build milestones

### Milestone 0 — Documentation and schemas

Deliverables:

- event schema
- alert schema
- config schema
- initial rule format
- example incidents

### Milestone 1 — Passive Hermes scanner

Deliverables:

- Rust CLI
- scan Hermes config/profiles/cron
- detect suspicious MCP entries
- detect risky cron jobs
- output JSON alerts

### Milestone 2 — Local store and incident timeline

Deliverables:

- SQLite storage
- incident IDs
- `incidents list/show`
- JSONL export

### Milestone 3 — Linux telemetry MVP

Deliverables:

- file drift monitor
- sensitive path watcher
- process command-line ingestion from auditd or logs
- network egress ingestion from nftables/auditd logs

### Milestone 4 — Correlation engine

Deliverables:

- correlate secret access + egress
- correlate untrusted content + tool call
- correlate MCP config change + process/network behavior

### Milestone 5 — Alerting and response

Deliverables:

- webhook/email alerting
- human-readable incident report
- optional task pause/approval integration for Hermes

### Milestone 6 — Windows/macOS basic support

Deliverables:

- Windows Event Log/Sysmon ingestion
- macOS FSEvents/log ingestion
- platform-specific config paths
- cross-platform release artifacts

---

## 13. Testing strategy

### Unit tests

- rule matching
- redaction
- path classification
- event normalization
- config parsing

### Integration tests

- sample Hermes configs
- malicious MCP fixtures
- cron job fixtures
- synthetic event chains

### Golden test fixtures

Maintain fixtures for known attacks:

- MCP `cat ~/.hermes/.env | curl`
- prompt injection in email
- prompt injection in GitHub issue
- secret read followed by direct-IP egress
- cron job exfiltration

### Cross-platform CI

Use GitHub Actions matrix:

- Ubuntu latest first
- Windows latest later
- macOS latest later

---

## 14. Security engineering rules

- Redact secrets before logs and alerts.
- Treat all parsed input as hostile.
- Avoid shelling out where possible.
- Prefer structured parsers over regex-only parsing for config formats.
- Keep response actions explicit and auditable.
- Do not block by default until detection quality is proven.
- Do not collect full email/web/document bodies by default.

---

## Final decision

Use this stack:

```text
Core: Rust
Hermes adapter/prototypes: Python
Rules: YAML
Config: TOML
Storage: SQLite
Export: JSONL
Dashboard: optional later, TypeScript/React
```

Development priority:

```text
1. Linux passive scanner
2. Linux runtime telemetry
3. Hermes event integration
4. Alerting/response
5. Windows basic telemetry
6. macOS basic telemetry
7. Optional dashboard and enterprise integrations
```
