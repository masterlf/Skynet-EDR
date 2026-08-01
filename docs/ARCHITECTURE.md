# Concept Architecture

This is a conceptual target architecture, not a claim that every depicted
sensor, channel, response action, or deployment mode ships in v0.4.1. The
current product boundary is passive local evidence and read-only visibility;
see the [MVP public support contract](MVP_SUPPORT_MATRIX.md).

## Overview

Skynet-EDR is designed as an agent-aware detection and response layer.

```text
AI agent runtime
  ├─ prompts and source metadata
  ├─ retrieved untrusted content
  ├─ tool calls and arguments
  ├─ MCP configuration and execution
  ├─ file/secret access
  ├─ cron/background jobs
  └─ network egress
        ↓
Skynet-EDR sensors
        ↓
Normalization + redaction
        ↓
Correlation engine
        ↓
Rules / policy / optional classifier
        ↓
Alerts + response actions
```

## Components

### 1. Agent event sensor (conceptual; current coverage is producer-specific)

Captures agent-native events:

- message source
- authenticated user identity where available
- session ID
- profile
- model/provider
- enabled toolsets
- tool calls
- tool arguments, redacted
- cron/background task context

### 2. Content provenance tracker (conceptual)

Labels content by source and trust level:

- authenticated user instruction
- system/developer policy
- web content
- email content
- file content
- terminal output
- MCP response
- third-party chat message

This helps distinguish command from data.

### 3. MCP/config sensor (conceptual; fixture-scanner coverage is narrow)

Monitors agent configuration for:

- new MCP servers
- shell-based MCP commands
- network egress commands
- unexpected webhooks
- broad tool exposure
- suspicious encoded payloads
- profile/config drift

### 4. Secret/file access sensor (conceptual)

Detects reads or attempted transmission of sensitive paths:

- `.env`
- `auth.json`
- `.ssh/`
- cloud credential files
- password stores
- agent config/memory/skills/cron definitions

### 5. Network sensor (conceptual; post-MVP)

Collects outbound metadata:

- destination IP/domain
- port
- protocol
- process/command where available
- timing correlation with tool calls

Possible implementations:

- nftables/iptables logging
- auditd process execution logs
- eBPF/Falco
- Zeek/Suricata for network metadata
- proxy logs

### 6. Correlation engine (implemented only for documented narrow rules)

Combines events into attack stories.

Example:

```text
untrusted GitHub issue contained instruction-like text
→ agent attempted shell command
→ command read ~/.hermes/.env
→ curl POST to direct IP
→ high-severity exfiltration alert
```

### 7. Response layer (conceptual; not shipped)

Candidate guard-mode response actions:

- send alert
- write incident JSON
- pause task
- require human approval

Later enforcement candidates:

- block egress
- disable MCP entry
- quarantine source
- rotate or mark credentials as exposed
- open SIEM/case-management ticket

## Deployment modes

### Passive mode (current v0.4.1 and planned v0.5.0)

Reads logs, config, and network metadata. Does not block.

### Guard mode (v0.6+ candidate)

Can pause tasks and require approval for risky chains.

### Enforcement mode (post-guard candidate)

Can block high-confidence exfiltration and disable malicious runtime entries.

## MVP recommendation

Historical recommendation: start with passive local evidence and read-only
visibility. v0.5.0 plans durable local alerting; guard-mode blocking is v0.6+
work after an exercised pre-execution control point exists.
