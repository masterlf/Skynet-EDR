# Concept Architecture

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

### 1. Agent event sensor

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

### 2. Content provenance tracker

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

### 3. MCP/config sensor

Monitors agent configuration for:

- new MCP servers
- shell-based MCP commands
- network egress commands
- unexpected webhooks
- broad tool exposure
- suspicious encoded payloads
- profile/config drift

### 4. Secret/file access sensor

Detects reads or attempted transmission of sensitive paths:

- `.env`
- `auth.json`
- `.ssh/`
- cloud credential files
- password stores
- agent config/memory/skills/cron definitions

### 5. Network sensor

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

### 6. Correlation engine

Combines events into attack stories.

Example:

```text
untrusted GitHub issue contained instruction-like text
→ agent attempted shell command
→ command read ~/.hermes/.env
→ curl POST to direct IP
→ high-severity exfiltration alert
```

### 7. Response layer

Initial response actions:

- send alert
- write incident JSON
- pause task
- require human approval

Future response actions:

- block egress
- disable MCP entry
- quarantine source
- rotate or mark credentials as exposed
- open SIEM/case-management ticket

## Deployment modes

### Passive mode

Reads logs, config, and network metadata. Does not block.

### Guard mode

Can pause tasks and require approval for risky chains.

### Enforcement mode

Can block high-confidence exfiltration and disable malicious runtime entries.

## MVP recommendation

Start with passive mode plus alerts. Add blocking only for very high-confidence detections.
