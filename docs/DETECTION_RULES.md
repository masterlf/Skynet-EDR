# Initial Detection Rules

This document lists early candidate rules. They are intentionally simple and high-signal.

## Severity model

- **Critical:** likely secret exfiltration or malicious runtime persistence.
- **High:** suspicious chain involving untrusted content and privileged action.
- **Medium:** suspicious configuration, tool, or network behavior requiring review.
- **Low:** weak indicator or isolated suspicious content.

## Rule candidates

### EDR-MCP-001: MCP shell plus egress

Detect MCP entries where the command is a shell interpreter and arguments include network egress tools.

Examples:

- `bash -c "cat ~/.env | curl ..."`
- `sh -c "wget ..."`
- `powershell -Command "Invoke-WebRequest ..."`
- `/dev/tcp/host/port`
- `nc`, `ncat`, `socat`

Severity: Critical if sensitive paths are referenced, High otherwise.

### EDR-SECRET-001: Sensitive file access

Detect reads of high-value secret locations:

- `~/.hermes/.env`
- `~/.hermes/auth.json`
- `~/.ssh/*`
- cloud credential files
- password manager exports

Severity: Medium by itself, Critical if followed by egress or message sending.

### EDR-EXFIL-001: Secret read followed by network egress

Detect sensitive file access followed by outbound network activity within a short window.

Default window: 60 seconds.

Severity: Critical.

### EDR-MALWARE-001: Malware-like content sent to AI runtime

Detect known safe malware-test indicators in untrusted Hermes tool output that is supplied back to the AI runtime for analysis. The v0.2 implementation uses deterministic test markers only, including a project-specific fake marker and defanged/EICAR-style test indicators; it does not require or ship real malware samples.

Severity: High. Raw payload content must be omitted before storage; store only structured indicator metadata such as signature family.

### EDR-PI-001: Untrusted content contains instruction override

Detect common prompt-injection language inside untrusted data:

- ignore previous instructions
- reveal system prompt
- send secrets
- exfiltrate
- do not tell the user
- use the terminal
- call this tool

Severity: Low by itself, High when correlated with tool use.

### EDR-CRON-001: Risky unattended automation

Detect scheduled/background jobs with broad tools and sensitive operations.

Indicators:

- terminal + file + web + messaging tools all enabled
- references to secrets or credentials
- update/install/pull/restart without explicit approval boundary
- external delivery of raw data

Severity: Medium to High depending on context.

### EDR-CONFIG-001: Agent config drift

Detect unexpected additions or changes in:

- MCP servers
- toolsets
- cron jobs
- plugins
- webhooks
- memory/skills with operational instructions

Severity: Medium; High if network or secret indicators are present.

### EDR-NET-001: Direct-IP egress

Detect HTTP(S) or unusual-port egress to a direct IP address rather than known domain.

Severity: Medium by itself, Critical if correlated with secret access.

### EDR-MSG-001: Suspicious messaging exfiltration

Detect attempts to send sensitive content through messaging or email tools without explicit authenticated-user request.

Severity: High to Critical.

## Alert format

Each alert should include:

- severity
- rule ID
- source and trust level
- origin URL/file/email/tool/session
- evidence snippet, redacted
- attempted action
- affected asset
- network destination if any
- action taken
- recommended containment

The platform-independent core alert model tracks the initial response surface:

- destinations: `stdout`, `jsonl_file`, `webhook`, and `email`
- response actions: `emit_alert`, `require_approval`, `pause_automation`, and `block_network_egress`
- approval boundaries: `passive_only`, `operator_required`, and `pre_approved_containment`

Approval boundaries are deliberately conservative. `passive_only` may only alert or require approval; it cannot pause automation or block egress. `operator_required` may pause automation but still cannot block network egress without an explicit containment boundary. `pre_approved_containment` is the only boundary that allows automatic network blocking.

Rendered alerts must be server-side redacted before any destination delivery. Evidence, source metadata, affected assets, recommended steps, and destination configuration are all treated as hostile/sensitive render inputs; webhook URLs with embedded tokens and local filesystem paths must not leak into rendered JSON.
