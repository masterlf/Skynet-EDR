# Detection Rules

This document distinguishes shipped deterministic rules from roadmap candidates. Implemented rules are intentionally simple, high-signal, and passive-safe: they create explainable matches from redacted canonical events but do not block, pause, or mutate runtime behavior by themselves.

## Severity model

- **Critical:** likely secret exfiltration or malicious runtime persistence.
- **High:** suspicious chain involving untrusted content and privileged action.
- **Medium:** suspicious configuration, tool, or network behavior requiring review.
- **Low:** weak indicator or isolated suspicious content.

## Implemented deterministic canonical sequence rules

The canonical sequence engine evaluates ordered `event_type` + `trust_level` predicates, optional redacted `attributes.*` predicates, a fixed time window, and either same-session or same-trace joins. Events are sorted by `observed_at_unix_ms` then `event_id` so matching is deterministic. Rules fail closed when structurally ambiguous.

The built-in AI-agent sequence pack currently ships these rules:

| Rule | Implemented behavior | Severity |
|---|---|---|
| EDR-MCP-001 | Untrusted prompt-injection content followed by an MCP tool request with `network_indicator=true` in the same trace. | High |
| EDR-CONFIG-001 | Untrusted prompt-injection content followed by an agent configuration change with `approval_required=false`. | High |
| EDR-CRON-001 | Untrusted prompt-injection content followed by automation scheduling with `persistence_indicator=true`. | High |
| EDR-PI-001 | Untrusted prompt-injection content followed by `agent.tool.requested` carrying both `network_indicator=true` and `sensitive_access=true`. Text-only prompt injection does not match. | High |
| EDR-MSG-001 | Untrusted prompt-injection content followed by `agent.tool.requested` carrying both `delivery_indicator=true` and `sensitive_access=true`. It does not evaluate an authenticated-user-request policy. | High |
| EDR-NET-001 | Untrusted prompt-injection content followed by network egress with explicit `attributes.direct_ip=true`. | High |
| EDR-SCOPE-001 | Untrusted prompt-injection content followed by approval/scope expansion. | High |
| EDR-PERSIST-001 | Untrusted prompt-injection content followed by an agent persistence configuration change. | High |

These rules deliberately do not duplicate `EDR-EXFIL-001`; secret-read plus egress remains handled by the existing Hermes EXFIL correlator.

## Rule semantics reference

The following rule notes provide operator-facing semantics. `EDR-EXFIL-001` and `EDR-MALWARE-001` are implemented by narrow Hermes correlators in authenticated continuous ingestion and the explicit normalized-trace importer rather than by the generic canonical sequence pack.

### EDR-MCP-001: MCP network tool request after instructional attack

The shipped sequence requires untrusted content with
`instruction_authority=false` and `contains_instructional_attack=true`, followed
within 60 seconds and in the same trace by `agent.mcp.tool.requested` with
`network_indicator=true`.

Severity: High. The current rule does not require a shell interpreter, direct IP,
or sensitive-path indicator; those may be represented by other correlated rules.

### EDR-SECRET-001: Sensitive file access

Detect reads of high-value secret locations:

- `~/.hermes/.env`
- `~/.hermes/auth.json`
- `~/.ssh/*`
- cloud credential files
- password manager exports

Severity: Medium by itself, Critical if followed by egress or message sending.

### EDR-EXFIL-001: Secret read followed by network egress

Authenticated continuous ingestion requires a distinct reviewed Hermes `agent.tool.requested` file read/enumeration followed by one reviewed process/network/MCP egress or messaging-delivery shape. Both events must have `agent_action` trust, the same authenticated source, and the same non-empty projected trace or (only when both traces are absent) session join. The precursor must sort before the successor by `(observed_at_unix_ms,event_id)` and be at most 60,000 ms earlier. One deterministic nearest pair is selected per trigger; mutation/write classes are benign.

Default window: 60 seconds.

Severity: Critical.

### EDR-MALWARE-001: Malware-like content sent to AI runtime

Authenticated continuous ingestion requires the exact conjunction `agent.tool.completed`, `tool_output` trust, reviewed Hermes MCP source/provenance, `result_omitted=true`, `malware_indicator=true`, and an allowlisted safe test signature. Boolean-only, near-marker, wrong-source, wrong-trust, and raw-bearing shapes do not match. Producer `rule_id` is not detector evidence.

Severity: High. Raw payload content must be omitted before storage; store only structured indicator metadata such as signature family.

These correlators consume producer-asserted event metadata; AF_UNIX UID authorization does not attest the process or event truth. They are passive detection, not prevention. Exact successful Hermes cron create/update results now have an outcome-gated producer; config, persistence, and approval-scope mutation producers remain explicitly dark until authoritative post-mutation evidence exists.

## Implemented sequence semantics and roadmap candidates

`EDR-PI-001` and `EDR-MSG-001` below document their implemented narrow
sequence predicates. The other entries in this section are roadmap semantics or
future adapter coverage unless listed in the implemented sections above.

### EDR-PI-001: Untrusted content contains instruction override

The implemented sequence does not keyword-scan prompt text. It requires the
first event to be untrusted prompt-injection content under the canonical
predicate, then `agent.tool.requested` in the same trace/session window with
both `attributes.network_indicator=true` and `attributes.sensitive_access=true`.
Text-only prompt injection does not match.

Severity: High.

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

Detect HTTP(S) or unusual-port egress to a direct IP address rather than known domain. The canonical sequence implementation requires the egress event to carry explicit boolean `attributes.direct_ip=true`; generic `network_indicator=true` alone is not enough.

Severity: Medium by itself, Critical if correlated with secret access.

### EDR-MSG-001: Suspicious messaging exfiltration

The implemented sequence requires untrusted prompt-injection content followed
by `agent.tool.requested` with both `attributes.delivery_indicator=true` and
`attributes.sensitive_access=true`. It neither identifies a specific messaging
or email transport nor evaluates whether an authenticated user requested it.

Severity: High.

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

The platform-independent core schema/rendering model defines a future response surface; these values do not implement delivery or control actions:

- destinations: `stdout`, `jsonl_file`, `webhook`, and `email`
- response actions: `emit_alert`, `require_approval`, `pause_automation`, and `block_network_egress`
- approval boundaries: `passive_only`, `operator_required`, and `pre_approved_containment`

Approval boundaries are deliberately conservative. `passive_only` may only emit
an alert and cannot require approval, pause automation, or block egress.
`operator_required` may require approval or pause automation but cannot block
network egress. `pre_approved_containment` is the only boundary that allows
automatic network blocking.

Webhook and email destinations are inert schema/rendering metadata in v0.4.1,
not alert-delivery implementations. If a future outbound destination is added,
rendered alerts must be server-side redacted before delivery. Evidence, source
metadata, affected assets, recommended steps, and destination configuration are
all treated as hostile/sensitive render inputs; webhook URLs with embedded
tokens and local filesystem paths must not leak into rendered JSON.
