# Detections

This page is the v0.2 detection and alerting index. The detailed candidate rules live in [Initial detection rules](DETECTION_RULES.md); this page explains how to read them and how they connect to the rest of the product.

## Detection philosophy

Skynet-EDR should alert on suspicious chains, not spooky words in isolation.

A prompt injection string is interesting. A prompt injection string followed by a privileged tool call, sensitive file access, and outbound network activity is an incident candidate. Voilà, now we have something worth waking a human for.

## Current detection inputs

Detection rules may use:

- canonical event type and severity;
- source kind and sensor name;
- provenance and trust level from [Canonical event schema](EVENT_SCHEMA.md#trust-levels);
- redaction metadata proving sensitive fields were handled before storage;
- attributes such as command class, file path class, network indicator, MCP server shape, or config drift;
- local storage timelines documented in [Local storage and CLI](LOCAL_STORAGE.md);
- lab scenarios from [Linux lab testing](LINUX_LAB_TESTING.md).

## Initial rule families

| Family | Example | Detailed doc |
|---|---|---|
| MCP/tool abuse | shell interpreter plus egress tooling in MCP config | [EDR-MCP-001](DETECTION_RULES.md#edr-mcp-001-mcp-shell-plus-egress) |
| Sensitive access | reads of `.env`, OAuth stores, SSH keys, cloud credentials, or agent config | [EDR-SECRET-001](DETECTION_RULES.md#edr-secret-001-sensitive-file-access) |
| Exfiltration chain | secret read followed by network egress | [EDR-EXFIL-001](DETECTION_RULES.md#edr-exfil-001-secret-read-followed-by-network-egress) |
| Prompt injection | untrusted content attempts to override instruction hierarchy | [EDR-PI-001](DETECTION_RULES.md#edr-pi-001-untrusted-content-contains-instruction-override) |
| Risky automation | unattended cron/background jobs with agent or network behavior | [EDR-CRON-001](DETECTION_RULES.md#edr-cron-001-risky-unattended-automation) |
| Config drift | agent profile, skill, plugin, MCP, or cron changes | [EDR-CONFIG-001](DETECTION_RULES.md#edr-config-001-agent-config-drift) |
| Network anomaly | direct-IP or unusual outbound egress | [EDR-NET-001](DETECTION_RULES.md#edr-net-001-direct-ip-egress) |
| Messaging exfiltration | suspicious outbound chat/email/file delivery | [EDR-MSG-001](DETECTION_RULES.md#edr-msg-001-suspicious-messaging-exfiltration) |

## Severity model

Use the severity model in [Initial detection rules](DETECTION_RULES.md#severity-model). In short:

- isolated weak signals should stay low or medium;
- high severity should require a meaningful risky action or strong correlation;
- critical severity should require high-confidence exfiltration, persistence, destructive action, or containment-worthy behavior.

If every alert is critical, no alert is critical. Security dashboards already contain enough decorative panic, merci.

## Alert evidence requirements

Every alert should include:

- title and severity;
- affected runtime/process/agent where known;
- rule identifier;
- evidence chain with timestamps;
- provenance and trust context;
- redaction status;
- recommended operator action;
- rollback/containment notes when applicable.

The initial alert format is documented in [Initial detection rules](DETECTION_RULES.md#alert-format).

## Testing detections

Use fake honeytokens and controlled sinks only:

- [Linux lab testing](LINUX_LAB_TESTING.md#fake-honeytokens-only)
- [Linux lab testing](LINUX_LAB_TESTING.md#controlled-sink)

Regression fixtures should validate both positive detections and non-alerting benign cases. Malformed input must not bypass validation; see [Canonical event schema](EVENT_SCHEMA.md#validation-requirements).
