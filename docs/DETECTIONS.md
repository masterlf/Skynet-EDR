# Detections

This page is the detection and alerting index. Implemented and roadmap rules live in [Detection rules](DETECTION_RULES.md); this page explains how to read them and how they connect to the rest of the product.

## Detection philosophy

Skynet-EDR should alert on suspicious chains, not spooky words in isolation.

A prompt injection string is interesting. A prompt injection string followed by a privileged tool call, sensitive file access, and outbound network activity is an incident candidate. Voilà, now we have something worth waking a human for.

## Current detection inputs

Detection rules may use:

- canonical event type and severity;
- source kind and sensor name;
- provenance and trust level from [Canonical event schema](EVENT_SCHEMA.md#trust-levels);
- redaction metadata proving sensitive fields were handled before storage;
- attributes such as command class, file path class, network indicator, explicit direct-IP egress, MCP server shape, or config drift;
- local storage timelines documented in [Local storage and CLI](LOCAL_STORAGE.md);
- lab scenarios from [Linux lab testing](LINUX_LAB_TESTING.md).

## Implemented engines

- The explicit `events ingest-hermes` trace importer runs Hermes-specific correlators for `EDR-EXFIL-001` and `EDR-MALWARE-001`. Those correlators are not currently invoked by AF_UNIX continuous ingestion or canonical JSONL spool ingestion.
- The canonical sequence engine evaluates ordered canonical events with exact `event_type`, exact `trust_level`, optional `attributes.*` predicates, a fixed time window, deterministic timestamp/event-id ordering, and same-session or same-trace joins.
- The built-in canonical sequence rule pack covers `EDR-MCP-001`, `EDR-CONFIG-001`, `EDR-CRON-001`, `EDR-PI-001`, `EDR-MSG-001`, `EDR-NET-001`, `EDR-SCOPE-001`, and `EDR-PERSIST-001` as passive explainable matches. It does not replace or duplicate the existing `EDR-EXFIL-001` Hermes secret-egress correlator.

## Rule-to-producer coverage matrix

“Live” means the shipped Hermes plugin can emit the exact trigger shape and the AF_UNIX transaction evaluates the relevant engine. “Producer-dependent” means the engine evaluates canonical spool records, but coverage exists only if an external producer supplies the documented event types and attributes. “Dark” means the rule is implemented but the named shipped producer does not emit its required action event. None of these paths provides guard-mode prevention.

| Rule | Engine | Hermes plugin → AF_UNIX | Canonical JSONL spool | `events ingest-hermes` trace import |
|---|---|---|---|---|
| `EDR-MCP-001` | canonical sequence | **Live, bounded:** prompt-injection tool output followed in the same trace by an unknown/MCP tool request with a recognized network indicator | **Producer-dependent** | Not evaluated by this importer |
| `EDR-PI-001` | canonical sequence | **Live, narrow:** prompt-injection tool output followed by `agent.tool.requested` carrying both `network_indicator=true` and `sensitive_access=true` | **Producer-dependent** | Not evaluated by this importer |
| `EDR-MSG-001` | canonical sequence | **Live, narrow:** prompt-injection tool output followed by a recognized delivery tool request that also carries `sensitive_access=true` | **Producer-dependent** | Not evaluated by this importer |
| `EDR-NET-001` | canonical sequence | **Live, narrow:** prompt-injection tool output followed by a recognized explicit IPv4 destination emitted as `agent.network.egress` with `direct_ip=true` | **Producer-dependent** | Not evaluated by this importer |
| `EDR-CONFIG-001` | canonical sequence | **Dark:** plugin emits no `agent.config.changed` event or `approval_required` attribute | **Producer-dependent** | Not evaluated by this importer |
| `EDR-CRON-001` | canonical sequence | **Dark:** plugin emits no `agent.automation.scheduled` event or `persistence_indicator` attribute | **Producer-dependent** | Not evaluated by this importer |
| `EDR-SCOPE-001` | canonical sequence | **Dark:** plugin emits no `agent.approval.granted` event or `scope_expansion` attribute | **Producer-dependent** | Not evaluated by this importer |
| `EDR-PERSIST-001` | canonical sequence | **Dark:** plugin emits no `agent.config.changed` event with `persistence_indicator=true` | **Producer-dependent** | Not evaluated by this importer |
| `EDR-EXFIL-001` | Hermes-specific correlator | **Unsupported on this path:** plugin indicators may be stored, but continuous ingestion does not run this correlator | Not evaluated by canonical spool ingestion | **Implemented and regression-tested** for normalized Hermes secret-access → egress traces |
| `EDR-MALWARE-001` | Hermes-specific correlator | **Unsupported on this path:** plugin can emit a safe malware-test indicator, but continuous ingestion does not run this correlator | Not evaluated by canonical spool ingestion | **Implemented and regression-tested** for normalized safe test-marker traces |
| `EDR-SECRET-001` | roadmap candidate only | **Unsupported:** no standalone shipped correlator | Unsupported | Unsupported |

Live rows still depend on event ordering within 60 seconds, the same trace, exact typed attributes, successful durable ingestion, and a non-truncated correlation candidate set. The plugin's network classifier does not fully cover IPv6, indirect SDK/Python/cloud-client egress, `scp`, `rsync`, `ftp://`, or `s3://`; absence of a match is not proof of safety. See [Hermes plugin telemetry](HERMES_PLUGIN_TELEMETRY.md#detection-limits) and [continuous ingestion operations](OPERATIONS.md#continuous-ingestion-operations).

## Rule families

| Family | Example | Detailed doc |
|---|---|---|
| MCP/tool abuse | instructional-attack content followed by a network-capable MCP request in the same trace | [EDR-MCP-001](DETECTION_RULES.md#edr-mcp-001-mcp-network-tool-request-after-instructional-attack) |
| Sensitive access | reads of `.env`, OAuth stores, SSH keys, cloud credentials, or agent config | [EDR-SECRET-001](DETECTION_RULES.md#edr-secret-001-sensitive-file-access) |
| Exfiltration chain | secret read followed by network egress | [EDR-EXFIL-001](DETECTION_RULES.md#edr-exfil-001-secret-read-followed-by-network-egress) |
| Malware-to-AI content | known safe malware-test indicators supplied to the AI runtime | [EDR-MALWARE-001](DETECTION_RULES.md#edr-malware-001-malware-like-content-sent-to-ai-runtime) |
| Prompt injection | untrusted content attempts to override instruction hierarchy | [EDR-PI-001](DETECTION_RULES.md#edr-pi-001-untrusted-content-contains-instruction-override) |
| Risky automation | unattended cron/background jobs with agent or network behavior | [EDR-CRON-001](DETECTION_RULES.md#edr-cron-001-risky-unattended-automation) |
| Config drift | agent profile, skill, plugin, MCP, or cron changes | [EDR-CONFIG-001](DETECTION_RULES.md#edr-config-001-agent-config-drift) |
| Network anomaly | direct-IP outbound egress with `attributes.direct_ip=true` | [EDR-NET-001](DETECTION_RULES.md#edr-net-001-direct-ip-egress) |
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
