# Concepts

Skynet-EDR is an AI-agent-aware Detection and Response project. It extends classic endpoint visibility with the context needed to understand autonomous AI runtime behavior: instruction provenance, tool calls, MCP configuration, sensitive file access, scheduled automation, and outbound communication.

For mission and milestones, see [Project goals](GOALS.md). For adversary assumptions, see [Threat model](THREAT_MODEL.md).

## Core idea

Traditional EDR can observe processes, files, and network activity. LLM guardrails can observe some model inputs and outputs. Skynet-EDR is designed to correlate both worlds:

```text
untrusted content
→ agent interpretation
→ tool/MCP action
→ sensitive file/config access
→ network, messaging, or persistence behavior
```

The value is not a magical prompt-injection score. The value is evidence that explains why a risky host or SaaS action happened and whether untrusted content plausibly influenced it.

## Vocabulary

| Term | Meaning |
|---|---|
| Agent runtime | A system that lets an LLM act through tools, files, browsers, APIs, messaging, cron jobs, or MCP servers. |
| Provenance | The origin and authority of content or actions: authenticated user, runtime policy, untrusted content, tool output, agent action, or sensor observation. |
| Tool call | A runtime-mediated action such as shell, file access, browser, HTTP, SaaS API, or messaging. |
| MCP server | A Model Context Protocol server exposing tools/resources/prompts to an agent runtime. |
| Sensitive asset | Secrets, credentials, OAuth stores, SSH keys, agent configuration, customer data, or other data that should not be read or exfiltrated casually. |
| Correlation | Combining events into a chain that is more meaningful than any single event. |
| Redacted evidence | Operator-facing security evidence with secrets and unnecessary local context removed before persistence and alerting. |

The schema-level source of truth for provenance and trust values is [Canonical event schema](EVENT_SCHEMA.md#trust-levels).

## Current v0.2 scope

The current Linux-first MVP is passive. It focuses on:

- redacted local event and incident evidence;
- canonical `skynet.event.v0` event ingestion;
- Hermes/AI-agent trace normalization;
- read-only CLI, local HTTP, and MCP visibility surfaces;
- high-signal correlation such as secret/config access followed by network egress;
- packaging and reproducible release artifacts.

See [Install](INSTALL.md) for supported package formats and [Operations](OPERATIONS.md) for runtime posture.

## Non-goals for the MVP

Skynet-EDR currently does not claim to be:

- a universal prompt-injection classifier;
- a replacement for host EDR, SIEM, IAM, or DLP;
- a remote shell or agent orchestration plane;
- a kernel-level sensor suite;
- an automated blocker for ambiguous behavior;
- a place to store raw secrets, full prompts, or unnecessary private content.

The MVP bias is detection before blocking. Enforcement should arrive only after event quality, redaction, and correlation are boringly reliable. Yes, boring again. Security loves boring.

## Evidence model

Good alerts should answer:

1. What happened?
2. Which agent/runtime/process produced or observed it?
3. What was the trust level and provenance?
4. Which sensitive asset or risky action was involved?
5. Was evidence redacted before storage?
6. What should an operator do next?

The initial alert shape is documented in [Initial detection rules](DETECTION_RULES.md#alert-format).

## Trust boundary rule

Untrusted content, tool output, terminal output, web pages, emails, PDFs, logs, and repository files are data, not authority. A collector may store redacted evidence about them; it must not treat them as instructions to Skynet-EDR or to the agent operator.

This rule is enforced in spirit across [Threat model](THREAT_MODEL.md#trust-boundaries), [Canonical event schema](EVENT_SCHEMA.md#design-rules), and [Quality and security engineering](QUALITY_AND_SECURITY_ENGINEERING.md#secure-coding-principles).
