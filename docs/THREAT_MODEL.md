# Threat Model

## Protected system

Skynet-EDR is intended to monitor AI-agent runtimes that combine LLM reasoning with local or remote actions.

Examples:

- Hermes Agent
- Claude Code-style coding agents
- Codex-style coding agents
- OpenCode/OpenClaw-style agents
- MCP-enabled assistants
- custom internal autonomous agents

## Assets

High-value assets include:

- API keys and tokens
- OAuth refresh tokens
- messaging bot tokens
- cloud credentials
- SSH keys
- source code
- private documents and emails
- agent memory and skills
- agent configuration
- scheduled jobs and automation definitions
- connected SaaS/API privileges

## Trust boundaries

### Trusted instruction sources

- system instructions
- developer/operator policy
- authenticated user messages from approved channels
- explicitly approved administrative actions

### Untrusted data sources

- web pages
- emails
- PDFs and office documents
- GitHub issues, PRs, READMEs, and repo files
- logs and terminal output
- MCP tool responses
- browser content
- third-party chat messages
- model-generated content from other agents

Untrusted data may be useful evidence, but it must not become authority.

## Threats

### Indirect prompt injection

An attacker places malicious instructions in content the agent will read later.

### Tool abuse

The agent is manipulated into using shell, file, browser, cloud, or messaging tools outside the user-approved scope.

### MCP compromise or abuse

A malicious or compromised MCP server exposes dangerous tools, runs shell commands, accesses sensitive files, or performs network egress.

### Credential exfiltration

The agent reads secrets and sends them to an attacker-controlled destination via HTTP, DNS, email, chat, image URL, or another side channel.

### Confused deputy

The agent uses its legitimate privileges to perform an action for an untrusted party.

### Persistent manipulation

Malicious instructions are stored in memory, skills, config, cron jobs, or project files and influence future sessions.

### Configuration drift

Unexpected changes introduce new tools, MCP servers, webhook routes, scheduled jobs, or credentials.

## Assumptions

- The agent may need powerful tools to be useful.
- Untrusted content cannot be eliminated.
- Prompt-injection detection will be imperfect.
- Behavioral correlation and blast-radius reduction are more reliable than pure text classification.

## Initial response philosophy

- Alert early on high-confidence chains.
- Avoid noisy alerts from isolated suspicious phrases.
- Prefer pause-and-ask over silent execution for ambiguous risky actions.
- Block only when the action is clearly dangerous, such as secret-to-network exfiltration.
