# Security Policy
## Supported versions
Skynet-EDR is currently pre-release. No production version is supported yet.
| Version | Supported | Notes |
|---|---:|---|
| `main` | Best effort | Active development only |
| Releases | No | No functional release exists yet |
## Reporting a vulnerability
Do not publish sensitive vulnerability details in public issues if they include working exploit chains, private credentials, bypass techniques, or active attacker infrastructure.
For now, report privately to the project owner through GitHub. A dedicated security contact and advisory flow will be added before the first functional release.
Please include:
- affected commit, branch, or release
- affected component
- reproduction steps
- impact assessment
- whether secrets, credentials, or external systems are involved
- suggested fix if known
## Response target
During pre-release, response is best effort.
Target once a first functional release exists:
- acknowledge within 72 hours
- triage within 7 days
- coordinate a fix or mitigation before public disclosure when practical
## Scope
In scope:
- prompt-injection chain handling
- MCP/tool-call abuse detection
- secret redaction failures
- unsafe parsing of hostile input
- data-exfiltration detection bypasses
- privilege or sandbox boundary failures in Skynet-EDR components
- CI/CD or release-process weaknesses affecting project integrity
Out of scope for now:
- social engineering against maintainers
- denial-of-service against third-party infrastructure
- findings requiring real credential theft
- reports against dependencies without a Skynet-EDR-specific impact path
## Safe harbor
Good-faith research is welcome if it avoids privacy violations, destructive actions, persistence, lateral movement, and access to real secrets. Use fake honeytokens and controlled lab targets only.
## Design stance
This project assumes:
- untrusted content can contain malicious instructions
- prompt-injection detection is imperfect
- secrets must be redacted before logs, storage, UI, and alerts
- response actions must be auditable
- false positives are acceptable only when evidence is clear and actionable
## Handling sensitive data
Future code must follow these rules:
- never log full secrets
- redact tokens, API keys, credentials, cookies, and authorization headers
- prefer hashes and short snippets for evidence
- make full-payload capture opt-in only
- document retention and deletion behavior
- keep test fixtures fake and clearly marked
