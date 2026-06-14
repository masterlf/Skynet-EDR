# Security Policy

## Project status

Skynet-EDR is currently in early concept and documentation phase. There is no production release yet.

## Reporting security issues

Please do not publish sensitive vulnerability details in public issues if they include working exploit chains, private credentials, or active attacker infrastructure.

For now, contact the project owner through GitHub. A dedicated security contact will be added before the first functional release.

## Design stance

This project assumes:

- untrusted content can contain malicious instructions
- prompt-injection detection is imperfect
- secrets must be redacted from logs and alerts
- response actions must be auditable
- false positives are acceptable only when evidence is clear and actionable

## Handling sensitive data

Future code should follow these rules:

- never log full secrets
- redact tokens, API keys, and credentials
- prefer hashes and short snippets for evidence
- make full-payload capture opt-in only
- document retention and deletion behavior
