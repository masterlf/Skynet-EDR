# Quality and Security Engineering Baseline

This document defines the development quality bar for Skynet-EDR.

## Goal

Skynet-EDR should be business-grade from the beginning: tested, reviewable, secure-by-default, and resistant to accidental credential leakage.

## Development model

- All changes land through pull requests.
- Direct commits to `main` are blocked by branch protection.
- Every feature or bug fix must include tests.
- Security tooling runs in CI and should be treated as a product requirement, not decoration.

## Test-driven development

Use RED-GREEN-REFACTOR for behavior changes:

1. Write a failing test.
2. Run the test and confirm it fails for the expected reason.
3. Implement the smallest change to pass.
4. Run the targeted test.
5. Run the relevant full suite.
6. Refactor only while tests stay green.

Required test categories:

- happy path
- invalid input
- malicious or malformed input
- redaction behavior
- persistence behavior if events/incidents are stored
- cross-platform abstraction behavior where applicable

## Secure coding principles

Skynet-EDR parses hostile data. The secure coding baseline is:

- Treat all external input as untrusted.
- Never log or store raw secrets.
- Redact secrets before writing events, incidents, logs, or UI responses.
- Prefer structured parsers over ad-hoc regex when parsing configs or events.
- Avoid shell execution in core logic.
- Use least-privilege OS APIs and file permissions.
- Keep platform-specific sensor code isolated.
- Make high-risk response actions opt-in and auditable.
- Fail closed when policy parsing or security decisions are ambiguous.

## Recommended tooling

### Free/open-source first

| Area | Tool | Notes |
|---|---|---|
| Secret scanning | GitHub Secret Scanning | Enabled for the public repository. |
| Secret scanning | Gitleaks | Fast open-source scanner for commits and working tree. |
| Secret scanning | TruffleHog | Strong verification-oriented secret scanner. Useful as a second opinion. |
| SAST | Semgrep OSS | Flexible rules, good for custom security checks. |
| SAST | CodeQL | Free for public GitHub repositories; good for deeper code scanning. |
| Rust vulnerabilities | cargo-audit | RustSec advisory database. |
| Rust dependency policy | cargo-deny | Licenses, bans, advisories, duplicate versions. |
| Rust linting | Clippy | Treat warnings as errors. |
| Rust formatting | rustfmt | Required before merge. |
| Rust UB checks | Miri | Later for critical unsafe/parser logic. |
| Rust fuzzing | cargo-fuzz | Later for parsers, rule engine, and redaction. |
| Dependency vulns | OSV-Scanner | Ecosystem-independent dependency vulnerability scanner. |
| Filesystem/container scan | Trivy | Useful for repo filesystem and future container images. |
| Supply-chain posture | OpenSSF Scorecard | Repository hygiene and supply-chain signal. |
| Provenance | SLSA GitHub Generator | Later for release provenance. |
| Python security | Bandit | For optional Hermes Python integration. |
| Python lint/format | Ruff | Fast linting and formatting. |

### Commercial tools worth considering later

- Semgrep AppSec Platform if triage and team workflow become useful.
- Snyk Open Source / Code if dependency and SAST reporting value justifies cost.
- GitHub Advanced Security is excellent, but may not be cheap for private/commercial use; public repo features are enough for now.

## Current repository security configuration

Configured or proposed:

- Branch protection for `main`.
- Dependabot version updates.
- Dependabot security updates.
- GitHub secret scanning and push protection.
- CI workflows for Semgrep, Gitleaks, Trivy, OSV-Scanner, CodeQL, cargo audit/deny, clippy, tests.

## PR checklist

Every PR should include:

- [ ] What changed and why.
- [ ] Tests added/updated.
- [ ] Verification commands run.
- [ ] Security impact.
- [ ] Secrets/redaction impact.
- [ ] Rollback notes.

## Claude Code operating rules

Claude Code should follow `CLAUDE.md` and `.claude/settings.json`.

Important constraints:

- Do not read secret files.
- Do not use network exfiltration commands.
- Do not bypass tests.
- Do not add dependencies without explaining why.
- Do not mark work complete without running verification.
