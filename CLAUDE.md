# Skynet-EDR Development Guidelines

Skynet-EDR is a security product. Treat the repository as production-grade from the first line of code.

## Mission

Build an AI-Agent Detection and Response system with Linux-first implementation and platform-native sensors for Windows and macOS later.

The detection model, event schema, rules, redaction, storage, CLI/API, web UI, MCP server, and alert model must remain platform-independent. Only sensor backends should be platform-specific.

## Non-negotiable engineering rules

1. **No direct commits to `main`.** All changes must land through pull requests.
2. **Tests first for every feature and bug fix.** Use RED-GREEN-REFACTOR.
3. **No production code without regression tests.** If behavior changes, tests change first.
4. **No secrets in code, docs, tests, fixtures, logs, screenshots, or examples.** Use fake clearly-marked placeholders.
5. **All parsed input is hostile.** Logs, configs, MCP output, prompts, files, and network metadata must be treated as untrusted.
6. **Redact before storing or alerting.** Never rely on UI-side redaction only.
7. **Avoid shelling out in core code.** Prefer native APIs and structured parsers.
8. **Do not add dependencies casually.** New dependencies need a security/maintenance justification.
9. **Fail closed for security decisions.** Unparseable policy or ambiguous sensitive action should not silently pass.
10. **Document threat assumptions.** If a design decision changes the threat model, update docs.

## Required workflow for Claude Code

Before writing code:

1. Read the relevant docs under `docs/`.
2. Identify the exact behavior to implement.
3. Write or update tests first.
4. Run the new test and confirm it fails for the expected reason.
5. Implement the smallest change that makes the test pass.
6. Run targeted tests.
7. Run the full relevant test suite.
8. Run formatting, linting, and security checks.
9. Summarize verification results in the PR body.

## Rust quality baseline

When Rust code exists, use:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check
```

Core expectations:

- Prefer safe Rust.
- Any `unsafe` requires a comment explaining why it is necessary and how invariants are upheld.
- Use explicit error types at boundaries; avoid swallowing errors.
- Avoid panics in daemon/runtime code.
- Keep platform-specific code behind clean interfaces.
- Use structured events and typed enums instead of stringly-typed logic where practical.

## Python integration quality baseline

Python is optional integration glue, not the core runtime.

When Python code exists, use:

```bash
python -m pytest
ruff check .
ruff format --check .
bandit -r integrations/ -q
```

Expectations:

- Type hints for public functions.
- No shell=True unless explicitly justified and tested.
- No secret logging.
- Use pathlib and structured JSON APIs.

## Security review checklist

Every PR must consider:

- Can untrusted input reach command execution?
- Can untrusted input influence file paths?
- Can secrets be read, logged, stored, or sent externally?
- Can MCP/tool output become instruction authority?
- Can a malformed event bypass detection?
- Can a rule failure silently disable protection?
- Does the change increase network egress or credential scope?
- Are alerts redacted and actionable?

## Testing expectations

Minimum tests per feature:

- happy path
- error path
- malformed/hostile input
- redaction behavior if sensitive data is involved
- platform abstraction behavior where relevant

Use fixtures for known attack chains, including:

- malicious MCP shell plus network egress
- secret file read followed by outbound network event
- prompt injection in untrusted content
- risky cron/background job
- suspicious config drift

## PR quality gate

A PR is not ready unless it includes:

- summary of change
- tests added or updated
- exact verification commands run
- security impact notes
- rollback notes if relevant

If a check is skipped because no code for that ecosystem exists yet, say so explicitly.
