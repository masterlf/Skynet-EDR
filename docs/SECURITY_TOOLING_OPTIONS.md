# Security Tooling Options

This project prefers open-source and free tooling first. Paid tools can be considered later if they provide clear value.

## Recommended baseline

### Secret scanning

1. **GitHub Secret Scanning + Push Protection**
   - Already enabled for the repository.
   - Best first line of defense for accidental credential commits.

2. **Gitleaks**
   - Open-source.
   - Fast and easy to run in CI and locally.

3. **TruffleHog**
   - Open-source core.
   - Strong verified-secret detection.
   - Useful as a second opinion because secret scanners catch different patterns.

### Static application security testing

1. **Semgrep OSS**
   - Best open-source default for custom secure-coding rules.
   - Good for project-specific checks like dangerous shell execution, unsafe path handling, and missing redaction.

2. **CodeQL**
   - Free for public GitHub repositories.
   - Good deeper semantic analysis.
   - Rust support exists, but custom Rust queries may require more maturity and testing.

### Rust dependency and policy scanning

1. **cargo-audit**
   - Checks RustSec advisories.

2. **cargo-deny**
   - Enforces license, advisory, duplicate, and banned dependency policies.

3. **OSV-Scanner**
   - Ecosystem-independent vulnerability scanning.

### Repository and supply-chain posture

1. **OpenSSF Scorecard**
   - Measures repository security posture.

2. **SLSA provenance**
   - Add later for releases and signed artifacts.

### Filesystem/container scanning

1. **Trivy**
   - Good for filesystem scanning now.
   - Also useful for container images later.

### Python integration scanning

1. **Ruff** for lint/format.
2. **Bandit** for Python security checks.
3. **pytest** for tests.

## Tools to consider later

| Tool | Type | Notes |
|---|---|---|
| Semgrep AppSec Platform | Commercial/free tiers | Better triage and dashboard if the project grows. |
| Snyk | Commercial/free tiers | Good dependency and code scanning; evaluate cost/value later. |
| GitHub Advanced Security | Commercial for private repos | Excellent but may be overkill/costly outside public repo usage. |
| FOSSA | Commercial/free tiers | License/compliance focus if dependency policy becomes complex. |

## Current CI strategy

The repository should run:

- CI formatting/lint/test checks
- Gitleaks
- TruffleHog verified scan
- Semgrep OSS
- Trivy filesystem scan
- OSV-Scanner
- cargo-audit and cargo-deny when Rust workspace exists
- CodeQL for Rust/Python when code exists
- OpenSSF Scorecard

Some jobs intentionally no-op until Rust/Python code exists. This keeps the repository protected without failing before implementation begins.
