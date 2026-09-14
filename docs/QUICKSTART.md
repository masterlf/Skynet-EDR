# Quickstart: see a real Hermes incident

The supported evaluation cell is **Ubuntu 24.04 amd64, systemd, the native DEB,
Hermes 0.20.0, and the default profile**. Skynet-EDR is passive: the simulation
records an incident; it does not block an agent action.

## Run the complete demonstration

Follow [Public live detection journey](PUBLIC_LIVE_JOURNEY.md) on a fresh
disposable VM with no credentials. The public harness installs the released
DEB, provisions a synthetic Hermes account, uses the package-owned enrollment
transaction, runs the safe simulation through the real gateway dispatcher, and
opens its incident in Risk Explorer. Model responses come from a loopback
fixture; no model account or API key is needed.

The same commands run in the **Public live detection journey** workflow. The
harness rejects an existing Hermes launcher, test account, installed package,
occupied service ports, or previous test state. It creates and restarts a
dedicated user's complete systemd manager. Use only a disposable host that you
are authorized to provision.

A successful verdict contains:

```json
{
  "schema": "skynet.public-journey.v1",
  "status": "PASS",
  "enrollment": "ENROLLED",
  "rule_id": "EDR-MALWARE-001",
  "incident_count": 1,
  "live_ack": true,
  "browser_event_binding": true
}
```

The actual verdict also records the DEB SHA-256 and Hermes commit. An old incident
or fallback-only submission fails the test.

## Understand the incident

Risk Explorer displays **Malware-like content supplied to AI runtime** with
rule `EDR-MALWARE-001`, severity **High**, and one evidence event. The test opens
that row and checks its event identifier against SQLite and the authenticated
Hermes API response.

This proves one allowlisted safe-marker journey. It does not measure general
malware or prompt-injection detection, and it does not widen the other six
rules' evidence level. See the [support contract](MVP_SUPPORT_MATRIX.md) and
[protection matrix](PROTECTION_MATRIX_v0.6.0.md).

## Evaluate an existing Hermes installation

For an existing supported host, use [Install](INSTALL.md) and
[Fail-closed Hermes enrollment](HERMES_ENROLLMENT.md). Review the enrollment
request and account-wide user-manager restart impact before applying it. The
disposable harness is not an installer for an existing account.

After enrollment, check `/api/status` and the gateway producer's fresh protocol-v3
health. A running daemon alone does not prove that Hermes telemetry arrives.
Use [Operations](OPERATIONS.md) for degraded health and diagnostics.

## Development and offline checks

```bash
python3 packaging/scripts/check-docs.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 packaging/scripts/threat-validation.py
```

These checks complement the real journey; unit fixtures do not establish live
enrollment, gateway dispatch, or browser rendering.
