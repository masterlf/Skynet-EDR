# Public live detection journey

## Contract

The gate follows one event through the published DEB, package-owned enrollment,
real Hermes gateway dispatcher, installed safe-simulation handler, authenticated
AF_UNIX ingestion, SQLite event/receipt/incident, loopback API, authenticated
Hermes proxy, and rendered Risk Explorer evidence.

It tests the published `v0.7.0-alpha.2` DEB with SHA-256
`aca54b93ecea85f8b789d5d8600b5ae1554b1513089a6778a5253fc1e11eaee4` and Hermes
`v2026.8.3`, commit `3c27eb6234bf91b8ceee9e9071591b31e9b148cb`, version `0.20.0`.
The gateway and dashboard use that same Hermes checkout. Future releases require
an explicit artifact identity update and a fresh qualifying run. This workflow
tests the published baseline, not a rebuilt candidate package.

## Prepare a disposable host

Use a fresh **Ubuntu 24.04 amd64 VM with systemd**, sudo access, and no private
data or credentials. Check out the reviewed Skynet-EDR test revision. Install
Node.js/npm and `uv 0.12.3` using trusted tooling. The workflow pins its uv
installer action and version. From the Skynet-EDR repository:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends git curl dbus-user-session python3-venv
# Required launcher trust boundary; change only on this disposable VM.
sudo chown root:root /opt
sudo chmod 0755 /opt
sudo git clone --depth 1 --branch v2026.8.3 \
  https://github.com/NousResearch/hermes-agent.git /opt/skynet-journey-hermes
test "$(sudo git -C /opt/skynet-journey-hermes rev-parse HEAD)" = \
  3c27eb6234bf91b8ceee9e9071591b31e9b148cb
sudo "$(command -v uv)" sync --frozen --project /opt/skynet-journey-hermes --python /usr/bin/python3
npm ci --ignore-scripts --no-audit --no-fund --prefix packaging/browser-gate
export PLAYWRIGHT_BROWSERS_PATH=/tmp/skynet-public-journey-browsers
npm exec --prefix packaging/browser-gate -- playwright install --with-deps chromium
curl --fail --location --proto '=https' --tlsv1.2 --output /tmp/skynet-edr-journey.deb \
  https://github.com/masterlf/Skynet-EDR/releases/download/v0.7.0-alpha.2/skynet-edr_0.7.0-alpha.2_amd64.deb
printf '%s  %s\n' \
  aca54b93ecea85f8b789d5d8600b5ae1554b1513089a6778a5253fc1e11eaee4 \
  /tmp/skynet-edr-journey.deb | sha256sum -c -
```

The harness provisions `skynet-journey`, its canonical default Hermes profile,
`/usr/bin/hermes`, and private evidence under `/var/lib/skynet-public-journey`.
It installs the DEB, enables linger, and authorizes the enrollment adapter to
stop/start that synthetic account's complete user manager. It rejects existing
target accounts, paths, packages, and occupied ports. It must not run on an
existing Hermes host or workstation.

## Run the journey

```bash
sudo env PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" \
  timeout --signal=TERM --kill-after=20s 12m \
  bash packaging/scripts/public-live-journey.sh --disposable-host \
    --deb /tmp/skynet-edr-journey.deb \
    --hermes-repo /opt/skynet-journey-hermes \
    --browser-runtime "$PWD/packaging/browser-gate"
```

Dependency downloads occur during preparation. The model fixture binds only
`127.0.0.1:19000`, the credential-free A2A gateway `127.0.0.1:9900`, the daemon
API `127.0.0.1:8787`, and the authenticated dashboard `127.0.0.1:9119`. The browser
proxy rejects other origins and keeps its temporary token off direct daemon
requests.

The fixture first returns the benign reply required for real enrollment. It
then switches to `tool_search → tool_describe → tool_call` without restarting
the enrolled gateway. The installed handler must report `persisted`; fallback,
duplicate, failure, and timeout cannot pass. A read-only verifier checks the
new event, durable receipt, authenticated gateway UID/PID and package generation,
exactly one high-severity incident, and its API evidence. The browser opens the
same incident and renders the same event ID. The binding is checked again after
browser inspection. No test inserts events/incidents or mocks the daemon API.

## Results and cleanup

Exit zero and a JSON `status=PASS` are both required. The bounded verdict records
the package hash, Hermes commit, enrollment state, rule, incident count, live ACK,
and browser binding. GitHub Actions retains only this verdict, with the test
commit and run URL providing execution identity. A green run is integration
evidence, not independent operator acceptance or broad detection effectiveness.

A nonzero exit reports a fixed stage such as `enrollment`, `dispatch`,
`persistence`, or `browser`. Private runtime output stays in root-owned mode-0700
test storage. Bounded stored/API/session evidence and browser text are checked
for the known forbidden synthetic marker; this does not prove universal
redaction or test arbitrary secret-bearing input.

The harness stops its processes and the synthetic user's manager on completion.
It preserves the package, account, and enrollment recovery state for inspection.
**Discard or revert the VM before another run.** Backup/restore, upgrade/rollback,
and clean uninstall remain separate roadmap work. Follow the
[enrollment recovery guidance](HERMES_ENROLLMENT.md) if investigating a failure.

Evidence-checker regressions can run without Linux:

```bash
python3 -m unittest discover -s packaging/tests -p test_public_journey_evidence.py
```
