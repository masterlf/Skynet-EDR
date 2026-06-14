# Linux Lab and Privileged Sensor Manual Test Plan

Phase 9 prepares the disposable Linux lab workflow for future privileged sensor validation. It does **not** enable automatic privileged sensor execution in Skynet-EDR, CI, cron, or agent tooling.

## Safety boundary

- **Manual workflow only.** A human operator starts every privileged command from an interactive shell after reading the expected blast radius.
- **Disposable VM.** Run only inside a throwaway VM that can be destroyed or rolled back from a clean snapshot.
- **Non-production.** Never run these workflows on Frederic's workstation, Hermes host, production infrastructure, customer systems, or any machine containing real credentials.
- **Frederic-provided VM details.** Execution is blocked until Frederic provides the VM target, access method, rollback mechanism, and allowed egress policy.
- **No automatic privileged sensor execution.** Tests in this repository remain fake-fixture and unprivileged. CI must never start auditd, eBPF, packet capture, firewall logging, or kernel-level watchers.

## Blocked inputs

Before any privileged lab run, record these inputs in the run notes or PR comment:

1. OS distribution and version, including kernel version.
2. Hypervisor or provider, for example local KVM, VirtualBox, Proxmox, cloud VM, or disposable container host.
3. Root or sudo availability and whether passwordless sudo is enabled.
4. Snapshot or rollback mechanism, including snapshot name or rebuild script.
5. Egress policy: no external egress, allowlist only, or fully isolated NAT.
6. Network interface names and whether loopback-only tests are required.
7. Whether auditd, fanotify/inotify, nftables/iptables logging, eBPF, or process accounting are allowed.
8. Maximum runtime and maximum log volume before cleanup.
9. Confirmation that the VM contains no real secrets, cloud credentials, SSH private keys, OAuth tokens, or production data.

If any item is unknown, stop. The correct outcome is a blocked task, not a heroic little security swamp swim.

## Lab architecture

```text
operator shell
  -> disposable VM snapshot
      -> Skynet-EDR test binary / fixture runner
      -> fake honeytoken files only
      -> controlled sink on 127.0.0.1
      -> local logs and JSONL artifacts
  -> destroy or rollback VM
```

Recommended network modes, from safest to riskiest:

1. Host-only or isolated network, loopback sink only.
2. NAT with firewall deny-all egress except package mirrors during setup.
3. Allowlisted outbound egress to a controlled sink owned by Frederic.

Do not use arbitrary public webhook receivers, pastebins, disposable SaaS endpoints, or personal messaging bots as sinks for lab data. That is how test telemetry becomes yesterday's incident report. Très chic, but no.

## Fake honeytokens only

Use fake honeytokens only. They must be syntactically plausible enough to exercise redaction and detection, but clearly non-secret and non-functional.

Allowed examples:

```text
SKYNET_EDR_FAKE_TOKEN=skynet-edr-fake-token-000000000000
AWS_ACCESS_KEY_ID=AKIA-FAKE-HONEYTOKEN-0000
AWS_SECRET_ACCESS_KEY=skynet-edr-fake-secret-do-not-use
GITHUB_TOKEN=ghp_skynet_edr_fake_honeytoken_not_valid
HERMES_FAKE_OAUTH_REFRESH_TOKEN=skynet-edr-fake-refresh-token
```

Rules:

- No real secrets.
- No copied production-looking tokens from password managers, shell history, CI logs, cloud consoles, Hermes auth files, or screenshots.
- Store fake honeytokens under a lab-only directory such as `/opt/skynet-edr-lab/honeytokens/`.
- Mark every file with `FAKE HONEYTOKEN FOR SKYNET-EDR LAB ONLY`.
- Delete the files before final VM rollback, even though the VM should be disposable.

## Controlled sink

Default sink is loopback only: `127.0.0.1`.

Preferred local sink options:

```bash
# Option A: Python loopback HTTP sink. Manual workflow only.
python3 -m http.server 18080 --bind 127.0.0.1

# Option B: netcat loopback listener if installed. Manual workflow only.
nc -l 127.0.0.1 18080
```

The controlled sink is for metadata and fake honeytoken redaction tests only. It must not receive real credentials or production data.

Allowed destination examples:

```text
http://127.0.0.1:18080/skynet-edr-lab
http://localhost:18080/skynet-edr-lab
```

Blocked destination examples:

```text
https://webhook.site/...
https://pastebin.example/...
https://discord.com/api/webhooks/...
https://api.telegram.org/bot.../sendMessage
```

## Manual workflow: passive scanner baseline

Purpose: confirm current unprivileged fake-fixture scanner behavior before privileged tests.

1. Build the project in the disposable VM.
2. Run the fake-fixture tests only:

```bash
cargo test -p skynet-edr-daemon --test linux_passive_scanner --all-features
```

Expected result:

- Tests pass without root.
- Events reference fixture-relative paths only.
- Serialized events do not contain absolute lab paths.
- Fake honeytokens are redacted.

## Manual workflow: auditd candidate validation

Purpose: future validation of process execution telemetry without enabling auditd in CI or default daemon startup.

Preconditions:

- VM rollback confirmed.
- auditd use explicitly approved in the blocked inputs.
- Controlled sink bound to `127.0.0.1`.
- Fake honeytoken file exists under `/opt/skynet-edr-lab/honeytokens/`.

Operator notes:

- Prefer narrowly scoped audit rules.
- Save the exact rules applied.
- Remove rules after the test.
- Export only redacted event summaries.

Example activity to generate a benign signal:

```bash
# Manual workflow only. Fake file and loopback destination only.
printf '%s\n' 'SKYNET_EDR_FAKE_TOKEN=skynet-edr-fake-token-000000000000' \
  | curl --data-binary @- http://127.0.0.1:18080/skynet-edr-lab
```

Expected Skynet-EDR behavior for future implementation:

- Detect process plus loopback network activity as lab telemetry.
- Treat fake honeytoken transmission as a redaction test, not a real incident.
- Preserve command metadata without storing raw secret-looking values.

## Manual workflow: filesystem watcher candidate validation

Purpose: future validation of sensitive-path file watcher behavior.

Preconditions:

- VM rollback confirmed.
- inotify/fanotify use explicitly approved.
- Test directory is lab-only.

Example activity:

```bash
sudo mkdir -p /opt/skynet-edr-lab/honeytokens
sudo sh -c "printf '%s\n' 'FAKE HONEYTOKEN FOR SKYNET-EDR LAB ONLY' > /opt/skynet-edr-lab/honeytokens/README.txt"
sudo sh -c "printf '%s\n' 'SKYNET_EDR_FAKE_TOKEN=skynet-edr-fake-token-000000000000' > /opt/skynet-edr-lab/honeytokens/fake.env"
```

Expected Skynet-EDR behavior for future implementation:

- Identify reads under the configured lab honeytoken directory.
- Redact secret-looking values before storage or alerting.
- Avoid watching real home directories unless explicitly configured for that disposable VM.

## Manual workflow: network egress candidate validation

Purpose: future validation of network metadata ingestion from nftables/iptables logs or equivalent.

Preconditions:

- VM rollback confirmed.
- Firewall logging explicitly approved.
- Log volume limit defined.
- Controlled sink bound to `127.0.0.1`, or egress allowlist is documented.

Expected Skynet-EDR behavior for future implementation:

- Capture destination IP, port, protocol, timestamp, and process correlation where available.
- Mark loopback sink events as lab-controlled.
- Do not capture payload bodies by default.
- Do not transmit telemetry to external services by default.

## Evidence handling

Allowed artifacts:

- Redacted JSON events.
- Redacted JSONL incident exports.
- Exact command transcript with fake honeytokens redacted.
- Sensor status summaries.
- VM OS/kernel/version metadata.

Forbidden artifacts:

- Raw packet captures containing payloads.
- Real credential files.
- Full Hermes auth files.
- Private SSH keys.
- Cloud provider credentials.
- Unredacted terminal history.

## Cleanup and rollback

At the end of every manual lab run:

1. Stop Skynet-EDR test processes.
2. Stop the controlled sink.
3. Remove temporary audit/firewall/watch rules.
4. Export only redacted artifacts.
5. Destroy or rollback the disposable VM snapshot.
6. Note any deviations, skipped steps, or unexpected sensor behavior.

## Repository guardrails

- Unit and integration tests stay fake-fixture based.
- Documentation tests enforce the presence of manual-only, disposable-VM, fake-honeytoken, controlled-sink, and blocked-input requirements.
- Any future privileged sensor implementation must be opt-in, feature-gated where practical, and disabled by default.
- Any future automated lab runner must require a Frederic-approved VM descriptor and must fail closed when the descriptor is missing.
