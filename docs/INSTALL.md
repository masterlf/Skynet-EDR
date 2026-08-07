# Skynet-EDR Linux installation guide

Skynet-EDR is currently a pre-production, passive-first AI-agent Detection and Response project. The installable prerelease has a shipped live Hermes producer only; OpenClaw, Codex, Claude Code, and similar runtimes require an external conforming producer and are not shipped live integrations.

The install goal is conservative: collect and normalize local AI-agent security evidence without creating a new root-level attack surface. No privileged runtime sensor is enabled by default.

## Supported Linux scope

| Tier | Distributions | Install path | Support promise |
|---|---|---|---|
| Tier 1 | Ubuntu 24.04 `x86_64`/`amd64` | `.deb`, custom tarball | Clean-container install/remove/purge evidence without service start; evaluation support for that package lifecycle only. |
| Tier 2 | Published `x86_64`/`amd64` artifacts for Debian, Mint, RHEL-compatible Linux, Fedora, Arch, and custom tarball targets | `.deb`, `.rpm`, Arch package, custom tarball | Lab/advanced-user availability only; no native runtime-support promise at this baseline. |

Initial architecture targets:

- `x86_64` / `amd64`: primary.
- `aarch64` / `arm64`, musl/Alpine, non-systemd hosts, Windows, and macOS: unsupported or unproven.

The published RPM and Arch artifacts do not establish RHEL/Fedora/Arch runtime compatibility. The custom tarball does not provision the `skynet-edr-ingest` group or sysusers/tmpfiles state needed for authenticated continuous ingress. See the [MVP public support contract](MVP_SUPPORT_MATRIX.md) before enabling a daemon or producer.

## What is installed

Packaged installs should create this layout:

```text
/usr/bin/skynet-edr
/usr/bin/skynet-edr-daemon
/etc/skynet-edr/config.toml
/etc/skynet-edr/rules.d/
/etc/skynet-edr/agents.d/
/var/lib/skynet-edr/skynet.sqlite
/var/log/skynet-edr/
/run/skynet-edr/
/run/skynet-edr-ingest/
/usr/lib/systemd/system/skynet-edr.service
/usr/lib/sysusers.d/skynet-edr.conf
/usr/lib/tmpfiles.d/skynet-edr.conf
```

A dedicated locked service account is used:

```text
user:  skynet-edr
group: skynet-edr
ingress group: skynet-edr-ingest
home:  /var/lib/skynet-edr
shell: /usr/sbin/nologin or equivalent
```

Default permissions:

```text
/etc/skynet-edr/                  root:skynet-edr 0750
/etc/skynet-edr/config.toml   root:skynet-edr 0640
/etc/skynet-edr/rules.d/          root:skynet-edr 0750
/etc/skynet-edr/agents.d/         root:skynet-edr 0750
/var/lib/skynet-edr/              skynet-edr:skynet-edr 0750
/var/log/skynet-edr/              skynet-edr:skynet-edr 0750
/run/skynet-edr/                  skynet-edr:skynet-edr 0750
/run/skynet-edr-ingest/           skynet-edr:skynet-edr-ingest 0750
/usr/bin/skynet-edr*              root:root 0755
```

## Install from source for development

Prerequisites:

- Rust stable toolchain.
- `cargo`.
- SQLite build dependencies as required by `rusqlite` on your distribution.

Build and install locally:

```bash
git clone https://github.com/masterlf/Skynet-EDR.git
cd Skynet-EDR
cargo build --release --workspace --bins

sudo install -d -m 0755 /usr/local/bin
sudo install -m 0755 target/release/skynet-edr /usr/local/bin/skynet-edr
sudo install -m 0755 target/release/skynet-edr-daemon /usr/local/bin/skynet-edr-daemon

skynet-edr --version
skynet-edr-daemon --version
skynet-edr-install-hermes-plugin --help
skynet-edr-daemon status
```

Initialize local state:

```bash
sudo install -d -m 0750 -o root -g root /etc/skynet-edr
sudo install -d -m 0750 /var/lib/skynet-edr
sudo skynet-edr store init --db /var/lib/skynet-edr/skynet.sqlite
```

For development-only tests, running from `target/release` without installing is also acceptable.

## Download release packages

Download packages from the GitHub Releases page:

```text
https://github.com/masterlf/Skynet-EDR/releases
```

For `v0.5.0`, the expected Linux `amd64` artifacts are:

```text
skynet-edr_0.5.0_amd64.deb
skynet-edr-0.5.0-1.x86_64.rpm
skynet-edr-0.5.0-1-x86_64.pkg.tar.zst
skynet-edr-0.5.0-x86_64-unknown-linux-gnu.tar.gz
checksums.txt
```

Verify downloaded files before installation:

```bash
sha256sum -c checksums.txt --ignore-missing
```

## Install from `.deb` on Ubuntu, Debian, or Mint

After downloading the `.deb` and `checksums.txt` from the release:

```bash
sha256sum -c checksums.txt --ignore-missing
sudo apt install ./skynet-edr_0.5.0_amd64.deb
skynet-edr --version
skynet-edr-daemon --version
skynet-edr-install-hermes-plugin --help
skynet-edr-daemon status
```

Packages should not auto-enable privileged sensors. Enable the daemon only after reviewing `/etc/skynet-edr/config.toml`:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now skynet-edr.service
sudo systemctl status skynet-edr.service
journalctl -u skynet-edr.service -n 100 --no-pager
```

Current caveat: the service starts the conservative passive daemon path. Review `/etc/skynet-edr/config.toml` before enablement; privileged sensors remain disabled and unsupported by the MVP service.

## Enroll the Hermes plugin

The historical advisory copier has been removed because copied bytes and a
successful enable command cannot prove enrollment. `skynet-edr-install-hermes-plugin`
now delegates to the machine-readable `skynet-edr-hermes-enroll` transaction.
See [Fail-closed Hermes enrollment](HERMES_ENROLLMENT.md) for its exact request,
manifest, observation, adapter, rollback, and clean-host gate contracts.

The repository ships the transaction, deterministic boundary fixtures, and the
root-owned adapter at `/usr/libexec/skynet-edr/hermes-enrollment-adapter.py`.
The adapter's exact Hermes 0.19.0 CLI/read-back and booted-systemd contract has
not yet passed the disposable clean-host gate. Therefore no live deployment may
yet claim autonomous `ENROLLED`; the current operational verdict is
`S3_ADAPTER_BLOCK`. Do not recreate the removed copy/enable/manual-restart
sequence as a parallel success path.

The plugin worker sends to `/run/skynet-edr-ingest/ingest.sock`. During daemon
outages it writes a private versioned fallback under:

```text
~/.local/state/skynet-edr/hermes/skynet-edr-plugin.log
~/.local/state/skynet-edr/hermes/events-v1.jsonl
~/.local/state/skynet-edr/hermes/events-v1.offset
```

Legacy manual ingestion remains available for an explicitly selected spool:

```bash
skynet-edr events ingest-spool \
  --db /var/lib/skynet-edr/skynet.sqlite \
  --spool ~/.local/state/skynet-edr/hermes/events-v1.jsonl \
  --checkpoint ~/.local/state/skynet-edr/hermes/manual-import.offset
```

See [Hermes plugin telemetry](HERMES_PLUGIN_TELEMETRY.md) for the hook model,
logging guarantees, and environment variables. Use [Continuous ingestion operations](OPERATIONS.md#continuous-ingestion-operations) for the authoritative enrollment, socket/UID boundary, health counters, fallback policy, canary, restart, and rollback runbook.

## Install from `.rpm` on RHEL-compatible Linux or Fedora

After downloading the `.rpm` and `checksums.txt` from the release:

```bash
sha256sum -c checksums.txt --ignore-missing
sudo dnf install ./skynet-edr-0.5.0-1.x86_64.rpm
skynet-edr --version
skynet-edr-daemon --version
skynet-edr-install-hermes-plugin --help
skynet-edr-daemon status
```

Then review config and enable manually:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now skynet-edr.service
sudo systemctl status skynet-edr.service
```

SELinux note: Skynet-EDR should not require disabling SELinux. If future sensors need access to home directories, audit logs, eBPF, or agent runtime sockets, ship a narrow SELinux policy module instead of telling users to set permissive mode. No circus with SELinux, merci.

## Install on Arch Linux

After downloading the Arch package and `checksums.txt` from the release:

```bash
sha256sum -c checksums.txt --ignore-missing
sudo pacman -U ./skynet-edr-0.5.0-1-x86_64.pkg.tar.zst
skynet-edr --version
skynet-edr-daemon status
```

Arch is treated as rolling best-effort until continuous package smoke tests exist.

## Custom unpackaged install

The custom tarball is for labs, air-gapped hosts, or unsupported distributions.

Expected tarball layout:

```text
skynet-edr-VERSION-TARGET/
  bin/skynet-edr
  bin/skynet-edr-daemon
  packaging/config/config.toml
  packaging/systemd/skynet-edr.service
  packaging/sysusers/skynet-edr.conf
  packaging/tmpfiles/skynet-edr.conf
  install.sh
  uninstall.sh
  skynet-edr-install-hermes-plugin.sh
  skynet-edr-hermes-enroll.py
  integrations/hermes/skynet-edr/plugin.yaml
  integrations/hermes/skynet-edr/__init__.py
  integrations/hermes/skynet-edr/README.md
  SHA256SUMS
  README.install.md
```

Install:

```bash
tar -xzf skynet-edr-VERSION-TARGET.tar.gz
cd skynet-edr-VERSION-TARGET
sha256sum -c SHA256SUMS
sudo ./install.sh
```

Optional paths:

```bash
sudo ./install.sh --prefix /opt/skynet-edr --no-systemd
sudo ./install.sh --no-systemd
```

Custom prefixes require `--no-systemd` because the packaged unit deliberately
uses `/usr/bin`. The prefix changes binary placement only; configuration, state,
documentation, and the optional Hermes plugin template retain their standard
system paths.

Uninstall while preserving data:

```bash
sudo ./uninstall.sh
```

Purge local state only when you intentionally want to remove evidence/configuration:

```bash
sudo ./uninstall.sh --purge
```

Production warning: do not install Skynet-EDR with `curl | sudo sh`. Download artifacts, verify signatures/checksums, then install.

## AI-agent protection scope

Skynet-EDR should protect local AI-agent activity through adapters and normalized event ingestion rather than broad secret scraping.

Initial target agents:

| Agent/runtime | Protection approach |
|---|---|
| Hermes Agent | Shipped passive producer path, subject to explicit enrollment and documented coverage limits. |
| OpenClaw | Adapter contract/fixture model only; no shipped live producer. |
| Codex CLI / OpenAI coding agents | External conforming producer required; no shipped live producer. |
| Claude Code | External conforming producer required; no shipped live producer. |
| Similar AI agents | External conforming producer required; no shipped live producer. |

Design rule: prefer agent-provided audit/event traces and read-only local APIs. Avoid making agent secret stores readable by the Skynet-EDR daemon unless a narrow, explicit sensor justifies it.

## Verification commands

After install:

```bash
skynet-edr --version
skynet-edr-daemon --version
skynet-edr-install-hermes-plugin --help
skynet-edr-daemon status
sudo -u skynet-edr skynet-edr store init --db /var/lib/skynet-edr/skynet.sqlite
skynet-edr doctor
skynet-edr diagnostics collect --output ./skynet-edr-diagnostics
```

`skynet-edr doctor` uses `/etc/skynet-edr/config.toml` and `/var/lib/skynet-edr/skynet.sqlite` by default. It checks readiness through loopback-only API access or plugin-spool availability and refuses non-loopback API targets instead of probing them. It does not require `rules.d` or `agents.d` to exist.

Diagnostics bundles are redaction-safe by default: no raw event export, no missing database creation, private `0700` output directory, and `0600` files. Add operator-provided evidence explicitly, for example:

```bash
journalctl -u skynet-edr.service -n 100 --no-pager > /tmp/skynet-edr-status.txt
skynet-edr diagnostics collect \
  --output ./skynet-edr-diagnostics \
  --service-status-file /tmp/skynet-edr-status.txt
```

Service checks:

```bash
systemctl status skynet-edr.service
journalctl -u skynet-edr.service --since today --no-pager
systemd-analyze verify /usr/lib/systemd/system/skynet-edr.service
systemd-analyze security skynet-edr.service
```

## Upgrade and rollback

Package upgrades must preserve:

- `/etc/skynet-edr/`
- `/var/lib/skynet-edr/`
- operator-modified rules/config

Before storage migrations become real, package scripts should back up state to:

```text
/var/lib/skynet-edr/backups/pre-upgrade-VERSION-TIMESTAMP/
```

Rollback should be documented per release:

```bash
sudo systemctl stop skynet-edr.service
sudo apt install ./previous.deb       # Debian/Ubuntu/Mint
sudo dnf downgrade ./previous.rpm     # RHEL/Fedora
sudo pacman -U ./previous.pkg.tar.zst # Arch
sudo systemctl start skynet-edr.service
```

## Uninstall

Debian/Ubuntu/Mint:

```bash
sudo systemctl disable --now skynet-edr.service || true
sudo apt remove skynet-edr
```

RHEL/Fedora:

```bash
sudo systemctl disable --now skynet-edr.service || true
sudo dnf remove skynet-edr
```

Arch:

```bash
sudo systemctl disable --now skynet-edr.service || true
sudo pacman -R skynet-edr
```

Uninstall should preserve `/etc/skynet-edr` and `/var/lib/skynet-edr` by default. Destructive purge must be explicit. Package-manager and tarball removal fail closed while a Hermes adapter transaction snapshot is active; upgrades remain allowed. Run bounded `unenroll` first rather than orphaning group, daemon, or user-unit state.

## Troubleshooting

| Symptom | Check |
|---|---|
| Service will not start | `journalctl -u skynet-edr.service -n 100 --no-pager` |
| Permission denied on DB | ownership/mode of `/var/lib/skynet-edr` and service user |
| Config unreadable | `/etc/skynet-edr` group and mode |
| RHEL/Fedora denial | `ausearch -m avc -ts recent` and SELinux policy status |
| API unreachable | verify bind is loopback-only and service is active |
| Agent evidence missing | verify the agent adapter/export path and ingestion logs |
| Operator bundle needed | `skynet-edr diagnostics collect --output ./skynet-edr-diagnostics` |

## Current limitation

The packaged daemon now has a passive long-running loop, a loopback read-only API, and authenticated bounded AF_UNIX ingestion. It still has no privileged sensor or guard-mode enforcement path. Continuous ingestion is Linux-only, the ingestion accept thread is not independently supervised, and the shipped Hermes producer leaves several implemented canonical rules dark; use the [coverage matrix](DETECTIONS.md#rule-to-producer-coverage-matrix) rather than inferring coverage from rule presence.
