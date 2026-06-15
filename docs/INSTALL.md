# Skynet-EDR Linux installation guide

Skynet-EDR is currently a pre-production, passive-first AI-agent Detection and Response project. The installation model is designed for hosts that run or supervise local AI agents such as Hermes Agent, OpenClaw, Codex, Claude Code, and similar tool-using runtimes.

The install goal is conservative: collect and normalize local AI-agent security evidence without creating a new root-level attack surface. No privileged runtime sensor is enabled by default.

## Supported Linux scope

| Tier | Distributions | Install path | Support promise |
|---|---|---|---|
| Tier 1 | Ubuntu LTS, Debian stable, Linux Mint current | `.deb`, custom tarball | Primary target once packages are published. |
| Tier 2 | RHEL-compatible Linux, Fedora current | `.rpm`, custom tarball | Supported after package smoke tests pass on clean hosts. |
| Tier 3 | Arch Linux | Arch package artifact / PKGBUILD style recipe, custom tarball | Best-effort rolling distribution support. |
| Tier 4 | Other systemd Linux distributions | custom tarball | Advanced-user path, no production claim until tested. |

Initial architecture targets:

- `x86_64` / `amd64`: primary.
- `aarch64` / `arm64`: planned after x86_64 package flow is stable.
- `musl`/Alpine and non-systemd hosts: not first-class yet.

## What is installed

Packaged installs should create this layout:

```text
/usr/bin/skynet-edr
/usr/bin/skynet-edr-daemon
/etc/skynet-edr/config.toml
/etc/skynet-edr/rules.d/
/etc/skynet-edr/agents.d/
/var/lib/skynet-edr/skynet-edr.sqlite
/var/log/skynet-edr/
/run/skynet-edr/
/usr/lib/systemd/system/skynet-edr.service
/usr/lib/sysusers.d/skynet-edr.conf
/usr/lib/tmpfiles.d/skynet-edr.conf
```

A dedicated locked service account is used:

```text
user:  skynet-edr
group: skynet-edr
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
/usr/bin/skynet-edr*              root:root 0755
```


## Versioning and artifact paths

Current workspace version: `0.1.0`. All crates in the 0.1.x line should move together because the CLI, daemon skeleton, MCP surface, docs, and packaging scripts describe one MVP product baseline.

0.1.x is pre-production. Patch releases may update documentation, package metadata, passive/read-only APIs, fixture-driven detections, and compatibility fixes. They must not quietly introduce privileged sensor auto-start, broad agent secret access, non-loopback listeners, or default network egress. Those changes need explicit documentation and review.

Build outputs use the scripts' actual paths and names:

```text
dist/skynet-edr_${VERSION}_${ARCH}.deb
dist/skynet-edr-${VERSION}-1.${ARCH}.rpm
dist/skynet-edr-${VERSION}-1-${ARCH}.pkg.tar.zst
dist/skynet-edr-${VERSION}-${TARGET}.tar.gz
```

Defaults today are `VERSION=0.1.0`, `ARCH=amd64` for nFPM package builds, and `TARGET=$(rustc -vV | awk '/host:/ {print $2}')` for the tarball unless overridden with `SKYNET_EDR_VERSION`, `NFPM_ARCH`, or `SKYNET_EDR_TARGET`.

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
skynet-edr-daemon status
```

Initialize local state:

```bash
sudo install -d -m 0750 -o root -g root /etc/skynet-edr
sudo install -d -m 0750 /var/lib/skynet-edr
sudo skynet-edr store init --db /var/lib/skynet-edr/skynet-edr.sqlite
```

For development-only tests, running from `target/release` without installing is also acceptable.

## Install from `.deb` on Ubuntu, Debian, or Mint

Once release packages are published:

```bash
sudo apt install ./skynet-edr_${VERSION}_${ARCH}.deb
skynet-edr --version
skynet-edr-daemon --version
skynet-edr-daemon status
```

Packages should not auto-enable privileged sensors. Enable the daemon only after reviewing `/etc/skynet-edr/config.toml`:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now skynet-edr.service
sudo systemctl status skynet-edr.service
journalctl -u skynet-edr.service -n 100 --no-pager
```

Current caveat: until `skynet-edr-daemon run` exists, the packaged service is a forward-looking template and should not be treated as a production long-running service.

## Install from `.rpm` on RHEL-compatible Linux or Fedora

Once release packages are published:

```bash
sudo dnf install ./skynet-edr-${VERSION}-1.${ARCH}.rpm
skynet-edr --version
skynet-edr-daemon --version
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

Once an Arch artifact or PKGBUILD-style recipe is published:

```bash
sudo pacman -U ./skynet-edr-${VERSION}-1-${ARCH}.pkg.tar.zst
skynet-edr --version
skynet-edr-daemon status
```

Arch is treated as rolling best-effort until continuous package smoke tests exist.

## Custom unpackaged install

The custom tarball is for labs, air-gapped hosts, or unsupported distributions.

Expected tarball layout:

```text
skynet-edr-${VERSION}-${TARGET}/
  bin/skynet-edr
  bin/skynet-edr-daemon
  packaging/config/config.toml
  packaging/systemd/skynet-edr.service
  packaging/sysusers/skynet-edr.conf
  packaging/tmpfiles/skynet-edr.conf
  install.sh
  uninstall.sh
  SHA256SUMS
  README.install.md
```

Install:

```bash
tar -xzf dist/skynet-edr-${VERSION}-${TARGET}.tar.gz
cd skynet-edr-${VERSION}-${TARGET}
sha256sum -c SHA256SUMS
sudo ./install.sh
```

Optional paths:

```bash
sudo PREFIX=/opt/skynet-edr ./install.sh
sudo ./install.sh --no-systemd
```

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
| Hermes Agent | Native trace/event ingestion, MCP visibility, local profile/config awareness. |
| OpenClaw | Generic agent trace ingestion, process/file/network correlation, future adapter. |
| Codex CLI / OpenAI coding agents | Terminal/tool-call trace ingestion where available; process/file/network correlation. |
| Claude Code | Tool-call trace ingestion where available; process/file/network correlation. |
| Similar AI agents | Generic JSON/JSONL trace ingestion and local runtime indicators. |

Design rule: prefer agent-provided audit/event traces and read-only local APIs. Avoid making agent secret stores readable by the Skynet-EDR daemon unless a narrow, explicit sensor justifies it.

## Verification commands

After install:

```bash
skynet-edr --version
skynet-edr-daemon --version
skynet-edr-daemon status
sudo -u skynet-edr skynet-edr store init --db /var/lib/skynet-edr/skynet-edr.sqlite
sudo -u skynet-edr skynet-edr events list --db /var/lib/skynet-edr/skynet-edr.sqlite
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

Uninstall should preserve `/etc/skynet-edr` and `/var/lib/skynet-edr` by default. Destructive purge must be explicit.

## Troubleshooting

| Symptom | Check |
|---|---|
| Service will not start | `journalctl -u skynet-edr.service -n 100 --no-pager` |
| Permission denied on DB | ownership/mode of `/var/lib/skynet-edr` and service user |
| Config unreadable | `/etc/skynet-edr` group and mode |
| RHEL/Fedora denial | `ausearch -m avc -ts recent` and SELinux policy status |
| API unreachable | verify bind is loopback-only and service is active |
| Agent evidence missing | verify the agent adapter/export path and ingestion logs |

## MVP acceptance test commands

Run these from the repository root before treating an MVP docs/package alignment change as ready:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
packaging/scripts/validate-packaging.sh
git diff --check
```

Optional release-artifact checks, when the required host tools are installed:

```bash
packaging/scripts/build-tarball.sh
packaging/scripts/build-packages.sh
tar -tf dist/skynet-edr-${VERSION}-${TARGET}.tar.gz
dpkg-deb --contents dist/skynet-edr_${VERSION}_${ARCH}.deb
rpm -qpl dist/skynet-edr-${VERSION}-1.${ARCH}.rpm
tar -tf dist/skynet-edr-${VERSION}-1-${ARCH}.pkg.tar.zst
```

## Current limitation

The repository has a daemon skeleton but not a production long-running service loop yet. The packaged systemd unit is `skynet-edr.service` and currently calls the future `skynet-edr-daemon run --config /etc/skynet-edr/config.toml` entry point, so it is a template to validate and review, not a production service to enable blindly. Packaging assets are intentionally conservative and should remain passive/read-only until the daemon runtime and sensor privilege model are implemented and tested.
