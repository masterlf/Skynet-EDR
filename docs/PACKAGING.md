# Skynet-EDR packaging and release plan

This document defines the Linux packaging baseline for Skynet-EDR. The product target is local AI-agent protection for Hermes Agent, OpenClaw, Codex, Claude Code, and similar tool-using runtimes.

Skynet-EDR is security software. Packaging, install scripts, maintainer scripts, service units, and release workflows are privileged attack surface and must be reviewed like production code.

## Packaging objectives

1. Make Skynet-EDR installable on common Linux distributions.
2. Keep the default deployment passive, local, and least-privileged.
3. Support packaged installs and custom unpackaged installs.
4. Prepare for signed releases, SBOMs, provenance, and package repositories.
5. Avoid promising production support before install/upgrade/rollback tests exist.

## Distribution targets

| Target | Artifact | Priority | Notes |
|---|---|---:|---|
| Ubuntu / Debian / Mint | `.deb` | 1 | First-class Linux target. |
| RHEL / Fedora | `.rpm` | 2 | Requires SELinux-aware docs and later policy packaging. |
| Arch Linux | `.pkg.tar.zst` / PKGBUILD-style recipe | 3 | Best-effort rolling support. |
| Other Linux | `.tar.gz` custom install | 4 | Advanced-user and air-gapped path. |

Use `nFPM` as the first cross-distribution packaging generator. Native distro packaging can be added later when repository publishing and policy packaging mature.

## Package contents

Required files:

```text
/usr/bin/skynet-edr
/usr/bin/skynet-edr-daemon
/usr/lib/systemd/system/skynet-edr.service
/usr/lib/sysusers.d/skynet-edr.conf
/usr/lib/tmpfiles.d/skynet-edr.conf
/etc/skynet-edr/config.toml
/usr/share/skynet-edr/hermes-plugin/skynet-edr/
/usr/bin/skynet-edr-install-hermes-plugin
/usr/share/doc/skynet-edr/
/usr/share/licenses/skynet-edr/LICENSE
```

Runtime directories created by systemd/tpmfiles:

```text
/etc/skynet-edr
/etc/skynet-edr/rules.d
/etc/skynet-edr/agents.d
/var/lib/skynet-edr
/var/log/skynet-edr
/var/cache/skynet-edr
/run/skynet-edr
```

## Service and privilege model

Default package posture:

- Dedicated `skynet-edr` user/group.
- No root daemon by default.
- No privileged Linux sensors auto-started by default.
- Local API remains loopback-only.
- Network egress disabled at the service level unless explicitly needed later for alert forwarding.
- Main daemon stores and correlates redacted events.
- Future privileged sensors should be separate helper processes with narrow capabilities.

The daemon exposes a conservative long-running `run --config <path>` path. Therefore:

- package assets include the service unit wired to the daemon,
- package post-install must not auto-enable/start the service,
- CI validates static assets, binaries, and the passive daemon startup path,
- production service checks should still verify passive config and systemd hardening before enablement.

## AI-agent adapter packaging

Skynet-EDR should not be tightly coupled to one AI agent. Package configuration reserves `/etc/skynet-edr/agents.d/` for adapter definitions.

Initial adapter posture:

| Agent | Package/default handling |
|---|---|
| Hermes Agent | first-class config example and event ingestion docs. |
| OpenClaw | generic adapter placeholder until trace format is verified. |
| Codex | generic adapter placeholder; prefer local trace/event export over scraping. |
| Claude Code | generic adapter placeholder; prefer local trace/event export over scraping. |
| Similar agents | generic JSON/JSONL event ingestion and process/file/network correlation. |

Future split packages may include:

```text
skynet-edr
skynet-edr-rules
skynet-edr-agent-integrations
skynet-edr-sensor-linux
```

Do not grant broad read access to AI-agent secrets as a packaging shortcut. Use explicit integration paths, agent-owned audit exports, local read-only APIs, or narrow privileged helper sensors.

## Release artifact set

For each release tag:

```text
skynet-edr_VERSION_linux_amd64.deb
skynet-edr_VERSION_linux_x86_64.rpm
skynet-edr_VERSION_linux_x86_64.pkg.tar.zst
skynet-edr_VERSION_linux_x86_64.tar.gz
checksums.txt
checksums.txt.sig
SBOM.spdx.json
SBOM.cyclonedx.json
release-notes.md
upgrade-notes.md
rollback-notes.md
```

Later production releases should add:

- cosign signatures,
- SLSA/in-toto provenance,
- signed APT repository metadata,
- signed RPM repository metadata,
- verified Arch package recipe/source signatures.

## Package build commands

Local package baseline:

```bash
cargo build --release --workspace --bins
packaging/scripts/validate-packaging.sh

SKYNET_EDR_VERSION=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name=="skynet-edr-cli") | .version') \
NFPM_ARCH=amd64 \
nfpm package --config packaging/nfpm.yaml --packager deb --target dist/skynet-edr.deb

SKYNET_EDR_VERSION=$SKYNET_EDR_VERSION \
NFPM_ARCH=amd64 \
nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/skynet-edr.rpm
```

Custom tarball:

```bash
packaging/scripts/build-tarball.sh
```

## Validation gates

Minimum PR gate:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
packaging/scripts/validate-packaging.sh
git diff --check
```

Release gate once package tooling is available:

```bash
cargo build --release --workspace --bins
skynet-edr --version
skynet-edr-daemon --version
skynet-edr-daemon status
nfpm package --config packaging/nfpm.yaml --packager deb --target dist/skynet-edr.deb
nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/skynet-edr.rpm
nfpm package --config packaging/nfpm.yaml --packager archlinux --target dist/skynet-edr.pkg.tar.zst
dpkg-deb --contents dist/skynet-edr.deb
rpm -qpl dist/skynet-edr.rpm
tar -tf dist/skynet-edr.pkg.tar.zst
```

Smoke tests should eventually run in clean Ubuntu/Debian/Fedora/Arch containers or VMs. Do not call a package production-ready without install/upgrade/remove tests.

## Maintainer script rules

Package scripts must be:

- idempotent,
- minimal,
- auditable,
- non-networking,
- safe if run multiple times,
- preserving operator config and state,
- explicit about destructive purge.

Package install may create users/directories and reload systemd. It should not:

- auto-enable privileged sensors,
- change firewall rules,
- disable SELinux/AppArmor,
- make AI-agent credential directories readable,
- start network listeners on non-loopback addresses,
- fetch remote code.

## Signing and provenance plan

Before public production packages:

1. Signed release tags.
2. `checksums.txt` for all artifacts.
3. Signed checksum file.
4. SBOMs from locked Rust dependencies.
5. Artifact signatures via cosign or GPG.
6. Protected release workflow.
7. Separate repository signing keys for APT/RPM repositories.
8. Documented key rotation and revocation.

## Upgrade and rollback policy

Package upgrades must preserve:

- `/etc/skynet-edr/`,
- `/var/lib/skynet-edr/`,
- operator-modified rules,
- local AI-agent adapter configuration.

Database migrations must be versioned, idempotent, and backed up before mutation. Until migrations exist, packages should avoid modifying the database beyond explicit operator commands.

Rollback notes must accompany every release once packages are published.

## Current limitation

This repository currently contains a daemon skeleton. The package/service baseline is useful now, but production service enablement must wait for a persistent daemon command and tested runtime behavior.
