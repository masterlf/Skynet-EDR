# DEB/systemd deployment and rollback

This runbook is intentionally bounded to Ubuntu/Debian `amd64`, systemd, and the Skynet-EDR DEB. It does not authorize RPM, Arch, tarball, live repair, database restore, or Hermes enrollment.

## Hard safety boundary

Never extract or replay a package payload as root on a live or persistent host. `dpkg-deb -x`, `dpkg-deb --control`, `rpm2cpio | cpio`, `tar -x`, `bsdtar -x`, and archive GUIs are inspection tools only inside a disposable, non-root, network-isolated environment with no writable host mount. Production software changes use the native package manager only. If a disposable environment or required evidence is unavailable, the deployment is BLOCKED.

The package-owned `/usr/libexec/skynet-edr/deploy-verify` is read-only and has no repair mode. A missing path, wrong object type, owner/group/mode mismatch, service-user DAC failure, wrong systemd identity, stale executable, non-200 API response, malformed JSON, version mismatch, degraded ingestion, or read-only schema failure returns nonzero. Do not convert its failure into an automated `chown`, `chmod`, restart, reinstall, or database operation.

## Before the change

1. Verify the candidate and rollback DEB checksums against the reviewed release manifest.
2. Record the installed version: `dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' skynet-edr`.
3. Record `systemctl show skynet-edr.service -p ActiveState -p SubState -p MainPID -p ExecMainStartTimestampMonotonic`.
4. Create and verify a consistent SQLite backup with SQLite's `.backup` command to a root-only backup filesystem. Never copy a live SQLite file. Backup failure blocks the change.
5. Run `sudo /usr/libexec/skynet-edr/deploy-verify --expected-product-version <canonical-semver> --expected-deb-version <native-deb-version>`. Both inputs use exact equality; any failure blocks the change and this command never repairs state.
6. Obtain explicit approval for the exact DEB digest, host, window, expected restart, and rollback DEB digest.

## Deploy

Install exactly once through APT:

```sh
sudo apt-get install --no-install-recommends ./skynet-edr_<version>_amd64.deb
```

Do not use `dpkg -i`, force flags, script suppression, copied binaries, tar installers, or package extraction. A nonzero APT exit stops the procedure. Preserve output and inspect before any retry.

Package installation and service restart are separate approvals. If the installed binary changed while `MainPID` did not, report `RESTART_REQUIRED`; do not claim health. After an approved restart, run only:

```sh
sudo systemctl restart skynet-edr.service
sudo /usr/libexec/skynet-edr/deploy-verify --expected-product-version 0.6.0-beta.1 --expected-deb-version 0.6.0~beta.1
sudo dpkg -V skynet-edr
```

Success requires an empty `dpkg -V` result and verifier `PASS`. Preserve package version, PID/start identity, verifier JSON, and journal evidence.

## Failure and rollback

Stop on the first failed check. Do not run recursive `chown`, `chmod`, `rm`, or copy; do not extract/reinstall packages as an improvised repair; do not restore SQLite automatically. Preserve the failed state and evidence.

With rollback approved and the prior checksum-verified DEB available:

```sh
sudo systemctl stop skynet-edr.service
sudo apt-get install --no-install-recommends ./skynet-edr_<previous-version>_amd64.deb
sudo systemctl start skynet-edr.service
sudo /usr/libexec/skynet-edr/deploy-verify --expected-product-version <previous-product-version> --expected-deb-version <previous-native-deb-version>
sudo dpkg -V skynet-edr
```

Rollback preserves the current database and configuration. If schema compatibility, exact path tuples, service identity, writable state, or API contracts do not pass, leave the deployment explicitly FAILED/BLOCKED and escalate. Database restore is a separate incident procedure requiring compatibility proof and approval.

## CI evidence and residual risk

Both package workflows are configured to invoke `packaging/scripts/vm-smoke.sh` only after passing the GitHub Actions, `runner.environment=github-hosted`, and explicit disposable-smoke interlocks. The configured gate is intended to pre-create root-owned state, install with APT, prove the installed verifier is byte-identical to the reviewed source and package-integrity-clean, start the real systemd unit, verify the real `skynet-edr` UID and writable state, check status/risks/rules HTTP 200 contracts, then inject root ownership drift and prove the installed verifier rejects it. Exact-final-tree hosted execution evidence remains pending until those jobs are green and retained.

This v0.6.0-beta.1 prerelease does not qualify RPM, Arch, non-systemd, multi-host orchestration, database downgrade compatibility, production auto-repair, or Hermes runtime reload/enrollment. Those remain blocked until their own disposable native gates exist.
