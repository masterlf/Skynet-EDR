# Release process

This page turns the packaging plan into an operator checklist for publishing Skynet-EDR releases.

For package formats and maintainer-script rules, see [Packaging plan](PACKAGING.md). For user install and rollback instructions, see [Install](INSTALL.md).

## Release objectives

A release should be:

- installable on the documented Linux targets;
- checksum-verifiable;
- reproducible enough to inspect generated artifacts;
- clear about current MVP limitations;
- backed by test, lint, packaging, and documentation gates;
- safe to roll back.

## Pre-release checklist

Run from a clean release branch or tag candidate:

```bash
git status --short
python3 packaging/scripts/check-docs.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
packaging/scripts/validate-packaging.sh
```

If optional tools are available, also run the security checks documented in [Security tooling options](SECURITY_TOOLING_OPTIONS.md) and [Quality and security engineering](QUALITY_AND_SECURITY_ENGINEERING.md#recommended-tooling).

## Version and changelog hygiene

Before building artifacts:

1. Confirm the version in package metadata matches the intended tag.
2. Confirm README and [Install](INSTALL.md) describe the package set accurately.
3. Confirm [Canonical event schema](EVENT_SCHEMA.md) still names the supported schema version.
4. Confirm release notes distinguish implemented behavior from roadmap intent.
5. Confirm no docs, fixtures, screenshots, logs, or generated artifacts contain real secrets.

## Build artifacts

Use the package build commands in [Packaging plan](PACKAGING.md#package-build-commands). The expected artifact set is described in [Packaging plan](PACKAGING.md#release-artifact-set).

Current release assets should include Linux packages such as `.deb`, `.rpm`, Arch `.pkg.tar.zst`, a custom `.tar.gz`, and `checksums.txt` when the release workflow supports them.

## Validate artifacts

Follow the validation gates in [Packaging plan](PACKAGING.md#validation-gates). At minimum:

- verify package metadata;
- inspect package contents;
- verify checksums directly;
- install in clean test environments where possible;
- verify `skynet-edr status` and basic CLI commands;
- verify uninstall/rollback behavior for package-manager formats.

## Publish

1. Create or update the release tag according to the repository's GitHub workflow.
2. Let release workflows build and upload artifacts.
3. Verify the published assets and checksums from a clean download.
4. Update release notes with install, upgrade, rollback, and known-limitation sections.
5. Confirm [Install](INSTALL.md#download-release-packages) remains accurate.

## Post-release smoke test

On a clean Linux host or disposable VM:

```bash
# package-manager install command from docs/INSTALL.md
skynet-edr status
skynet-edr store init
skynet-edr events list --limit 5
skynet-edr incidents list --limit 5
```

If any command fails, treat it as a release blocker or publish an explicit known issue with rollback instructions. No silent shrugging; that is how tiny yak problems become production marmots.

## Rollback

Rollback policy is documented in [Packaging plan](PACKAGING.md#upgrade-and-rollback-policy) and user-facing commands are in [Install](INSTALL.md#upgrade-and-rollback).

A release is not complete until rollback is understandable by someone who did not build the artifact.
