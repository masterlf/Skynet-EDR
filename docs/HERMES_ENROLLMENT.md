# Fail-closed Hermes enrollment (S3)

## Status

The repository ships a bounded enrollment transaction and deterministic fixture adapter contract. It does **not** yet ship a privileged live-host adapter, and therefore no real host may currently be reported as autonomously `ENROLLED`. The later clean-host gate below is mandatory before changing that claim.

The only compatibility cell exercised by the transaction tests is Ubuntu 24.04, `x86_64`/`amd64`, systemd, Hermes `0.19.0`, Skynet-EDR plugin `0.4.1`. Every other distro, architecture, init system, Hermes version, dashboard-only runtime, and global-role setup is unsupported or unproven and fails closed.

## Command

`skynet-edr-hermes-enroll check|apply|verify|unenroll` consumes:

- `--request`: private JSON naming the OS account and numeric UID, exact absolute `hermes_home`, named profile, exact host tuple, exact Hermes/plugin versions, reviewed unit names, restart authorization, socket DAC+UID decisions, and an allowlisted file manifest containing SHA-256, size, mode, and owner;
- `--source`: exact trusted package payload directory. Non-fixture requests are
  pinned to `/usr/share/skynet-edr/hermes-plugin/skynet-edr`; `fixture: true` is
  test-only and must never be accepted by a future live adapter;
- `--state-root`: private tool-owned lock, transaction metadata, prior generation, and preserved evidence root;
- `--observations`: private fresh observation JSON produced by the reviewed boundary adapter;
- `--adapter`: required only for mutations; an absolute executable invoked without a shell.

The request also pins the canonical `manifest_sha256`; changing any manifest
field without updating that digest fails closed. The compatibility name
`skynet-edr-install-hermes-plugin` delegates to this command. The former advisory
copy-and-print path is intentionally gone.

Output is one bounded JSON object with fixed `schema`, `state`, `category`, and `noop` fields. Raw request values, paths, environment, event data, credentials, and child stdout/stderr are never echoed. Only `ENROLLED` exits zero for `check`, `apply`, and `verify`. Idempotent `unenroll` exits zero in `ABSENT`.

## Transaction and trust boundary

`check` is read-only. It resolves account/UID, rejects implicit root, relative/traversal/control-character paths, symlink/non-directory components, writable untrusted ancestors, unsupported host/version tuples, ambiguous authorization, malformed units, non-allowlisted payload entries, special/symlink/hard-linked files, and byte/size/mode/owner/version drift.

`apply` serializes on a private lock, re-checks state, stages allowlisted files with `O_NOFOLLOW`, fsyncs files/directories, atomically renames the complete generation, preserves one prior generation, and invokes only the reviewed adapter actions. `HERMES_HOME`, `HERMES_PROFILE`, and the expected generation are passed on every adapter action. Enable, restart, and harmless real-hook actions require fresh read-back; command exit alone is never proof. Without explicit restart authorization, the result is `RELOAD_REQUIRED` and nonzero. A second verified apply is a no-op with no file/mtime/adapter churn.

`verify` rereads installed bytes and observations. It requires enabled read-back, exact loaded generation, a fresh process boundary, healthy listener and transport, zero backlog/degradation, fresh numeric UID plus `gateway` role, and a uniquely correlated committed harmless real hook that opened no incident. A synthetic canary never satisfies the hook proof.

`unenroll` disables with read-back and removes only the selected tool-owned generation/metadata. It preserves evidence state and unrelated users/profiles. Evidence purge is deliberately out of scope.

## Adapter contract

The adapter is a security boundary, not arbitrary plugin output. It receives one action argument: `enable`, `disable`, `restart`, or `hook`. It receives a minimal environment containing exact `HOME`, `HERMES_HOME`, `HERMES_PROFILE`, `SKYNET_EDR_GENERATION`, and `SKYNET_EDR_OBSERVATIONS`. It must use typed parsers for daemon config, exact per-unit role drop-ins, exact reviewed units, socket DAC and numeric UID authorization. It must never set a global role or silently broaden units/groups/config. It updates the private observation document atomically only after fresh read-back.

The repository fixture adapter is mocked at service/config boundaries and is not permission to mutate a live system.

## Mandatory clean-host promotion gate

Before any support claim changes from unproven to supported, a separate reviewed task must ship and exercise the live adapter in a disposable booted Ubuntu 24.04 amd64/systemd host with Hermes 0.19.0. The gate must prove package manifest ownership, temporary target user/profile/custom `HERMES_HOME`, exact daemon TOML edits, socket group plus `SO_PEERCRED` UID allowlist, exact unit drop-ins, approved restart and rollback, post-restart v2 producer health, real correlated hook receipt, fake-secret byte scans, concurrent applies, fault injection at copy/fsync/rename/enable/config/drop-in/restart/hook stages, package partial-upgrade/removal, and repeatable unenroll while preserving fallback/checkpoint/log/database evidence. No live operator host or profile may be used.

Until that gate passes, the literal operational verdict is `S3_IMPLEMENTATION_BLOCK`.
