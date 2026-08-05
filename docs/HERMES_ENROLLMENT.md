# Fail-closed Hermes enrollment (S3)

## Status

The repository ships a bounded enrollment transaction, deterministic fixture contract, and a package-owned privileged adapter at `/usr/libexec/skynet-edr/hermes-enrollment-adapter.py`. The adapter is reviewable production code, but its exact Hermes 0.19.0 CLI/read-back and booted-systemd behavior has not yet passed the disposable clean-host gate. Therefore no real host may currently be reported as autonomously `ENROLLED`; the later gate remains mandatory before changing that claim.

The only compatibility cell exercised by the transaction tests is Ubuntu 24.04, `x86_64`/`amd64`, systemd, Hermes `0.19.0`, Skynet-EDR plugin `0.4.1`. Every other distro, architecture, init system, Hermes version, dashboard-only runtime, and global-role setup is unsupported or unproven and fails closed.

## Command

`skynet-edr-hermes-enroll check|apply|verify|unenroll` consumes:

- `--request`: private JSON naming the OS account and numeric UID, exact absolute `hermes_home`, named profile, exact host tuple, exact Hermes/plugin versions, reviewed unit names, restart authorization, and socket DAC+UID decisions;
- `--source`: exact trusted package payload directory. Non-fixture requests are
  pinned to `/usr/share/skynet-edr/hermes-plugin/skynet-edr`; `fixture: true` is
  test-only and must never be accepted by a future live adapter;
- `--state-root`: production is pinned to root-owned mode-`0700` `/var/lib/skynet-edr-hermes-enrollment`, outside daemon-writable `/var/lib/skynet-edr`; caller-selected roots are rejected by the shipped entry point;
- `--observations`: production accepts only the pinned base path, then derives metadata and observations under `targets/<sha256(uid,profile)>` inside that private root. The transaction, not the target process, atomically writes each isolated bounded adapter result as `0600`;
- `--adapter`: mutations are pinned to the root-owned, non-writable package adapter path. Arbitrary adapters are accepted only by the in-process deterministic test harness.

The production payload identity comes from the root-owned package manifest at
`/usr/share/skynet-edr/hermes-plugin/manifest.json`; caller-supplied manifest
fields are ignored outside deterministic tests. The compatibility name
`skynet-edr-install-hermes-plugin` delegates to this command. The former advisory
copy-and-print path is intentionally gone.

Output is one bounded JSON object with fixed `schema`, `state`, `category`, and `noop` fields. Raw request values, paths, environment, event data, credentials, and child stdout/stderr are never echoed. Only `ENROLLED` exits zero for `check`, `apply`, and `verify`. Idempotent `unenroll` exits zero in `ABSENT`.

## Transaction and trust boundary

`check` is read-only. It resolves account/UID, rejects implicit root, relative/traversal/control-character paths, symlink/non-directory components, writable untrusted ancestors, unsupported host/version tuples, ambiguous authorization, malformed units, non-allowlisted payload entries, special/symlink/hard-linked files, and byte/size/mode/owner/version drift.

`apply` serializes on a private lock, re-checks state, stages allowlisted files with `O_NOFOLLOW`, fsyncs files/directories, atomically renames the complete backend and Desktop generations, preserves prior bytes plus metadata, and invokes only the reviewed adapter actions. `HERMES_HOME`, `HERMES_PROFILE`, and the expected generation are passed on every adapter action. Target Hermes actions execute after an explicit UID/GID/supplementary-group credential drop; installed files are owned by that numeric UID. Each action has a random nonce, and the parent accepts only a bounded adapter JSON result before atomically replacing the private observation. The final hook nonce is bound into enrollment metadata and expires after 30 seconds, so stale/replayed observations fail closed. Without explicit restart authorization, the result is `RELOAD_REQUIRED` and nonzero. A second freshly verified apply is a no-op with no file/mtime/adapter churn.

`verify` rereads installed bytes and observations. It requires enabled read-back, exact loaded generation, a fresh process boundary, healthy listener and transport, zero backlog/degradation, fresh numeric UID plus `gateway` role, and a uniquely correlated committed harmless real hook that opened no incident. A synthetic canary never satisfies the hook proof.

`unenroll` disables with fresh nonce-bound read-back and removes only matching selected backend/Desktop generations and metadata. It preserves evidence state and unrelated users/profiles. Evidence purge is deliberately out of scope.

## Adapter contract

The adapter is a security boundary, not arbitrary plugin output. It receives one action argument: privileged `prepare`, `rollback`, or `restart`, or target-identity `enable`, `disable`, or `hook`. It receives a minimal environment containing exact `HOME`, `HERMES_HOME`, `HERMES_PROFILE`, generation, target UID, action, and random nonce. Target actions run as the requested non-root identity; host preparation, rollback, and restart remain privileged and bounded. The adapter returns one bounded JSON observation on stdout; stdout/stderr are never forwarded, and the parent writes trusted metadata plus the result privately.

`prepare` accepts no path overrides. It edits only `/etc/skynet-edr/config.toml`, the exact `skynet-edr-ingest` group, and `/etc/systemd/user/hermes-gateway.service.d/50-skynet-edr.conf`. The TOML parser rejects duplicate/missing/mistyped owned keys, nonstandard socket/group values, root authorization, and roles other than `gateway`; the serializer changes only `enabled`, `socket_group`, `allowed_uids`, `allow_root`, and `required_reported_roles`. The adapter snapshots exact prior config/drop-in bytes, ownership, modes, and prior group membership in private root-owned state before mutation. `rollback` restores that snapshot and removes only membership it added. Child output is capped at 64 KiB, duplicate-key JSON is rejected, and raw Hermes/systemctl/API diagnostics are discarded.

The only reviewed producer unit is `hermes-gateway.service`; dashboard, template, caller-selected, and multiple-unit requests fail closed. The adapter uses fixed `/usr/bin/hermes` and `/usr/bin/systemctl` paths, CLI enable/disable plus JSON list read-back, targeted daemon and user-unit restarts, fixed loopback daemon status, and a fixed no-tool enrollment session to require a newer committed real-hook timestamp. Those exact external contracts remain unproven until the clean-host gate passes.

The fixture tests mock service/config boundaries and are not permission to mutate a live system.

## Mandatory clean-host promotion gate

Before any support claim changes from unproven to supported, a separate reviewed task must ship and exercise the live adapter in a disposable booted Ubuntu 24.04 amd64/systemd host with Hermes 0.19.0. The gate must prove package manifest ownership, temporary target user/profile/custom `HERMES_HOME`, exact daemon TOML edits, socket group plus `SO_PEERCRED` UID allowlist, exact unit drop-ins, approved restart and rollback, post-restart v2 producer health, real correlated hook receipt, fake-secret byte scans, concurrent applies, fault injection at copy/fsync/rename/enable/config/drop-in/restart/hook stages, package partial-upgrade/removal, and repeatable unenroll while preserving fallback/checkpoint/log/database evidence. No live operator host or profile may be used.

Until that gate passes, the literal operational verdict is `S3_ADAPTER_BLOCK`.
