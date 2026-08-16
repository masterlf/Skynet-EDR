# Hermes 0.20 gateway dispatch compatibility spike

## Scope and verdict

This is decision evidence for task `A1-0`, not a support-matrix promotion or an
autonomous-enrollment attestation. It answers whether the v0.6 package-owned
Hermes plugin can be discovered by Hermes 0.20.0, maintain a healthy protocol-v3
`gateway` source, and emit telemetry from a real gateway dispatcher path into
the authenticated Skynet-EDR AF_UNIX listener.

**Verdict: bounded adapter port.** The plugin/discovery/hook/ingestion contracts
needed by Skynet-EDR remain compatible. Hermes 0.20.0 does not require a new
plugin architecture or a different ingestion design. The enrollment adapter's
exact Hermes-version allowlist and its transaction fixtures must be widened and
the complete clean-host enrollment gate must pass before 0.20 can be claimed as
supported. Until then, `S3_ADAPTER_BLOCK` remains the operational verdict for
autonomous enrollment.

## Validated cell

| Input | Exact value |
|---|---|
| Cell | Disposable LXC, Ubuntu 24.04.3 LTS, x86_64, systemd PID 1 |
| Skynet-EDR source | `425416d3712128d229b018fe3b726a1ca2189c9d` |
| Skynet-EDR artifact | package-built `skynet-edr_0.6.0_amd64.deb` |
| Hermes source | SSH-signed tag `v2026.8.3`, commit `3c27eb6234bf91b8ceee9e9071591b31e9b148cb` |
| Hermes version | `0.20.0` from the tag, `importlib.metadata`, and `pyproject.toml` |
| Hermes profile | `default` |
| Producer identity | unprivileged synthetic user, UID 1001, runtime role `gateway` |
| Plugin | package-owned `skynet-edr` 0.6.0, generation `febf1cb3d3b8800b44383a7d05e55c72c6555e7465ec2e8b1bfa2ecb3f48aa60` |
| Dispatcher | bundled A2A platform, localhost-only, no bearer token |
| Model transport | loopback-only fixed-response fixture; no credentials or external inference |

The repository was copied with `git archive HEAD`, so untracked workstation files
were not present in the cell. The fake provider key was clearly non-functional.
No Hermes auth file or real credential was installed or captured.
GitHub's tag-object API reported the `v2026.8.3` SSH signature as verified and
mapped it to the commit above.

## Compatibility delta: Hermes 0.19.0 to 0.20.0

The compared upstream release commits were:

- `3ef6bbd201263d354fd83ec55b3c306ded2eb72a` (`0.19.0`)
- `3c27eb6234bf91b8ceee9e9071591b31e9b148cb` (`v2026.8.3`, `0.20.0`)

Relevant findings:

1. `hermes_cli/plugins.py` retained the standalone plugin discovery, lifecycle
   hook registration, `HERMES_HOME`, profile-aware context, plugin-enable, and
   list/read-back contracts used by Skynet-EDR. Its relevant delta adds a
   plugin-safe subagent lifecycle facade, makes one source read explicitly
   UTF-8, and clarifies docstrings. No Skynet hook signature changed.
2. The Linux systemd gateway unit remains `hermes-gateway.service`, and
   `hermes gateway run` remains the producer command. The service-manager diff
   did not change the systemd unit/environment contract used by the adapter;
   0.20 changes in that file were outside this path (primarily S6 handling).
3. Hermes 0.20 accepted the documented `HERMES_HOME`,
   `HERMES_PROFILE=default`, `HERMES_RUNTIME_ROLE=gateway`, and plugin generation
   environment without a private API or source patch.
4. The existing separate browser gate installs upstream commit
   `f5be9236e00ddf2f2a412697f267078fc4ee068e`. That commit still declares 0.20.0,
   but it is 84 commits after the signed `v2026.8.3` release commit. The browser
   gate therefore does not establish exact-release provenance. This spike used
   the signed release commit and adds real gateway dispatch plus AF_UNIX evidence.
5. At the time of this historical spike, the enrollment adapter still rejected
   `0.20.0` because its supported tuple was fixed to `0.19.0`. PR #104 later
   implemented and clean-host-qualified the bounded 0.20.0 port. This statement
   is historical evidence, not the current release verdict; the release notes
   and `HERMES_ENROLLMENT.md` are authoritative for v0.7.0-alpha.1.

## Runtime evidence

### Package and plugin discovery

Hermes loaded the package payload through its real discovery entry point:

```text
name=skynet-edr
kind=standalone
version=0.6.0
source=user
enabled=true
hooks=5
tools=0
error=null
```

The active plugin bytes matched the package manifest generation shown above.
The producer's peer credentials were kernel-authenticated as UID 1001, and the
socket was `srw-rw---- skynet-edr:skynet-edr-ingest`.

### Gateway producer health

With the real `hermes gateway run` process alive, `/api/status` reported:

```json
{
  "state": "healthy",
  "listener_live": true,
  "transport_heartbeat_state": "fresh",
  "runtime_role": "gateway",
  "protocol_version": 3,
  "s3_eligible": true,
  "authenticated_uid": 1001,
  "backlog_bytes": 0,
  "events_dropped_total": 0,
  "events_malformed_total": 0
}
```

This used documented runtime/plugin environment only. A2A was enabled with the
upstream documented `gateway.platforms.a2a.enabled` setting solely to provide a
real localhost dispatcher input.

### Real dispatcher to authenticated ingestion

The A2A Agent Card was live on loopback and advertised protocol 1.0. A real
JSON-RPC `message/send` request entered the live Hermes gateway session. Hermes
called the loopback fixture and returned:

```json
{
  "id": "a1-0",
  "error": null,
  "result_state": "TASK_STATE_COMPLETED",
  "result_text": "SPIKE_OK"
}
```

Skynet-EDR's event count changed from 0 to 3. The exact active gateway source
advanced from `commit_sequence=0` / `events_persisted_total=0` to
`commit_sequence=3` / `events_persisted_total=3`, with no source error. SQLite
contained these three redacted event types on one trace:

```text
agent.session.started
agent.llm.call.requested
agent.session.ended
```

The stored LLM event had `content_omitted=true`; the raw dispatcher prompt was
not stored. This proves the event came from a real Hermes dispatcher lifecycle,
not a manifest parser, synthetic status object, or direct socket fixture.

A stale source row from an intentionally terminated first producer remained in
in-memory status while a second producer was exercised. The complete enrollment
attestation restarts the Skynet-EDR daemon before gateway startup, which clears
that lab artifact; production attestation also rejects competing sources for the
same UID/generation. This behavior was not treated as enrollment success.

## Reproduction core

Run only in a disposable Ubuntu 24.04 systemd cell containing no credentials.
Build/install the exact Skynet-EDR package, check out Hermes at signed tag
`v2026.8.3`, create its environment with Ubuntu's Python 3.12, and confirm all
three version identities before proceeding:

```bash
git -C /opt/hermes-agent checkout --detach v2026.8.3^{}
git -C /opt/hermes-agent rev-parse HEAD
git -C /opt/hermes-agent describe --exact-match --tags HEAD
/opt/hermes-agent/.venv/bin/python -c \
  'import importlib.metadata as m; print(m.version("hermes-agent"))'
```

The expected outputs are the release commit above, `v2026.8.3`, and `0.20.0`.
Configure `/etc/skynet-edr/config.toml` for the synthetic account only:
`ingest.enabled=true`, `allowed_uids=[<synthetic UID>]`,
`allow_root=false`, and `required_reported_roles=["gateway"]`. Add that account
to `skynet-edr-ingest`, restart its complete user manager so the group is
effective, restart `skynet-edr.service`, and verify the socket is mode 0660 and
owned by `skynet-edr:skynet-edr-ingest`.

Copy the package-owned plugin into the synthetic account's `default` profile,
enable it with Hermes, and verify real discovery:

```bash
export HERMES_HOME="$HOME/.hermes" HERMES_PROFILE=default
/opt/hermes-agent/.venv/bin/hermes plugins enable skynet-edr \
  --no-allow-tool-override
/opt/hermes-agent/.venv/bin/hermes plugins list --json
```

The fixed-response server is:

```bash
python3 packaging/spikes/hermes-020/mock_openai.py --port 19000
```

Configure a named custom provider with:

```yaml
model:
  default: spike-model
  provider: spike-local
providers:
  spike-local:
    name: Spike Local
    base_url: http://127.0.0.1:19000/v1
    key_env: SKYNET_EDR_SPIKE_KEY
    api_mode: openai_chat
    model: spike-model
gateway:
  platforms:
    a2a:
      enabled: true
      extra:
        port: 9900
```

Start the gateway as the synthetic account with the documented environment:

```bash
export HERMES_HOME="$HOME/.hermes"
export HERMES_PROFILE=default
export HERMES_RUNTIME_ROLE=gateway
export SKYNET_EDR_INGEST_SOCKET=/run/skynet-edr-ingest/ingest.sock
export SKYNET_EDR_PLUGIN_GENERATION=<lowercase package manifest generation>
export SKYNET_EDR_SPIKE_KEY=skynet-edr-fake-key-not-valid
export PYTHONDONTWRITEBYTECODE=1
/opt/hermes-agent/.venv/bin/hermes gateway run
```

The fake key is a fixture marker, not a credential. Wait for the A2A Agent Card
and healthy Skynet-EDR source, save the request below as `/tmp/a1-0.json`, then
send it over loopback:

```bash
curl --fail --silent --show-error --max-time 90 \
  -H 'Content-Type: application/json' \
  --data @/tmp/a1-0.json \
  http://127.0.0.1:9900/
curl --fail --silent http://127.0.0.1:8787/api/status
```

Request body:

```json
{
  "jsonrpc": "2.0",
  "id": "a1-0",
  "method": "message/send",
  "params": {
    "message": {
      "role": "ROLE_USER",
      "parts": [
        {
          "text": "A1-0 harmless dispatcher canary",
          "mediaType": "text/plain"
        }
      ],
      "messageId": "a1-0-benign-message"
    }
  }
}
```

Verification requires all of the following, from the exact active source:

- HTTP 200 and `TASK_STATE_COMPLETED` from the A2A request;
- `ingestion.state=healthy`, fresh gateway role, protocol 3, and `s3_eligible=true`;
- authenticated UID equal to the synthetic producer account;
- event and commit counters increase from the pre-dispatch baseline;
- SQLite contains the three event types above and no raw prompt content.

## Follow-on acceptance requirements

A follow-on S3 implementation may add an exact 0.20.0 compatibility tuple, but
must not change current support claims until it also:

1. adds RED-first adapter/version/transaction fixtures for 0.20.0;
2. runs the package-owned `apply`, `verify`, rollback, fault-injection, and
   repeatable-unenroll clean-host gate from `HERMES_ENROLLMENT.md`;
3. proves the exact systemd unit/drop-in and manager-environment read-back, not
   only foreground `gateway run`;
4. proves the startup attestation canary and exact fresh source/PID binding;
5. scans evidence for real secrets and private host/profile identifiers; and
6. keeps `S3_ADAPTER_BLOCK` on any ambiguous or partial result.

The current 0.19 clean-host blocker recorded by commit
`ad652bcc58e63033ac5d2d1cf6d0c9fd512a6b9d` is therefore not erased by this
spike. The result is positive compatibility evidence and a bounded port
recommendation, not permission to claim autonomous 0.20 enrollment.
