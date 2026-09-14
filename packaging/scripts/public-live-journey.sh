#!/usr/bin/env bash
# Destructive lab provisioning is confined to a fresh disposable Ubuntu host.
set -Eeuo pipefail
umask 077

usage() {
  echo 'usage: public-live-journey.sh --disposable-host --deb PATH --hermes-repo PATH --browser-runtime PATH' >&2
  exit 2
}
deb=""; hermes_repo=""; browser_runtime=""; disposable=""
while (($#)); do
  case "$1" in
    --disposable-host) disposable=yes; shift ;;
    --deb) [[ $# -ge 2 ]] || usage; deb=$2; shift 2 ;;
    --hermes-repo) [[ $# -ge 2 ]] || usage; hermes_repo=$2; shift 2 ;;
    --browser-runtime) [[ $# -ge 2 ]] || usage; browser_runtime=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$disposable" == yes && "$EUID" == 0 ]] || usage
[[ -f "$deb" && -d "$hermes_repo/.git" && -d "$browser_runtime/node_modules/playwright" ]] || usage
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
deb=$(realpath -- "$deb")
hermes_repo=$(realpath -- "$hermes_repo")
browser_runtime=$(realpath -- "$browser_runtime")
readonly expected_sha=aca54b93ecea85f8b789d5d8600b5ae1554b1513089a6778a5253fc1e11eaee4
readonly hermes_ref=3c27eb6234bf91b8ceee9e9071591b31e9b148cb
readonly lab=/var/lib/skynet-public-journey
readonly account=skynet-journey
readonly target_home=/home/skynet-journey
stage=preflight
error_line=0
fixture_pid=""; dashboard_pid=""; target_uid=""; created_account=""

finish() {
  result=$?
  trap - EXIT
  [[ -z "$dashboard_pid" ]] || kill "$dashboard_pid" 2>/dev/null || true
  [[ -z "$fixture_pid" ]] || kill "$fixture_pid" 2>/dev/null || true
  if [[ "$created_account" == yes ]]; then
    systemctl stop "user@${target_uid}.service" skynet-edr.service >/dev/null 2>&1 || true
  fi
  if ((result != 0)); then
    for verb in check apply verify; do
      if [[ -f "$lab/$verb.json" ]]; then
        python3 "$repo/packaging/scripts/public_journey_evidence.py" enrollment-diagnostic \
          --enrollment-result "$lab/$verb.json" >&2 || true
      fi
    done
    printf '{"schema":"skynet.public-journey.v1","status":"FAIL","stage":"%s","line":%s}\n' "$stage" "$error_line"
  fi
  # Preserve private evidence and enrollment recovery state; discard the VM after inspection.
  exit "$result"
}
trap finish EXIT
trap 'error_line=$LINENO' ERR
trap 'exit 1' TERM INT

[[ "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" == ubuntu:24.04 ]]
[[ "$(uname -m)" == x86_64 && "$(cat /proc/1/comm)" == systemd ]]
[[ "$hermes_repo" == /opt/skynet-journey-hermes ]]
[[ "$(git -C "$hermes_repo" rev-parse HEAD)" == "$hermes_ref" ]]
[[ -z "$(git -C "$hermes_repo" status --porcelain --untracked-files=no)" ]]
[[ -x "$hermes_repo/.venv/bin/hermes" ]]
[[ ! -e "$lab" && ! -L "$lab" && ! -e /usr/bin/hermes && ! -L /usr/bin/hermes ]]
[[ ! -e "$target_home" && ! -L "$target_home" ]]
! getent passwd "$account" >/dev/null
! dpkg-query -W -f='${db:Status-Abbrev}' skynet-edr 2>/dev/null | grep -q '^ii '
for directory in /opt /opt/skynet-journey-hermes; do
  [[ "$(stat -c %u "$directory")" == 0 ]]
  [[ -z "$(find "$directory" -maxdepth 0 -perm /022 -print)" ]]
done
printf '%s  %s\n' "$expected_sha" "$deb" | sha256sum -c - >/dev/null
[[ "$(dpkg-deb -f "$deb" Version)" == '0.7.0~alpha.2' ]]
python3 - <<'PY'
import socket
for port in (8787, 9119, 9900, 19000):
    with socket.socket() as server:
        server.bind(("127.0.0.1", port))
PY
install -d -m 0700 "$lab"
stage=provision
dpkg --install "$deb" >"$lab/install.log" 2>&1
useradd --create-home --shell /bin/bash "$account"
created_account=yes
target_uid=$(id -u "$account")
install -d -o "$account" -g "$account" -m 0700 "$target_home/.hermes"
cat >/usr/bin/hermes <<'SH'
#!/bin/sh
exec /opt/skynet-journey-hermes/.venv/bin/hermes "$@"
SH
chmod 0755 /usr/bin/hermes
cat >"$target_home/.hermes/config.yaml" <<'YAML'
model:
  default: spike-model
  provider: spike-local
providers:
  spike-local:
    name: Public Journey Fixture
    base_url: http://127.0.0.1:19000/v1
    key_env: SKYNET_EDR_SPIKE_KEY
    api_mode: openai_chat
    model: spike-model
platform_toolsets:
  a2a: [skynet_edr]
gateway:
  platforms:
    a2a:
      enabled: true
      extra:
        port: 9900
YAML
chown "$account:$account" "$target_home/.hermes/config.yaml"
run_as() {
  runuser -u "$account" -- env HOME="$target_home" HERMES_HOME="$target_home/.hermes" \
    HERMES_PROFILE=default PYTHONDONTWRITEBYTECODE=1 \
    SKYNET_EDR_SPIKE_KEY=skynet-edr-fake-key-not-valid \
    XDG_RUNTIME_DIR="/run/user/$target_uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$target_uid/bus" "$@"
}
start_fixture() {
  python3 "$repo/packaging/spikes/hermes-020/mock_openai.py" --port 19000 "$@" \
    >"$lab/model.log" 2>&1 &
  fixture_pid=$!
  for _ in $(seq 1 50); do
    if curl --noproxy '*' --fail --silent --max-time 1 http://127.0.0.1:19000/v1/models >/dev/null; then return; fi
    kill -0 "$fixture_pid"
    sleep 0.1
  done
  return 1
}
start_fixture --reply SKYNET_EDR_ENROLLMENT_OK
loginctl enable-linger "$account"
systemctl start "user@${target_uid}.service"
run_as /usr/bin/hermes gateway install --force >"$lab/gateway-install.log" 2>&1
# The fixture key is deliberately nonfunctional and must survive manager restarts.
install -d -o "$account" -g "$account" -m 0700 "$target_home/.config/systemd/user/hermes-gateway.service.d"
cat >"$target_home/.config/systemd/user/hermes-gateway.service.d/10-public-journey.conf" <<'UNIT'
[Service]
Environment=SKYNET_EDR_SPIKE_KEY=skynet-edr-fake-key-not-valid
Environment=PYTHONDONTWRITEBYTECODE=1
UNIT
chown -R "$account:$account" "$target_home/.config/systemd/user/hermes-gateway.service.d"
run_as systemctl --user daemon-reload
run_as systemctl --user restart hermes-gateway.service
for _ in $(seq 1 60); do
  if curl --noproxy '*' --fail --silent --max-time 1 http://127.0.0.1:9900/.well-known/agent-card.json >/dev/null; then break; fi
  sleep 1
done
curl --noproxy '*' --fail --silent --max-time 2 http://127.0.0.1:9900/.well-known/agent-card.json >/dev/null
python3 - "$target_uid" >"$lab/request.json" <<'PY'
import json, sys
print(json.dumps({
    "account": "skynet-journey", "uid": int(sys.argv[1]), "allow_root": False,
    "hermes_home": "/home/skynet-journey/.hermes", "profile": "default",
    "host": {"id": "ubuntu", "version": "24.04", "arch": "x86_64", "init": "systemd"},
    "hermes_version": "0.20.0", "payload_version": "0.7.0-alpha.2",
    "socket": {"dac": True, "uid_authorized": True}, "required_role": "gateway",
    "units": ["hermes-gateway.service"], "restart_authorized": True,
}))
PY
enroll() {
  timeout 90 /usr/bin/skynet-edr-hermes-enroll "$1" --request "$lab/request.json" \
    --source /usr/share/skynet-edr/hermes-plugin/skynet-edr \
    --state-root /var/lib/skynet-edr-hermes-enrollment \
    --observations /var/lib/skynet-edr-hermes-enrollment/observations.json \
    --adapter /usr/libexec/skynet-edr/hermes-enrollment-adapter.py
}
stage=enrollment-check
if enroll check >"$lab/check.json"; then exit 1; fi
python3 - "$lab/check.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))["state"] == "ABSENT"
PY
stage=enrollment-apply
enroll apply >"$lab/apply.json"
stage=enrollment-verify
enroll verify >"$lab/verify.json"
python3 - "$lab/apply.json" "$lab/verify.json" <<'PY'
import json, sys
assert all(json.load(open(path))["state"] == "ENROLLED" for path in sys.argv[1:])
PY
generation=$(python3 -c 'import json; print(json.load(open("/usr/share/skynet-edr/hermes-plugin/manifest.json"))["generation"])')
gateway_pid=$(run_as systemctl --user show hermes-gateway.service --property=MainPID --value)
python3 "$repo/packaging/scripts/public_journey_evidence.py" snapshot >"$lab/before.json"

stage=dispatch
kill "$fixture_pid"; wait "$fixture_pid" || true; fixture_pid=""
start_fixture --mode safe-detection
curl --noproxy '*' --fail --silent --show-error --max-time 120 \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":"public-journey","method":"message/send","params":{"message":{"role":"ROLE_USER","parts":[{"text":"Run the explicit Skynet-EDR safe detection simulation once.","mediaType":"text/plain"}],"messageId":"public-journey-safe-simulation"}}}' \
  http://127.0.0.1:9900/ >"$lab/dispatch.json"
verify_chain() {
  [[ "$(run_as systemctl --user show hermes-gateway.service --property=MainPID --value)" == "$gateway_pid" ]]
  python3 "$repo/packaging/scripts/public_journey_evidence.py" verify \
    --before "$lab/before.json" --dispatch "$lab/dispatch.json" \
    --session-db "$target_home/.hermes/state.db" --uid "$target_uid" \
    --generation "$generation" --gateway-pid "$gateway_pid"
}
stage=persistence
verify_chain >"$lab/binding.json"

stage=browser
session_token=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
run_as env HERMES_DASHBOARD_SESSION_TOKEN="$session_token" SKYNET_EDR_HERMES_PLUGIN_ENABLED=0 \
  /usr/bin/hermes dashboard --host 127.0.0.1 --port 9119 --no-open >"$lab/dashboard.log" 2>&1 &
dashboard_pid=$!
for _ in $(seq 1 90); do
  if curl --noproxy '*' --fail --silent --max-time 1 -H "X-Hermes-Session-Token: $session_token" \
    http://127.0.0.1:9119/api/plugins/skynet-edr/status >/dev/null; then break; fi
  kill -0 "$dashboard_pid"
  sleep 1
done
HERMES_DASHBOARD_SESSION_TOKEN="$session_token" node "$repo/packaging/scripts/public-journey-browser.mjs" \
  "$browser_runtime" "$lab/binding.json" >"$lab/browser.json" 2>"$lab/browser-error.log"
verify_chain >"$lab/final-binding.json"
cmp "$lab/binding.json" "$lab/final-binding.json"
stage=complete
printf '{"schema":"skynet.public-journey.v1","status":"PASS","package_sha256":"%s","hermes_commit":"%s","enrollment":"ENROLLED","rule_id":"EDR-MALWARE-001","incident_count":1,"live_ack":true,"browser_event_binding":true}\n' "$expected_sha" "$hermes_ref"
