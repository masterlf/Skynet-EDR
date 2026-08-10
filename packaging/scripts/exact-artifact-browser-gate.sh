#!/usr/bin/env bash
set -Eeuo pipefail

# This gate installs a DEB and system service. It is CI-only by design.
if [[ "${GITHUB_ACTIONS:-}" != "true" || "${SKYNET_EDR_RUNNER_ENVIRONMENT:-}" != "github-hosted" ]]; then
  echo "exact artifact browser gate requires GITHUB_ACTIONS=true on a disposable GitHub-hosted runner" >&2
  exit 2
fi

usage() { echo "usage: $0 --deb PATH --hermes-repo PATH" >&2; exit 2; }
deb=""; hermes_repo=""
while (($#)); do
  case "$1" in
    --deb) [[ $# -ge 2 ]] || usage; deb=$2; shift 2 ;;
    --hermes-repo) [[ $# -ge 2 ]] || usage; hermes_repo=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ -f "$deb" && ! -L "$deb" && -d "$hermes_repo/.git" ]] || usage
deb=$(realpath -- "$deb")

readonly PRODUCT_VERSION="0.6.0-alpha.3"
readonly DEB_VERSION="0.6.0~alpha.3"
HERMES_REF=f5be9236e00ddf2f2a412697f267078fc4ee068e
readonly HERMES_REF
readonly HERMES_PORT="9119"
readonly DAEMON_PORT="8787"
readonly FIXTURE="${GITHUB_WORKSPACE}/crates/skynet-edr-daemon/tests/fixtures/status_alert_delivery_degraded.json"
work=$(mktemp -d)
hermes_home="$work/hermes-home"
hermes_cli="$hermes_repo/.venv/bin/hermes"
browser_runtime="$GITHUB_WORKSPACE/packaging/browser-gate"
dashboard_pid=""; fixture_pid=""; service_started=""
cleanup() {
  [[ -z "$fixture_pid" ]] || kill "$fixture_pid" 2>/dev/null || true
  [[ -z "$dashboard_pid" ]] || kill "$dashboard_pid" 2>/dev/null || true
  [[ -z "$service_started" ]] || sudo systemctl stop skynet-edr.service 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

[[ "$(git -C "$hermes_repo" rev-parse HEAD)" == "$HERMES_REF" ]]
[[ -z "$(git -C "$hermes_repo" status --porcelain --untracked-files=no)" ]]
[[ -x "$hermes_cli" ]]
[[ -d "$browser_runtime/node_modules/playwright" ]]
[[ -n "${PLAYWRIGHT_BROWSERS_PATH:-}" && -d "$PLAYWRIGHT_BROWSERS_PATH" ]]
browser_executable=$(cd "$browser_runtime" && node -e \
  "const { chromium } = require('playwright'); process.stdout.write(chromium.executablePath())")
[[ -x "$browser_executable" ]]
[[ "$(dpkg-deb -f "$deb" Version)" == "$DEB_VERSION" ]]
[[ "$(dpkg-deb -f "$deb" Depends)" == "systemd, python3" ]]
for dependency in systemd python3; do
  [[ "$(dpkg-query -W -f='${db:Status-Abbrev}' "$dependency")" == "ii " ]]
done
sudo dpkg --install "$deb"
[[ "$(dpkg-query -W -f='${Version}' skynet-edr)" == "$DEB_VERSION" ]]
sudo systemctl start skynet-edr.service
service_started=1
for _ in $(seq 1 30); do
  curl --fail --silent "http://127.0.0.1:${DAEMON_PORT}/api/status" >/dev/null && break
  sleep 1
done
curl --fail --silent "http://127.0.0.1:${DAEMON_PORT}/api/status" >/dev/null

verify_installed_payloads() {
  sudo /usr/libexec/skynet-edr/deploy-verify \
    --expected-product-version "$PRODUCT_VERSION" \
    --expected-deb-version "$DEB_VERSION" \
    --hermes-plugin-root "$hermes_home/plugins/skynet-edr" \
    --hermes-plugin-uid "$(id -u)" \
    --hermes-plugin-gid "$(id -g)" \
    --port "$DAEMON_PORT"
}

install -d -m 0700 "$hermes_home"
install -d -m 0755 "$hermes_home/plugins"
cp -a /usr/share/skynet-edr/hermes-plugin/skynet-edr "$hermes_home/plugins/skynet-edr"
cp -a /usr/share/skynet-edr/hermes-plugin/manifest.json "$hermes_home/plugins/manifest.json"
export HERMES_HOME="$hermes_home"
export HOME="$work/home"
install -d -m 0700 "$HOME"
export PYTHONDONTWRITEBYTECODE=1
"$hermes_cli" plugins enable --no-allow-tool-override skynet-edr

verify_installed_payloads

token=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
export HERMES_DASHBOARD_SESSION_TOKEN="$token"
export SKYNET_EDR_API_URL="http://127.0.0.1:${DAEMON_PORT}"
"$hermes_cli" dashboard --host 127.0.0.1 --port "$HERMES_PORT" --no-open >"$work/hermes.log" 2>&1 &
dashboard_pid=$!
for _ in $(seq 1 90); do
  if curl --fail --silent --show-error -H "X-Hermes-Session-Token: $token" \
      "http://127.0.0.1:${HERMES_PORT}/api/dashboard/plugins" >"$work/plugins.json"; then
    break
  fi
  sleep 1
done
kill -0 "$dashboard_pid"
unauthenticated_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:${HERMES_PORT}/api/plugins/skynet-edr/status")
[[ "$unauthenticated_status" == "401" ]] || {
  echo "unauthenticated plugin proxy did not fail closed" >&2
  exit 1
}
curl --fail --silent --show-error -H "X-Hermes-Session-Token: $token" \
  "http://127.0.0.1:${HERMES_PORT}/api/plugins/skynet-edr/status" >"$work/status.json"

python3 - "$work/plugins.json" <<'PY'
import json, sys
plugins=json.load(open(sys.argv[1], encoding='utf-8'))
matches=[value for value in plugins if value.get('name') == 'skynet-edr'] if isinstance(plugins, list) else []
if len(matches) != 1:
    raise SystemExit('packaged dashboard plugin registration count mismatch')
value=matches[0]
tab=value.get('tab') if isinstance(value.get('tab'), dict) else {}
if value.get('version') != '0.6.0-alpha.3' or value.get('has_api') is not True or tab.get('path') != '/skynet-edr/risks':
    raise SystemExit('packaged dashboard route registration mismatch')
PY

(cd "$browser_runtime" && node "$GITHUB_WORKSPACE/packaging/scripts/hermes-browser-smoke.mjs" \
  "http://127.0.0.1:${HERMES_PORT}/skynet-edr/risks" normal \
  /usr/share/skynet-edr/hermes-plugin/manifest.json "$browser_runtime")
verify_installed_payloads

sudo systemctl stop skynet-edr.service
service_started=""
python3 "$GITHUB_WORKSPACE/packaging/scripts/browser-fixture-server.py" \
  --port "$DAEMON_PORT" --status "$FIXTURE" >"$work/fixture.log" 2>&1 &
fixture_pid=$!
for _ in $(seq 1 30); do
  curl --fail --silent "http://127.0.0.1:${DAEMON_PORT}/healthz" >/dev/null && break
  sleep 1
done
kill -0 "$fixture_pid"
(cd "$browser_runtime" && node "$GITHUB_WORKSPACE/packaging/scripts/hermes-browser-smoke.mjs" \
  "http://127.0.0.1:${HERMES_PORT}/skynet-edr/risks" alert-delivery \
  /usr/share/skynet-edr/hermes-plugin/manifest.json "$browser_runtime")

kill "$fixture_pid"
wait "$fixture_pid" || true
fixture_pid=""
sudo systemctl start skynet-edr.service
service_started=1
for _ in $(seq 1 30); do
  curl --fail --silent "http://127.0.0.1:${DAEMON_PORT}/api/status" >/dev/null && break
  sleep 1
done
curl --fail --silent "http://127.0.0.1:${DAEMON_PORT}/api/status" >/dev/null
verify_installed_payloads
sudo dpkg -V skynet-edr
sha256sum "$deb"
echo "exact artifact browser gate passed both lanes"
