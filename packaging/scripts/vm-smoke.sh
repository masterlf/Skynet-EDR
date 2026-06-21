#!/usr/bin/env sh
set -eu

usage() {
  cat <<'USAGE'
Usage: sudo vm-smoke.sh --deb <package.deb> --repo <source-checkout> [--skip-purge]

Runs the clean-host Ubuntu packaging/runtime smoke gate against an already-built
Skynet-EDR DEB. The source checkout supplies test fixtures only; installed
binaries are exercised from /usr/bin.
USAGE
}

DEB=
REPO=
SKIP_PURGE=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --deb) DEB=${2:?missing --deb path}; shift 2 ;;
    --repo) REPO=${2:?missing --repo path}; shift 2 ;;
    --skip-purge) SKIP_PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "vm-smoke.sh must run as root" >&2
  exit 1
fi
if [ -z "$DEB" ] || [ -z "$REPO" ]; then
  usage >&2
  exit 2
fi
if [ ! -f "$DEB" ]; then
  echo "DEB not found: $DEB" >&2
  exit 1
fi
if [ ! -d "$REPO" ]; then
  echo "repo checkout not found: $REPO" >&2
  exit 1
fi

RUNTIME=/tmp/skynet-edr-vm-smoke
DB="$RUNTIME/skynet.sqlite"
SPOOL="$REPO/crates/skynet-edr-core/tests/fixtures/hermes_agent_golden_events_v0.jsonl"
MALWARE_TRACE="$REPO/crates/skynet-edr-core/tests/fixtures/hermes_fake_malware_content_trace.json"
CHECKPOINT="$RUNTIME/spool.checkpoint"
EVENTS_EXPORT="$RUNTIME/events.jsonl"
INCIDENTS_EXPORT="$RUNTIME/incidents.jsonl"
RAW_SECRET='FAKE_SKYNET_ATTACK_SIM_SECRET_DO_NOT_EXPOSE'
RAW_PATH='/home/attack-sim/.skynet/fake-secret.env'
RAW_MALWARE_MARKER='SKYNET_FAKE_MALWARE_TEST_STRING_DO_NOT_EXECUTE'
EXPECTED_VERSION=$(dpkg-deb -f "$DEB" Version)

cleanup() {
  systemctl stop skynet-edr.service >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

rm -rf "$RUNTIME"
install -d -m 0755 "$RUNTIME"
test -f "$SPOOL"
test -f "$MALWARE_TRACE"

dpkg -i "$DEB"

ACTUAL_VERSION=$(dpkg-query -W -f='${Version}' skynet-edr)
if [ "$ACTUAL_VERSION" != "$EXPECTED_VERSION" ]; then
  echo "dpkg version mismatch: package=$EXPECTED_VERSION installed=$ACTUAL_VERSION" >&2
  exit 1
fi

getent passwd skynet-edr >/dev/null
getent group skynet-edr >/dev/null
test "$(stat -c '%U:%G %a' /etc/skynet-edr/config.toml)" = "root:skynet-edr 640"

skynet-edr --version
skynet-edr-daemon --version
skynet-edr status
skynet-edr store init --db "$DB"
skynet-edr events ingest-spool --db "$DB" --spool "$SPOOL" --checkpoint "$CHECKPOINT"
skynet-edr events list --db "$DB"
skynet-edr events export --db "$DB" --format jsonl > "$EVENTS_EXPORT"
skynet-edr attack-sim secret-egress --db "$DB"
skynet-edr events ingest-hermes --db "$DB" --trace-json "$MALWARE_TRACE"
skynet-edr incidents list --db "$DB"
skynet-edr incidents export --db "$DB" --format jsonl > "$INCIDENTS_EXPORT"

if grep -a -F "$RAW_SECRET" "$EVENTS_EXPORT" "$INCIDENTS_EXPORT" "$DB" >/dev/null; then
  echo "raw fake secret leaked into persisted/exported runtime data" >&2
  exit 1
fi
if grep -a -F "$RAW_PATH" "$EVENTS_EXPORT" "$INCIDENTS_EXPORT" "$DB" >/dev/null; then
  echo "raw fake local path leaked into persisted/exported runtime data" >&2
  exit 1
fi
if grep -a -F "$RAW_MALWARE_MARKER" "$EVENTS_EXPORT" "$INCIDENTS_EXPORT" "$DB" >/dev/null; then
  echo "raw fake malware marker leaked into persisted/exported runtime data" >&2
  exit 1
fi
grep -F '[REDACTED:secret]' "$INCIDENTS_EXPORT" >/dev/null
grep -F '[REDACTED:local_context]' "$INCIDENTS_EXPORT" >/dev/null
grep -F 'EDR-MALWARE-001' "$INCIDENTS_EXPORT" >/dev/null
grep -F 'skynet_fake_malware_test_string' "$INCIDENTS_EXPORT" >/dev/null

systemctl daemon-reload
systemctl start skynet-edr.service
systemctl is-active --quiet skynet-edr.service
i=0
until curl -fsS http://127.0.0.1:8787/api/status >/dev/null; do
  i=$((i + 1))
  if [ "$i" -ge 20 ]; then
    echo "skynet-edr API did not become ready on 127.0.0.1:8787" >&2
    journalctl -u skynet-edr.service --no-pager -n 80 >&2 || true
    exit 1
  fi
  sleep 0.25
done

apt-get remove -y skynet-edr
if [ "$SKIP_PURGE" -eq 0 ]; then
  apt-get purge -y skynet-edr
fi

echo "Skynet-EDR VM smoke passed for $DEB"
