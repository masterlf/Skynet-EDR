#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 --hermes-repo PATH --plugin-source PATH [--port PORT]" >&2
  exit 2
}

hermes_repo=""
plugin_source=""
port="19002"
while (($#)); do
  case "$1" in
    --hermes-repo) [[ $# -ge 2 ]] || usage; hermes_repo=$2; shift 2 ;;
    --plugin-source) [[ $# -ge 2 ]] || usage; plugin_source=$2; shift 2 ;;
    --port) [[ $# -ge 2 ]] || usage; port=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ -d "$hermes_repo/.git" && -x "$hermes_repo/.venv/bin/hermes" ]] || usage
[[ -f "$plugin_source/plugin.yaml" && -f "$plugin_source/__init__.py" ]] || usage
[[ "$port" =~ ^[0-9]+$ && "$port" -ge 1024 && "$port" -le 65535 ]] || usage
hermes_repo=$(realpath -- "$hermes_repo")
plugin_source=$(realpath -- "$plugin_source")
readonly HERMES_REF="3c27eb6234bf91b8ceee9e9071591b31e9b148cb"
readonly SAFE_REPLY="SKYNET_EDR_SAFE_DETECTION_OK"
readonly FORBIDDEN_MARKER="FAKE_SKYNET_EDR_ALPHA2_SECRET_DO_NOT_EXPOSE"
readonly MOCK_SERVER="$(realpath -- "$(dirname -- "$0")/../spikes/hermes-020/mock_openai.py")"
[[ "$(git -C "$hermes_repo" rev-parse HEAD)" == "$HERMES_REF" ]]
[[ -z "$(git -C "$hermes_repo" status --porcelain --untracked-files=no)" ]]

work=$(mktemp -d)
fixture_pid=""
cleanup() {
  [[ -z "$fixture_pid" ]] || kill "$fixture_pid" 2>/dev/null || true
  [[ -z "$fixture_pid" ]] || wait "$fixture_pid" 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT
install -d -m 0700 "$work/home/plugins" "$work/state"
cp -a -- "$plugin_source" "$work/home/plugins/skynet-edr"

python3 "$MOCK_SERVER" --port "$port" --mode safe-detection >"$work/mock.log" 2>&1 &
fixture_pid=$!
for _ in $(seq 1 50); do
  if curl --fail --silent --show-error "http://127.0.0.1:${port}/v1/models" >"$work/models.json" 2>/dev/null; then
    break
  fi
  kill -0 "$fixture_pid"
  sleep 0.1
done
curl --fail --silent --show-error "http://127.0.0.1:${port}/v1/models" >/dev/null

export HERMES_HOME="$work/home"
export HOME="$work/home"
export PYTHONDONTWRITEBYTECODE=1
export SKYNET_EDR_STATE_DIR="$work/state"
export SKYNET_EDR_HERMES_PLUGIN_ENABLED=1
export SKYNET_EDR_INGEST_SOCKET="$work/missing-ingest.sock"
export OPENAI_API_KEY="fixture-only"
hermes="$hermes_repo/.venv/bin/hermes"
"$hermes" config set model.provider custom >/dev/null
"$hermes" config set model.default spike-model >/dev/null
"$hermes" config set model.base_url "http://127.0.0.1:${port}/v1" >/dev/null
"$hermes" plugins enable --no-allow-tool-override skynet-edr >/dev/null
"$hermes" tools list | grep -F 'enabled  skynet_edr' >/dev/null
"$hermes" -z 'Run the explicit Skynet-EDR safe detection simulation once.' \
  --provider custom -m spike-model -t skynet_edr --ignore-rules --reasoning none \
  >"$work/final-output.txt"
[[ "$(<"$work/final-output.txt")" == "$SAFE_REPLY" ]]

spool="$work/state/events-v1.jsonl"
[[ -f "$spool" && ! -L "$spool" ]]
python3 - "$spool" "$work/home/state.db" "$work/final-output.txt" "$work/state/skynet-edr-plugin.log" "$FORBIDDEN_MARKER" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

spool_path, session_db, final_output, plugin_log, forbidden = map(Path, sys.argv[1:])
events = [json.loads(line) for line in spool_path.read_text(encoding="utf-8").splitlines()]
requested = [
    event.get("attributes", {}).get("tool_name")
    for event in events
    if event.get("attributes", {}).get("hook") == "pre_tool_call"
]
if requested != [
    "tool_search",
    "tool_describe",
    "skynet_edr_safe_detection_simulation",
]:
    raise SystemExit(f"unexpected real-dispatch hook sequence: {requested!r}")
completed = [
    event for event in events
    if event.get("event_type") == "agent.tool.completed"
    and event.get("attributes", {}).get("tool_name") == "skynet_edr_safe_detection_simulation"
]
if len(completed) != 1:
    raise SystemExit(f"expected exactly one completed safe simulation event, got {len(completed)}")
event = completed[0]
attrs = event.get("attributes", {})
if (
    attrs.get("rule_id") != "EDR-MALWARE-001"
    or attrs.get("malware_indicator") is not True
    or attrs.get("malware_signature") != "skynet_fake_malware_test_string"
    or attrs.get("result_omitted") is not True
):
    raise SystemExit("safe simulation event classification mismatch")
redaction = event.get("redaction", {})
if redaction.get("contains_sensitive_data") is not True or redaction.get("redacted_fields") != [{
    "path": "attributes.result_preview",
    "reason": "secret",
    "replacement": "[REDACTED:secret]",
}]:
    raise SystemExit("safe simulation result redaction mismatch")

for path in (spool_path, final_output, plugin_log, session_db):
    if path.exists() and forbidden.name.encode() in path.read_bytes():
        raise SystemExit(f"forbidden marker survived reviewed output or storage: {path.name}")

connection = sqlite3.connect(session_db)
try:
    rows = connection.execute(
        "SELECT role, tool_calls, content FROM messages ORDER BY id"
    ).fetchall()
finally:
    connection.close()
called = []
handler_result_seen = False
raw_marker_seen = False
for role, tool_calls, content in rows:
    if tool_calls:
        for call in json.loads(tool_calls):
            called.append(call.get("function", {}).get("name"))
    if role == "tool" and content:
        handler_result_seen |= (
            '"detection_signal":"submitted"' in content
            and '"sensitive_output":"[REDACTED:secret]"' in content
        )
        raw_marker_seen |= "skynet_fake_malware_test_string_do_not_execute" in content
if called != ["tool_search", "tool_describe", "tool_call"]:
    raise SystemExit(f"unexpected model tool-call sequence: {called!r}")
if not handler_result_seen:
    raise SystemExit("plugin handler result was not returned through the real dispatcher")
if raw_marker_seen:
    raise SystemExit("raw safe-simulation marker survived in the plugin handler result")
PY

echo "Hermes 0.20 real deferred-dispatch gate passed"
