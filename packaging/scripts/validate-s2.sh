#!/usr/bin/env bash
set -u
umask 077

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$REPO" || exit 2
HELPER="$REPO/packaging/scripts/s2-report-dir.py"
usage() { echo "usage: $0 --output ABSOLUTE_PATH" >&2; exit 2; }
if [ "$#" -eq 2 ] && [ "$1" = "--output" ]; then
  OUTPUT=$2
  if ! python3 "$HELPER" check "$OUTPUT"; then
    echo "unsafe output path: $OUTPUT" >&2
    exit 2
  fi
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "tracked tree must be clean before S2 validation" >&2
    exit 2
  fi
  exec python3 "$HELPER" exec "$OUTPUT" "$0" --internal "$OUTPUT"
fi
[ "$#" -eq 2 ] && [ "$1" = "--internal" ] || usage
OUTPUT=$2
: "${S2_REPORT_TOKEN:?missing retained report token}"
: "${S2_REPORT_STAGE:?missing retained report stage descriptor}"
REPORT_TOKEN=$S2_REPORT_TOKEN
REPORT_STAGE=$S2_REPORT_STAGE
mkdir -m 700 -- "$REPORT_STAGE/logs" || exit 2
TMPROOT=$(mktemp -d "${TMPDIR:-/tmp}/skynet-edr-s2.XXXXXX") || exit 2
PUBLISHED=0
cleanup() {
  rm -rf -- "$TMPROOT"
  if [ "$PUBLISHED" -eq 0 ]; then
    python3 "$HELPER" abort-fd "$OUTPUT" "$REPORT_TOKEN" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM
mkdir -m 700 "$TMPROOT/state" "$TMPROOT/target" "$TMPROOT/raw"
export SKYNET_EDR_STATE_DIR="$TMPROOT/state"
export CARGO_TARGET_DIR="$TMPROOT/target"
export CARGO_NET_OFFLINE=true
export PYTHONDONTWRITEBYTECODE=1
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
HEAD=$(git rev-parse HEAD)
printf 'gate\tstatus\twall_s\tuser_s\tsys_s\tmax_rss_kb\ttest_count\n' > "$REPORT_STAGE/metrics.tsv"
OVERALL=0

count_tests() {
  python3 - "$1" <<'PY'
import re, sys
text=open(sys.argv[1],encoding="utf-8",errors="replace").read()
values=[]
values += [int(x) for x in re.findall(r"test result: ok\. (\d+) passed", text)]
values += [int(x) for x in re.findall(r"Ran (\d+) tests?", text)]
values += [int(x) for x in re.findall(r"^# tests (\d+)$", text, re.M)]
print(sum(values))
PY
}

run_gate() {
  gate=$1; shift
  log="$TMPROOT/raw/$gate.log"
  timing="$TMPROOT/$gate.time"
  /usr/bin/time -f '%e\t%U\t%S\t%M' -o "$timing" "$@" > "$log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then status=pass; else status=fail; OVERALL=1; fi
  test_count=$(count_tests "$log")
  IFS=$'\t' read -r wall user sys rss < "$timing"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$gate" "$status" "$wall" "$user" "$sys" "$rss" "$test_count" >> "$REPORT_STAGE/metrics.tsv"
  printf 'gate=%s status=%s test_count=%s\n' "$gate" "$status" "$test_count" > "$REPORT_STAGE/logs/$gate.log"
}

run_gate docs python3 packaging/scripts/check-docs.py
run_gate packaging packaging/scripts/validate-packaging.sh
run_gate fmt cargo fmt --all -- --check
run_gate clippy cargo clippy --workspace --all-targets --all-features --offline -- -D warnings
run_gate rust-workspace cargo test --workspace --all-features --offline
run_gate hermes-python python3 -m unittest discover -s integrations/hermes/tests -p 'test_*.py'
run_gate producer-corpus python3 -m unittest integrations/hermes/tests/test_detection_corpus.py
run_gate dashboard-node node --test integrations/hermes/skynet-edr/dashboard/plugin.test.mjs
run_gate desktop-node node --test integrations/hermes/skynet-edr/desktop/plugin.test.mjs
run_gate corpus cargo test -p skynet-edr-core --test detection_corpus --all-features --offline
run_gate runtime-canary cargo test -p skynet-edr-daemon --test s2_runtime_canary --all-features --offline -- --nocapture
ENDED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 - "$REPORT_STAGE" "$TMPROOT/raw/runtime-canary.log" "$STARTED" "$ENDED" "$HEAD" "$OVERALL" <<'PY'
import json, os, platform, re, subprocess, sys
from pathlib import Path
out=Path(sys.argv[1]); canary_path=Path(sys.argv[2]); started,ended,head,overall=sys.argv[3:]
rows=[]
for line in (out/'metrics.tsv').read_text().splitlines()[1:]:
    gate,status,wall,user,system,rss,count=line.split('\t')
    rows.append({'gate':gate,'status':status,'wall_s':float(wall),'user_s':float(user),'sys_s':float(system),'max_rss_kb':int(rss),'test_count':int(count)})
def version(*cmd):
    return subprocess.run(cmd,text=True,capture_output=True,check=False).stdout.splitlines()[0]
canary=canary_path.read_text(encoding='utf-8',errors='replace')
metric=re.search(r'S2_CANARY_METRICS=(\{.*\})',canary)
canary_metrics=json.loads(metric.group(1)) if metric else None
manifest={'schema_version':'skynet.s2.validation.v1','started_at_utc':started,'ended_at_utc':ended,'git_head':head,'tracked_dirty':False,'synthetic_data_only':True,'host':{'os':platform.system(),'arch':platform.machine()},'toolchain':{'rustc':version('rustc','--version'),'cargo':version('cargo','--version'),'rustfmt':version('rustfmt','--version'),'clippy':version('cargo','clippy','--version'),'python':version('python3','--version'),'node':version('node','--version')},'gates':[r['gate'] for r in rows]}
accounting=None if canary_metrics is None else {key:canary_metrics[key] for key in ('generated','enqueued','terminal_acks','receipts','drops','fallback_records','socket_failures','backlog','collisions','truncations')}
summary={'schema_version':'skynet.s2.validation-summary.v1','status':'pass' if overall=='0' else 'fail','real_hermes_runtime':False,'package_install_runtime':False,'gates':rows,'accounting':accounting,'canary_metrics':canary_metrics}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
(out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
PY
if [ "$OVERALL" -ne 0 ]; then
  echo "S2 validation failed; raw diagnostics deleted and no report published" >&2
  exit 1
fi
python3 "$HELPER" seal-fd "$OUTPUT" "$REPORT_TOKEN" || exit 1
python3 "$HELPER" publish-fd "$OUTPUT" "$REPORT_TOKEN" || exit 1
PUBLISHED=1
echo "S2 validation passed; sanitized report: $OUTPUT"
