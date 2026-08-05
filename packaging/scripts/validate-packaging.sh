#!/usr/bin/env sh
set -eu

required_files="
README.md
LICENSE
docs/INSTALL.md
docs/PACKAGING.md
packaging/nfpm.yaml
packaging/config/config.toml
packaging/systemd/skynet-edr.service
packaging/sysusers/skynet-edr.conf
packaging/tmpfiles/skynet-edr.conf
packaging/tarball/install.sh
packaging/tarball/uninstall.sh
packaging/scripts/build-tarball.sh
packaging/scripts/build-packages.sh
packaging/scripts/check-release-version.py
packaging/tests/test_check_release_version.py
packaging/scripts/validate-s2.sh
packaging/tests/test_validate_s2.py
packaging/scripts/stage-hermes-plugin-payload.sh
packaging/scripts/inspect-artifacts.sh
packaging/scripts/smoke-install-artifacts.sh
packaging/scripts/verify-public-release.sh
packaging/scripts/package-postinstall.sh
packaging/scripts/package-postremove.sh
packaging/scripts/skynet-edr-install-hermes-plugin.sh
packaging/scripts/skynet-edr-hermes-enroll.py
packaging/tests/test_hermes_enrollment.py
packaging/scripts/vm-smoke.sh
integrations/hermes/skynet-edr/plugin.yaml
integrations/hermes/skynet-edr/__init__.py
integrations/hermes/skynet-edr/dashboard/manifest.json
integrations/hermes/skynet-edr/dashboard/plugin.js
integrations/hermes/skynet-edr/dashboard/plugin_api.py
integrations/hermes/skynet-edr/desktop/plugin.js
integrations/hermes/skynet-edr/README.md
.github/workflows/packaging-release.yml
"

for file in $required_files; do
  if [ ! -f "$file" ]; then
    echo "missing required packaging file: $file" >&2
    exit 1
  fi
done

if [ "${SKYNET_EDR_EXPECTED_VERSION+x}" = x ]; then
  python3 packaging/scripts/check-release-version.py --expected "$SKYNET_EDR_EXPECTED_VERSION"
else
  python3 packaging/scripts/check-release-version.py
fi
python3 -m unittest discover -s packaging/tests -p 'test_*.py'

for script in packaging/tarball/install.sh packaging/tarball/uninstall.sh packaging/scripts/build-tarball.sh packaging/scripts/build-packages.sh packaging/scripts/stage-hermes-plugin-payload.sh packaging/scripts/inspect-artifacts.sh packaging/scripts/smoke-install-artifacts.sh packaging/scripts/verify-public-release.sh packaging/scripts/validate-packaging.sh packaging/scripts/validate-s2.sh packaging/scripts/package-postinstall.sh packaging/scripts/package-postremove.sh packaging/scripts/skynet-edr-install-hermes-plugin.sh packaging/scripts/skynet-edr-hermes-enroll.py packaging/scripts/vm-smoke.sh; do
  if [ ! -x "$script" ]; then
    echo "packaging script must be executable: $script" >&2
    exit 1
  fi
done

grep -q 'User=skynet-edr' packaging/systemd/skynet-edr.service
grep -q 'Group=skynet-edr' packaging/systemd/skynet-edr.service
grep -q 'NoNewPrivileges=yes' packaging/systemd/skynet-edr.service
grep -q 'RuntimeDirectoryMode=0750' packaging/systemd/skynet-edr.service
grep -q 'StateDirectoryMode=0750' packaging/systemd/skynet-edr.service
grep -q 'CacheDirectoryMode=0750' packaging/systemd/skynet-edr.service
grep -q 'LogsDirectoryMode=0750' packaging/systemd/skynet-edr.service
grep -q 'ProtectSystem=strict' packaging/systemd/skynet-edr.service
grep -q 'ProtectHome=true' packaging/systemd/skynet-edr.service
if grep -q 'ProtectHome=read-only' packaging/systemd/skynet-edr.service; then
  echo "daemon must not receive read access to user homes" >&2
  exit 1
fi
grep -q 'IPAddressDeny=any' packaging/systemd/skynet-edr.service
grep -q 'IPAddressAllow=localhost' packaging/systemd/skynet-edr.service
grep -q 'ExecStart=/usr/bin/skynet-edr-daemon run --config /etc/skynet-edr/config.toml' packaging/systemd/skynet-edr.service

grep -q '^u skynet-edr ' packaging/sysusers/skynet-edr.conf
grep -q '^g skynet-edr-ingest ' packaging/sysusers/skynet-edr.conf
grep -q '^m skynet-edr skynet-edr-ingest$' packaging/sysusers/skynet-edr.conf
grep -q '^d /var/lib/skynet-edr 0750 skynet-edr skynet-edr -' packaging/tmpfiles/skynet-edr.conf
grep -q '^d /etc/skynet-edr 0750 root skynet-edr -' packaging/tmpfiles/skynet-edr.conf
grep -q '^d /run/skynet-edr-ingest 0750 skynet-edr skynet-edr-ingest -' packaging/tmpfiles/skynet-edr.conf

grep -q '^\[ingest\]' packaging/config/config.toml
grep -q '^socket = "/run/skynet-edr-ingest/ingest.sock"' packaging/config/config.toml
grep -q '^socket_group = "skynet-edr-ingest"' packaging/config/config.toml
grep -q '^allowed_uids = \[\]' packaging/config/config.toml
grep -q '^allow_root = false' packaging/config/config.toml
grep -q '^required_reported_roles = \[\]' packaging/config/config.toml
grep -q '^max_frame_bytes = 262144' packaging/config/config.toml

grep -q 'skynet-edr-daemon' packaging/nfpm.yaml
grep -q 'type: config|noreplace' packaging/nfpm.yaml
grep -q '/etc/skynet-edr/agents.d' packaging/nfpm.yaml
grep -q 'scripts:' packaging/nfpm.yaml
grep -q 'postinstall:' packaging/nfpm.yaml
grep -q 'postremove:' packaging/nfpm.yaml
grep -q 'packaging/scripts/package-postinstall.sh' packaging/nfpm.yaml
grep -q 'packaging/scripts/package-postremove.sh' packaging/nfpm.yaml
grep -q '/usr/share/skynet-edr/hermes-plugin/skynet-edr' packaging/nfpm.yaml
grep -q 'dist/staging/nfpm/hermes-plugin/skynet-edr' packaging/nfpm.yaml
grep -q '/usr/bin/skynet-edr-install-hermes-plugin' packaging/nfpm.yaml
grep -q '/usr/bin/skynet-edr-hermes-enroll' packaging/nfpm.yaml
grep -q 'stage-hermes-plugin-payload.sh integrations/hermes/skynet-edr' packaging/scripts/build-tarball.sh
grep -q 'stage-hermes-plugin-payload.sh integrations/hermes/skynet-edr' packaging/scripts/build-packages.sh
python3 - <<'PY'
import re
from pathlib import Path

staging = Path("packaging/scripts/stage-hermes-plugin-payload.sh").read_text(encoding="utf-8")
build = Path("packaging/scripts/build-tarball.sh").read_text(encoding="utf-8")
allowed = re.findall(r"^copy_allowed_file '([^']+)'$", staging, flags=re.MULTILINE)
checksum_block = re.search(
    r"^\s*sha256sum \\\n(?P<body>.*?)^\s*> SHA256SUMS$",
    build,
    flags=re.MULTILINE | re.DOTALL,
)
if checksum_block is None:
    raise SystemExit("tarball SHA256SUMS command is missing or malformed")
covered = set(
    re.findall(
        r"^\s*(integrations/hermes/skynet-edr/\S+)\s*\\$",
        checksum_block.group("body"),
        flags=re.MULTILINE,
    )
)
missing = [
    path
    for path in allowed
    if f"integrations/hermes/skynet-edr/{path}" not in covered
]
if missing:
    raise SystemExit(
        "Hermes plugin payload files missing from tarball SHA256SUMS: "
        + ", ".join(missing)
    )
PY
if grep -q 'cp -R integrations/hermes/skynet-edr' packaging/scripts/build-tarball.sh packaging/scripts/build-packages.sh packaging/nfpm.yaml; then
  echo "Hermes plugin payload must be staged from an explicit allowlist, not copied recursively" >&2
  exit 1
fi
grep -q 'skynet-edr-hermes-enroll' packaging/scripts/skynet-edr-install-hermes-plugin.sh
grep -q 'dashboard/plugin.js' packaging/tarball/install.sh
grep -q 'dashboard/plugin_api.py' packaging/tarball/install.sh
grep -q 'desktop/plugin.js' packaging/tarball/install.sh
grep -q 'pre_tool_call' integrations/hermes/skynet-edr/__init__.py
grep -q 'post_tool_call' integrations/hermes/skynet-edr/__init__.py
grep -q 'skynet.event.v0' integrations/hermes/skynet-edr/__init__.py
grep -q 'skynet-edr-plugin.log' integrations/hermes/skynet-edr/README.md
grep -q 'events-v1.jsonl' integrations/hermes/skynet-edr/README.md
grep -q 'SKYNET_EDR_INGEST_SOCKET' integrations/hermes/skynet-edr/README.md
grep -q 'SUPPORTED_HERMES' packaging/scripts/skynet-edr-hermes-enroll.py
grep -q 'PLUGIN_SPOOL="$PLUGIN_STATE/events-v1.jsonl"' packaging/scripts/vm-smoke.sh
if grep -q 'PLUGIN_SPOOL="$PLUGIN_STATE/events.jsonl"' packaging/scripts/vm-smoke.sh; then
  echo "VM smoke must not open the historical Hermes events.jsonl spool" >&2
  exit 1
fi

grep -q 'systemd-sysusers' packaging/scripts/package-postinstall.sh
grep -q 'systemd-tmpfiles' packaging/scripts/package-postinstall.sh
grep -q 'chgrp skynet-edr /etc/skynet-edr/config.toml' packaging/scripts/package-postinstall.sh
grep -q 'systemctl daemon-reload' packaging/scripts/package-postinstall.sh
grep -q 'systemctl daemon-reload' packaging/scripts/package-postremove.sh

grep -q '^PREFIX=/usr$' packaging/tarball/install.sh
grep -q '^PREFIX=/usr$' packaging/tarball/uninstall.sh

grep -q 'Hermes Agent' docs/INSTALL.md
grep -q 'OpenClaw' docs/INSTALL.md
grep -q 'Codex' docs/INSTALL.md
grep -q 'Claude Code' docs/INSTALL.md
for family in Ubuntu Debian Mint RHEL Fedora Arch; do
  grep -q "$family" docs/INSTALL.md
done
grep -qi 'custom tarball' docs/PACKAGING.md

grep -q 'docs/INSTALL.md' README.md
grep -q 'docs/PACKAGING.md' README.md
grep -q 'skynet-edr doctor' docs/INSTALL.md
grep -q 'diagnostics collect' docs/INSTALL.md
grep -q 'skynet-edr doctor' docs/OPERATIONS.md
grep -q 'diagnostics collect' docs/OPERATIONS.md

grep -q 'workflow_dispatch:' .github/workflows/packaging-release.yml
grep -q 'push:' .github/workflows/packaging-release.yml
grep -q 'tags:' .github/workflows/packaging-release.yml
if grep -q '^  release:' .github/workflows/packaging-release.yml; then
  echo "packaging-release must not run on release events; tag push/manual only" >&2
  exit 1
fi
grep -q 'packaging/scripts/build-tarball.sh' .github/workflows/packaging-release.yml
grep -q 'packaging/scripts/build-packages.sh' .github/workflows/packaging-release.yml
grep -q 'packaging/scripts/inspect-artifacts.sh' .github/workflows/packaging-release.yml
grep -q 'actions/upload-artifact@' .github/workflows/packaging-release.yml

# Release/security hardening regression checks. Keep these narrow and explicit.
if grep -q 'directory: "/integrations/hermes/python"' .github/dependabot.yml; then
  echo "dead Dependabot pip ecosystem for /integrations/hermes/python must not return" >&2
  exit 1
fi
grep -q 'cooldown:' .github/dependabot.yml
grep -q 'package-ecosystem: "cargo"' .github/dependabot.yml
grep -q 'package-ecosystem: "github-actions"' .github/dependabot.yml

if [ ! -f .gitleaksignore ]; then
  echo "missing exact historical fake-secret gitleaks fingerprint allowlist" >&2
  exit 1
fi
grep -qx 'c7ad23af619abd84e3c475b5503a8af8f7696b19:crates/skynet-edr-core/tests/hermes_event_ingestion.rs:curl-auth-header:32' .gitleaksignore

for action in init autobuild analyze upload-sarif; do
  grep -q "github/codeql-action/${action}@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81 # v4.37.3" .github/workflows/codeql.yml .github/workflows/security.yml
done
grep -q 'trufflesecurity/trufflehog@6f3c981e7b77f235fd2702dd74af25fc4b72bf11' .github/workflows/security.yml
grep -q 'aquasecurity/trivy-action@c07df6fec6fa692e6fd1200d50aaa1fdd66f03c8' .github/workflows/security.yml

grep -q 'packaging/scripts/smoke-install-artifacts.sh' .github/workflows/packaging-release.yml
grep -q 'packaging/scripts/verify-public-release.sh' docs/RELEASE_PROCESS.md
grep -q 'docs/releases/${GITHUB_REF_NAME}.md' .github/workflows/packaging-release.yml
grep -q 'CARGO_TARGET_DIR' packaging/scripts/build-tarball.sh
grep -q 'CARGO_TARGET_DIR' packaging/scripts/build-packages.sh
if grep -q '0\.1\.0' .github/workflows/packaging-release.yml; then
  echo "packaging release notes must derive artifact names from tag/version, not hardcode 0.1.0" >&2
  exit 1
fi

sh -n packaging/tarball/install.sh
sh -n packaging/tarball/uninstall.sh
sh -n packaging/scripts/build-tarball.sh
sh -n packaging/scripts/build-packages.sh
sh -n packaging/scripts/stage-hermes-plugin-payload.sh
python3 - <<'PY'
import pathlib

script = pathlib.Path('packaging/scripts/stage-hermes-plugin-payload.sh').read_text()
for unsafe_fragment in ["old_ifs=$IFS", "IFS='/'", 'IFS=$old_ifs', 'set -- $rel_dir']:
    if unsafe_fragment in script:
        raise SystemExit(
            'Hermes plugin staging must iterate path components with quoted '
            f'parameter expansion, not {unsafe_fragment!r}'
        )
PY
sh -n packaging/scripts/inspect-artifacts.sh
sh -n packaging/scripts/smoke-install-artifacts.sh
sh -n packaging/scripts/verify-public-release.sh
sh -n packaging/scripts/package-postinstall.sh
sh -n packaging/scripts/package-postremove.sh
sh -n packaging/scripts/skynet-edr-install-hermes-plugin.sh
sh -n packaging/scripts/vm-smoke.sh

python3 - <<'PY'
import pathlib
text = pathlib.Path('packaging/nfpm.yaml').read_text()
for key in ['name:', 'arch:', 'platform:', 'version:', 'contents:']:
    if key not in text:
        raise SystemExit(f'nfpm config missing key: {key}')
for path in ['/usr/bin/skynet-edr', '/usr/bin/skynet-edr-daemon', '/etc/skynet-edr/config.toml', '/usr/lib/systemd/system/skynet-edr.service']:
    if f'dst: {path}' not in text:
        raise SystemExit(f'nfpm config missing destination: {path}')
PY

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/skynet-edr-hermes-stage.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT INT TERM
src_dir="$tmp_dir/src"
dst_dir="$tmp_dir/dst/skynet-edr"
mkdir -p "$src_dir/dashboard/__pycache__" "$src_dir/desktop" "$src_dir/__pycache__"
for path in \
  plugin.yaml \
  __init__.py \
  README.md \
  dashboard/manifest.json \
  dashboard/plugin.js \
  dashboard/plugin_api.py \
  desktop/plugin.js; do
  mkdir -p "$src_dir/$(dirname "$path")"
  printf 'allowed payload fixture: %s\n' "$path" > "$src_dir/$path"
done
printf 'generated cache fixture\n' > "$src_dir/__pycache__/__init__.cpython-312.pyc"
printf 'generated cache fixture\n' > "$src_dir/dashboard/__pycache__/plugin_api.cpython-312.pyc"
printf 'generated cache fixture\n' > "$src_dir/dashboard/plugin_api.pyc"

packaging/scripts/stage-hermes-plugin-payload.sh "$src_dir" "$dst_dir"
actual_payload="$tmp_dir/actual.txt"
expected_payload="$tmp_dir/expected.txt"
(
  cd "$dst_dir"
  find . -type f | sed 's#^./##' | sort
) > "$actual_payload"
cat > "$expected_payload" <<'EOF'
README.md
__init__.py
dashboard/manifest.json
dashboard/plugin.js
dashboard/plugin_api.py
desktop/plugin.js
plugin.yaml
EOF
if ! cmp -s "$expected_payload" "$actual_payload"; then
  echo "staged Hermes plugin payload does not match the exact allowlist" >&2
  diff -u "$expected_payload" "$actual_payload" >&2 || true
  exit 1
fi
if find "$dst_dir" \( -path '*/__pycache__/*' -o -name '*.pyc' \) | grep . >/dev/null 2>&1; then
  echo "staged Hermes plugin payload contains generated Python cache files" >&2
  exit 1
fi
if find "$dst_dir" -type f ! -perm 0644 | grep . >/dev/null 2>&1; then
  echo "staged Hermes plugin payload contains files without mode 0644" >&2
  exit 1
fi

symlink_root="$tmp_dir/src-link"
symlink_root_dst="$tmp_dir/dst/symlink-root"
ln -s "$src_dir" "$symlink_root"
if packaging/scripts/stage-hermes-plugin-payload.sh "$symlink_root" "$symlink_root_dst" >/dev/null 2>&1; then
  echo "Hermes plugin staging must reject a symlink source plugin directory" >&2
  exit 1
fi

dashboard_real="$tmp_dir/dashboard-real"
dashboard_symlink_src="$tmp_dir/src-dashboard-symlink"
dashboard_symlink_dst="$tmp_dir/dst/dashboard-symlink"
mkdir -p "$dashboard_real" "$dashboard_symlink_src/desktop"
for path in plugin.yaml __init__.py README.md desktop/plugin.js; do
  mkdir -p "$dashboard_symlink_src/$(dirname "$path")"
  printf 'allowed payload fixture: %s\n' "$path" > "$dashboard_symlink_src/$path"
done
printf 'allowed payload fixture: dashboard/manifest.json\n' > "$dashboard_real/manifest.json"
printf 'allowed payload fixture: dashboard/plugin.js\n' > "$dashboard_real/plugin.js"
printf 'allowed payload fixture: dashboard/plugin_api.py\n' > "$dashboard_real/plugin_api.py"
ln -s "$dashboard_real" "$dashboard_symlink_src/dashboard"
if packaging/scripts/stage-hermes-plugin-payload.sh "$dashboard_symlink_src" "$dashboard_symlink_dst" >/dev/null 2>&1; then
  echo "Hermes plugin staging must reject a symlink intermediate source directory" >&2
  exit 1
fi

existing_dst="$tmp_dir/dst/existing"
sentinel="$existing_dst/sentinel.txt"
sentinel_expected="$tmp_dir/sentinel.expected"
mkdir -p "$existing_dst"
printf 'preserve these sentinel bytes\n' > "$sentinel"
cp "$sentinel" "$sentinel_expected"
if packaging/scripts/stage-hermes-plugin-payload.sh "$src_dir" "$existing_dst" >/dev/null 2>&1; then
  echo "Hermes plugin staging must reject an existing destination directory" >&2
  exit 1
fi
if ! cmp -s "$sentinel_expected" "$sentinel"; then
  echo "Hermes plugin staging must preserve an existing destination unchanged" >&2
  exit 1
fi

echo "packaging baseline validation passed"
