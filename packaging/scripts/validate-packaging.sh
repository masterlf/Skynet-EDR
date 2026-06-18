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
packaging/scripts/inspect-artifacts.sh
packaging/scripts/package-postinstall.sh
packaging/scripts/package-postremove.sh
.github/workflows/packaging-release.yml
"

for file in $required_files; do
  if [ ! -f "$file" ]; then
    echo "missing required packaging file: $file" >&2
    exit 1
  fi
done

for script in packaging/tarball/install.sh packaging/tarball/uninstall.sh packaging/scripts/build-tarball.sh packaging/scripts/build-packages.sh packaging/scripts/inspect-artifacts.sh packaging/scripts/validate-packaging.sh packaging/scripts/package-postinstall.sh packaging/scripts/package-postremove.sh; do
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
grep -q 'IPAddressDeny=any' packaging/systemd/skynet-edr.service
grep -q 'IPAddressAllow=localhost' packaging/systemd/skynet-edr.service
grep -q 'ExecStart=/usr/bin/skynet-edr-daemon run --config /etc/skynet-edr/config.toml' packaging/systemd/skynet-edr.service

grep -q '^u skynet-edr ' packaging/sysusers/skynet-edr.conf
grep -q '^d /var/lib/skynet-edr 0750 skynet-edr skynet-edr -' packaging/tmpfiles/skynet-edr.conf
grep -q '^d /etc/skynet-edr 0750 root skynet-edr -' packaging/tmpfiles/skynet-edr.conf

grep -q 'skynet-edr-daemon' packaging/nfpm.yaml
grep -q 'type: config|noreplace' packaging/nfpm.yaml
grep -q '/etc/skynet-edr/agents.d' packaging/nfpm.yaml
grep -q 'scripts:' packaging/nfpm.yaml
grep -q 'postinstall:' packaging/nfpm.yaml
grep -q 'postremove:' packaging/nfpm.yaml
grep -q 'packaging/scripts/package-postinstall.sh' packaging/nfpm.yaml
grep -q 'packaging/scripts/package-postremove.sh' packaging/nfpm.yaml

grep -q 'systemd-sysusers' packaging/scripts/package-postinstall.sh
grep -q 'systemd-tmpfiles' packaging/scripts/package-postinstall.sh
grep -q 'chgrp skynet-edr /etc/skynet-edr/config.toml' packaging/scripts/package-postinstall.sh
grep -q 'systemctl daemon-reload' packaging/scripts/package-postinstall.sh
grep -q 'systemctl daemon-reload' packaging/scripts/package-postremove.sh

grep -q '^PREFIX=/usr$' packaging/tarball/install.sh

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

grep -q 'workflow_dispatch:' .github/workflows/packaging-release.yml
grep -q 'release:' .github/workflows/packaging-release.yml
grep -q 'packaging/scripts/build-tarball.sh' .github/workflows/packaging-release.yml
grep -q 'packaging/scripts/build-packages.sh' .github/workflows/packaging-release.yml
grep -q 'packaging/scripts/inspect-artifacts.sh' .github/workflows/packaging-release.yml
grep -q 'actions/upload-artifact@' .github/workflows/packaging-release.yml

sh -n packaging/tarball/install.sh
sh -n packaging/tarball/uninstall.sh
sh -n packaging/scripts/build-tarball.sh
sh -n packaging/scripts/build-packages.sh
sh -n packaging/scripts/inspect-artifacts.sh
sh -n packaging/scripts/package-postinstall.sh
sh -n packaging/scripts/package-postremove.sh

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

echo "packaging baseline validation passed"
