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
"

for file in $required_files; do
  if [ ! -f "$file" ]; then
    echo "missing required packaging file: $file" >&2
    exit 1
  fi
done

for script in packaging/tarball/install.sh packaging/tarball/uninstall.sh packaging/scripts/build-tarball.sh packaging/scripts/build-packages.sh packaging/scripts/validate-packaging.sh; do
  if [ ! -x "$script" ]; then
    echo "packaging script must be executable: $script" >&2
    exit 1
  fi
done

grep -q 'User=skynet-edr' packaging/systemd/skynet-edr.service
grep -q 'Group=skynet-edr' packaging/systemd/skynet-edr.service
grep -q 'NoNewPrivileges=yes' packaging/systemd/skynet-edr.service
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

sh -n packaging/tarball/install.sh
sh -n packaging/tarball/uninstall.sh
sh -n packaging/scripts/build-tarball.sh
sh -n packaging/scripts/build-packages.sh

python3 - <<'PY'
import pathlib, sys, yaml
config = yaml.safe_load(pathlib.Path('packaging/nfpm.yaml').read_text())
required = {'name', 'arch', 'platform', 'version', 'contents'}
missing = required - set(config)
if missing:
    raise SystemExit(f'nfpm config missing keys: {sorted(missing)}')
paths = {entry.get('dst') for entry in config['contents'] if isinstance(entry, dict)}
for path in ['/usr/bin/skynet-edr', '/usr/bin/skynet-edr-daemon', '/etc/skynet-edr/config.toml', '/usr/lib/systemd/system/skynet-edr.service']:
    if path not in paths:
        raise SystemExit(f'nfpm config missing destination: {path}')
PY

echo "packaging baseline validation passed"
