#!/usr/bin/env sh
set -eu

usage() {
  cat <<'USAGE'
Usage: install.sh [--prefix /usr|/usr/local] [--source target/release] [--no-systemd]

Installs Skynet-EDR binaries and Linux service templates from a source checkout
or release tarball. Run as root. Existing /etc/skynet-edr/config.toml is
preserved.
USAGE
}

PREFIX=/usr/local
SOURCE=target/release
INSTALL_SYSTEMD=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX=${2:?missing --prefix value}; shift 2 ;;
    --source) SOURCE=${2:?missing --source value}; shift 2 ;;
    --no-systemd) INSTALL_SYSTEMD=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

case "$PREFIX" in
  /|/tmp|/var/tmp)
    echo "refusing unsafe prefix: $PREFIX" >&2
    exit 1
    ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -d "$SCRIPT_DIR/packaging" ]; then
  ROOT=$SCRIPT_DIR
elif [ -d "$SCRIPT_DIR/../packaging" ]; then
  ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
else
  ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
fi

install_file() {
  src=$1
  dst=$2
  mode=$3
  owner_group=$4
  if [ ! -f "$src" ]; then
    echo "required source file missing: $src" >&2
    exit 1
  fi
  install -D -m "$mode" -o "${owner_group%:*}" -g "${owner_group#*:}" "$src" "$dst"
}

if [ -f "$SCRIPT_DIR/SHA256SUMS" ] && command -v sha256sum >/dev/null 2>&1; then
  (cd "$SCRIPT_DIR" && sha256sum -c SHA256SUMS)
fi

if ! getent group skynet-edr >/dev/null 2>&1; then
  groupadd --system skynet-edr
fi
if ! id skynet-edr >/dev/null 2>&1; then
  useradd --system --gid skynet-edr --home-dir /var/lib/skynet-edr --shell /usr/sbin/nologin skynet-edr
fi

install_file "$SOURCE/skynet-edr" "$PREFIX/bin/skynet-edr" 0755 root:root
install_file "$SOURCE/skynet-edr-daemon" "$PREFIX/bin/skynet-edr-daemon" 0755 root:root

install -d -m 0750 -o root -g skynet-edr /etc/skynet-edr /etc/skynet-edr/rules.d /etc/skynet-edr/agents.d
if [ ! -f /etc/skynet-edr/config.toml ]; then
  install_file "$ROOT/packaging/config/config.toml" /etc/skynet-edr/config.toml 0640 root:skynet-edr
else
  echo "preserved existing /etc/skynet-edr/config.toml"
fi

if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
  install_file "$ROOT/packaging/systemd/skynet-edr.service" /usr/lib/systemd/system/skynet-edr.service 0644 root:root
  install_file "$ROOT/packaging/sysusers/skynet-edr.conf" /usr/lib/sysusers.d/skynet-edr.conf 0644 root:root
  install_file "$ROOT/packaging/tmpfiles/skynet-edr.conf" /usr/lib/tmpfiles.d/skynet-edr.conf 0644 root:root
fi
install_file "$ROOT/docs/INSTALL.md" /usr/share/doc/skynet-edr/INSTALL.md 0644 root:root
install_file "$ROOT/docs/PACKAGING.md" /usr/share/doc/skynet-edr/PACKAGING.md 0644 root:root

install -d -m 0750 -o skynet-edr -g skynet-edr /var/lib/skynet-edr /var/log/skynet-edr /var/cache/skynet-edr /run/skynet-edr

if [ "$INSTALL_SYSTEMD" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

echo "Skynet-EDR installed. Review /etc/skynet-edr/config.toml before enabling the service."
echo "Current daemon service is forward-looking until persistent run mode is implemented."
