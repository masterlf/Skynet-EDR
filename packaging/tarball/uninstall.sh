#!/usr/bin/env sh
set -eu

PURGE=0
PREFIX=/usr

while [ "$#" -gt 0 ]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    --prefix) PREFIX=${2:?missing --prefix value}; shift 2 ;;
    --help|-h)
      echo "Usage: sudo ./uninstall.sh [--prefix <absolute-path>] [--purge]"
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$PREFIX" in
  /*) ;;
  *)
    echo "prefix must be an absolute path: $PREFIX" >&2
    exit 1
    ;;
esac

case "$PREFIX" in
  /|/tmp|/var/tmp)
    echo "refusing unsafe prefix: $PREFIX" >&2
    exit 1
    ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "uninstall.sh must be run as root" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now skynet-edr.service 2>/dev/null || true
fi

rm -f "$PREFIX/bin/skynet-edr"
rm -f "$PREFIX/bin/skynet-edr-daemon"
rm -f "$PREFIX/bin/skynet-edr-install-hermes-plugin"
rm -f "$PREFIX/bin/skynet-edr-hermes-enroll"
rm -f /usr/lib/systemd/system/skynet-edr.service
rm -f /usr/lib/sysusers.d/skynet-edr.conf
rm -f /usr/lib/tmpfiles.d/skynet-edr.conf
rm -f /usr/share/doc/skynet-edr/INSTALL.md
rm -f /usr/share/doc/skynet-edr/PACKAGING.md
rm -rf /usr/share/skynet-edr/hermes-plugin
rmdir /usr/share/doc/skynet-edr /usr/share/skynet-edr 2>/dev/null || true

if [ "$PURGE" -eq 1 ]; then
  rm -rf /etc/skynet-edr /var/lib/skynet-edr /var/log/skynet-edr /var/cache/skynet-edr /run/skynet-edr
  echo "Purged Skynet-EDR config, state, logs, cache, and runtime directories."
else
  echo "Preserved /etc/skynet-edr, /var/lib/skynet-edr, /var/log/skynet-edr, and user/group."
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

echo "Removed Skynet-EDR binaries and service metadata."
