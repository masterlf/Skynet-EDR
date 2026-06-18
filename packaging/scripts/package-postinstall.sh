#!/usr/bin/env sh
set -eu

if command -v systemd-sysusers >/dev/null 2>&1 && [ -f /usr/lib/sysusers.d/skynet-edr.conf ]; then
  systemd-sysusers /usr/lib/sysusers.d/skynet-edr.conf || true
fi

if command -v systemd-tmpfiles >/dev/null 2>&1 && [ -f /usr/lib/tmpfiles.d/skynet-edr.conf ]; then
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/skynet-edr.conf || true
fi

if getent group skynet-edr >/dev/null 2>&1; then
  if [ -d /etc/skynet-edr ]; then
    chgrp skynet-edr /etc/skynet-edr || true
    chmod 0750 /etc/skynet-edr || true
  fi
  if [ -f /etc/skynet-edr/config.toml ]; then
    chgrp skynet-edr /etc/skynet-edr/config.toml || true
    chmod 0640 /etc/skynet-edr/config.toml || true
  fi
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
