#!/usr/bin/env sh
set -eu

case "${1:-}" in
  upgrade|1|2)
    exit 0
    ;;
esac

for snapshot in /var/lib/skynet-edr-hermes-enrollment/adapter/*/snapshot.json; do
  if [ -f "$snapshot" ]; then
    echo "Skynet-EDR Hermes enrollment is active; run skynet-edr-hermes-enroll unenroll before removing the package." >&2
    exit 1
  fi
done
