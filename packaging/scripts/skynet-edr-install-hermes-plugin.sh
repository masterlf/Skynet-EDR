#!/usr/bin/env sh
set -eu

# Compatibility entry point only. The historical advisory copier was removed:
# copied bytes and a zero exit from `hermes plugins enable` are not enrollment.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ENROLLER="$SCRIPT_DIR/skynet-edr-hermes-enroll"
if [ ! -x "$ENROLLER" ]; then
  echo '{"category":"unsupported_contract","noop":false,"schema":1,"state":"DRIFTED"}'
  exit 1
fi
exec "$ENROLLER" "$@"
