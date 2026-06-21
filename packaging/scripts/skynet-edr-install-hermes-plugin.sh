#!/usr/bin/env sh
set -eu

usage() {
  cat <<'USAGE'
Usage: skynet-edr-install-hermes-plugin [--plugin-source <dir>] [--hermes-home <dir>] [--no-enable]

Installs the Skynet-EDR passive Hermes plugin into the current user's Hermes
plugin directory. Run as the Hermes user, not as root, unless you are installing
for root's Hermes profile intentionally.
USAGE
}

PLUGIN_SOURCE=/usr/share/skynet-edr/hermes-plugin/skynet-edr
HERMES_HOME=${HERMES_HOME:-$HOME/.hermes}
ENABLE=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plugin-source) PLUGIN_SOURCE=${2:?missing source}; shift 2 ;;
    --hermes-home) HERMES_HOME=${2:?missing Hermes home}; shift 2 ;;
    --no-enable) ENABLE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ ! -d "$PLUGIN_SOURCE" ]; then
  echo "plugin source not found: $PLUGIN_SOURCE" >&2
  exit 1
fi

TARGET="$HERMES_HOME/plugins/skynet-edr"
install -d -m 0700 "$HERMES_HOME" "$HERMES_HOME/plugins" "$TARGET"
install -m 0644 "$PLUGIN_SOURCE/plugin.yaml" "$TARGET/plugin.yaml"
install -m 0644 "$PLUGIN_SOURCE/__init__.py" "$TARGET/__init__.py"
install -m 0644 "$PLUGIN_SOURCE/README.md" "$TARGET/README.md"

STATE_DIR=${SKYNET_EDR_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/skynet-edr/hermes}
install -d -m 0700 "$STATE_DIR"

echo "Installed Skynet-EDR Hermes plugin to $TARGET"
echo "Default event spool: ${SKYNET_EDR_SPOOL_PATH:-$STATE_DIR/events.jsonl}"
echo "Default plugin log:  ${SKYNET_EDR_LOG_PATH:-$STATE_DIR/skynet-edr-plugin.log}"

if [ "$ENABLE" -eq 1 ] && command -v hermes >/dev/null 2>&1; then
  if hermes plugins enable skynet-edr >/dev/null 2>&1; then
    echo "Enabled plugin with: hermes plugins enable skynet-edr"
  else
    echo "Plugin copied. If Hermes uses opt-in plugins, enable it with: hermes plugins enable skynet-edr" >&2
  fi
else
  echo "If Hermes uses opt-in plugins, enable it with: hermes plugins enable skynet-edr"
fi

echo "Restart Hermes sessions after installation so hooks are loaded."
