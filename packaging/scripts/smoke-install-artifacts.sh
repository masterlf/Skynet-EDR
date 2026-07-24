#!/usr/bin/env sh
set -eu

DIST_DIR=${1:-dist}
TARGETS=${SKYNET_EDR_PACKAGE_SMOKE_TARGETS:-deb tarball rpm arch}
UBUNTU_IMAGE=${SKYNET_EDR_SMOKE_UBUNTU_IMAGE:-ubuntu:24.04}

if [ ! -d "$DIST_DIR" ]; then
  echo "artifact directory not found: $DIST_DIR" >&2
  exit 1
fi
DIST_DIR=$(CDPATH= cd -- "$DIST_DIR" && pwd)

find_one() {
  pattern=$1
  matches=$(find "$DIST_DIR" -maxdepth 1 -type f -name "$pattern" | sort)
  count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
  if [ "$count" -ne 1 ]; then
    echo "expected exactly one artifact matching $pattern in $DIST_DIR, found $count" >&2
    printf '%s\n' "$matches" >&2
    exit 1
  fi
  basename "$matches"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required smoke command not found: $1" >&2
    exit 1
  fi
}

require_checksums() {
  if [ ! -f "$DIST_DIR/checksums.txt" ]; then
    echo "missing checksum manifest: $DIST_DIR/checksums.txt" >&2
    exit 1
  fi
  (cd "$DIST_DIR" && sha256sum -c checksums.txt --ignore-missing)
}

container_engine() {
  if [ -n "${CONTAINER_ENGINE:-}" ]; then
    printf '%s\n' "$CONTAINER_ENGINE"
  elif command -v docker >/dev/null 2>&1; then
    printf '%s\n' docker
  elif command -v podman >/dev/null 2>&1; then
    printf '%s\n' podman
  else
    echo "docker or podman is required for clean DEB/tarball smoke tests" >&2
    exit 1
  fi
}

run_container() {
  name=$1
  image=$2
  shift 2
  engine=$(container_engine)
  echo "==> smoke: $name on $image"
  "$engine" run --rm \
    --name "skynet-edr-smoke-${name}-$$" \
    -v "$DIST_DIR:/artifacts:ro" \
    "$image" \
    sh -eu -s -- "$@"
}

smoke_deb() {
  deb=$(find_one 'skynet-edr_*.deb')
  run_container deb "$UBUNTU_IMAGE" "$deb" <<'SH'
deb=$1
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates systemd
(cd /artifacts && sha256sum -c checksums.txt --ignore-missing)
apt-get install -y --no-install-recommends "/artifacts/$deb"
skynet-edr --version
skynet-edr-daemon --version
skynet-edr-daemon status
test -x /usr/bin/skynet-edr
test -x /usr/bin/skynet-edr-daemon
test -r /etc/skynet-edr/config.toml
systemd-analyze verify /usr/lib/systemd/system/skynet-edr.service
printf 'state preserved across package remove\n' > /var/lib/skynet-edr/smoke-state.txt
apt-get remove -y skynet-edr
test ! -e /usr/bin/skynet-edr
test ! -e /usr/bin/skynet-edr-daemon
test -f /var/lib/skynet-edr/smoke-state.txt
apt-get purge -y skynet-edr
test ! -e /etc/skynet-edr/config.toml
test -f /var/lib/skynet-edr/smoke-state.txt
SH
}

smoke_tarball() {
  tarball=$(find_one 'skynet-edr-*.tar.gz')
  run_container tarball "$UBUNTU_IMAGE" "$tarball" <<'SH'
tarball=$1
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates systemd passwd
(cd /artifacts && sha256sum -c checksums.txt --ignore-missing)
workdir=$(mktemp -d)
tar -C "$workdir" -xzf "/artifacts/$tarball"
root=$(find "$workdir" -mindepth 1 -maxdepth 1 -type d | head -n 1)
cd "$root"
sha256sum -c SHA256SUMS
./bin/skynet-edr --version
./bin/skynet-edr-daemon --version
./bin/skynet-edr-daemon status
./install.sh --prefix /usr
skynet-edr --version
skynet-edr-daemon --version
skynet-edr-daemon status
test -x /usr/bin/skynet-edr
test -x /usr/bin/skynet-edr-daemon
test -r /etc/skynet-edr/config.toml
systemd-analyze verify /usr/lib/systemd/system/skynet-edr.service
printf 'state preserved across tarball uninstall\n' > /var/lib/skynet-edr/smoke-state.txt
./uninstall.sh --prefix /usr
test ! -e /usr/bin/skynet-edr
test ! -e /usr/bin/skynet-edr-daemon
test -f /etc/skynet-edr/config.toml
test -f /var/lib/skynet-edr/smoke-state.txt
./install.sh --prefix /usr
./uninstall.sh --prefix /usr --purge
test ! -e /etc/skynet-edr
test ! -e /var/lib/skynet-edr
test ! -e /var/log/skynet-edr
test ! -e /var/cache/skynet-edr
test ! -e /run/skynet-edr
SH
}

validate_rpm() {
  rpm_pkg=$(find_one 'skynet-edr-*.rpm')
  require_cmd rpm
  require_checksums
  rpm -qpl "$DIST_DIR/$rpm_pkg" | grep -q '^/usr/bin/skynet-edr$'
  rpm -qpl "$DIST_DIR/$rpm_pkg" | grep -q '^/usr/bin/skynet-edr-daemon$'
  rpm -qpl "$DIST_DIR/$rpm_pkg" | grep -q '^/usr/lib/systemd/system/skynet-edr.service$'
  echo "rpm artifact validation passed"
}

validate_arch() {
  arch_pkg=$(find_one 'skynet-edr-*.pkg.tar.zst')
  require_cmd tar
  require_cmd zstd
  require_checksums
  tar --zstd -tf "$DIST_DIR/$arch_pkg" | grep -q '^usr/bin/skynet-edr$'
  tar --zstd -tf "$DIST_DIR/$arch_pkg" | grep -q '^usr/bin/skynet-edr-daemon$'
  tar --zstd -tf "$DIST_DIR/$arch_pkg" | grep -q '^usr/lib/systemd/system/skynet-edr.service$'
  echo "Arch artifact validation passed"
}

for target in $TARGETS; do
  case "$target" in
    deb) smoke_deb ;;
    tarball|tar) smoke_tarball ;;
    rpm) validate_rpm ;;
    arch|archlinux) validate_arch ;;
    *) echo "unknown smoke target: $target" >&2; exit 2 ;;
  esac
done

echo "package smoke/validation passed: $TARGETS"
