#!/usr/bin/env sh
set -eu

usage() {
  cat <<'USAGE'
Usage: verify-public-release.sh --repo OWNER/REPO --tag vX.Y.Z [--work-dir DIR]

Downloads public Skynet-EDR release assets, verifies checksums, extracts the DEB
and tarball, runs packaged binaries, and validates RPM/Arch contents. Uses only
public release URLs; do not pass credentials.
USAGE
}

REPO=
TAG=
WORK_DIR=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) REPO=${2:?missing --repo value}; shift 2 ;;
    --tag) TAG=${2:?missing --tag value}; shift 2 ;;
    --work-dir) WORK_DIR=${2:?missing --work-dir value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$REPO" ] || [ -z "$TAG" ]; then
  usage >&2
  exit 2
fi
case "$REPO" in
  */*) ;;
  *) echo "--repo must be OWNER/REPO" >&2; exit 2 ;;
esac
case "$TAG" in
  v*) ;;
  *) echo "--tag must be a version tag like v0.3.0" >&2; exit 2 ;;
esac

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command not found: $1" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd sha256sum
require_cmd tar
require_cmd dpkg-deb
require_cmd rpm
require_cmd zstd

VERSION=${TAG#v}
TARGET=${SKYNET_EDR_TARGET:-x86_64-unknown-linux-gnu}
DEB_ARCH=${NFPM_ARCH:-amd64}
RPM_ARCH=${NFPM_RPM_ARCH:-x86_64}
ARCHLINUX_ARCH=${NFPM_ARCHLINUX_ARCH:-x86_64}

DEB="skynet-edr_${VERSION}_${DEB_ARCH}.deb"
RPM="skynet-edr-${VERSION}-1.${RPM_ARCH}.rpm"
ARCH="skynet-edr-${VERSION}-1-${ARCHLINUX_ARCH}.pkg.tar.zst"
TARBALL="skynet-edr-${VERSION}-${TARGET}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

if [ -z "$WORK_DIR" ]; then
  WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/skynet-edr-public-release.XXXXXX")
else
  mkdir -p "$WORK_DIR"
fi
WORK_DIR=$(CDPATH= cd -- "$WORK_DIR" && pwd)

echo "verifying public release ${REPO} ${TAG} in ${WORK_DIR}"
cd "$WORK_DIR"

for asset in checksums.txt "$DEB" "$RPM" "$ARCH" "$TARBALL"; do
  curl -fsSLO "${BASE_URL}/${asset}"
done

sha256sum -c checksums.txt

dpkg-deb -x "$DEB" deb-root
./deb-root/usr/bin/skynet-edr --version
./deb-root/usr/bin/skynet-edr-daemon --version
./deb-root/usr/bin/skynet-edr-daemon status

tar -xzf "$TARBALL"
cd "skynet-edr-${VERSION}-${TARGET}"
sha256sum -c SHA256SUMS
./bin/skynet-edr --version
./bin/skynet-edr-daemon --version
./bin/skynet-edr-daemon status
cd "$WORK_DIR"

rpm -qpl "$RPM" | grep -q '^/usr/bin/skynet-edr$'
rpm -qpl "$RPM" | grep -q '^/usr/bin/skynet-edr-daemon$'
rpm -qpl "$RPM" | grep -q '^/usr/lib/systemd/system/skynet-edr.service$'

tar --zstd -tf "$ARCH" | grep -q '^usr/bin/skynet-edr$'
tar --zstd -tf "$ARCH" | grep -q '^usr/bin/skynet-edr-daemon$'
tar --zstd -tf "$ARCH" | grep -q '^usr/lib/systemd/system/skynet-edr.service$'

echo "public release verification passed: ${REPO} ${TAG}"
