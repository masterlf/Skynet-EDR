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

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command not found: $1" >&2
    exit 1
  fi
}

require_cmd awk
require_cmd curl
require_cmd dpkg-deb
require_cmd find
require_cmd grep
require_cmd mktemp
require_cmd mv
require_cmd rpm
require_cmd sed
require_cmd sha256sum
require_cmd tar
require_cmd wc
require_cmd zstd

validate_segment() {
  name=$1
  value=$2
  if [ -z "$value" ] || [ "$value" = "." ] || [ "$value" = ".." ]; then
    echo "invalid $name in --repo: $value" >&2
    exit 2
  fi
  case "$value" in
    -*|*".."*|*[!A-Za-z0-9._-]*)
      echo "invalid $name in --repo: $value" >&2
      exit 2
      ;;
  esac
}

OWNER=${REPO%%/*}
REPO_NAME=${REPO#*/}
if [ "$OWNER" = "$REPO" ] || [ -z "$OWNER" ] || [ -z "$REPO_NAME" ]; then
  echo "--repo must be OWNER/REPO" >&2
  exit 2
fi
case "$REPO_NAME" in
  */*) echo "--repo must be exactly OWNER/REPO, not a path" >&2; exit 2 ;;
esac
validate_segment owner "$OWNER"
validate_segment repo "$REPO_NAME"

if ! printf '%s\n' "$TAG" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'; then
  echo "--tag must be a strict semantic version tag like v0.3.0, optionally with prerelease/build metadata" >&2
  exit 2
fi

VERSION=${TAG#v}
TARGET=${SKYNET_EDR_TARGET:-x86_64-unknown-linux-gnu}
DEB_ARCH=${NFPM_ARCH:-amd64}
RPM_ARCH=${NFPM_RPM_ARCH:-x86_64}
ARCHLINUX_ARCH=${NFPM_ARCHLINUX_ARCH:-x86_64}

DEB="skynet-edr_${VERSION}_${DEB_ARCH}.deb"
RPM="skynet-edr-${VERSION}-1.${RPM_ARCH}.rpm"
ARCH="skynet-edr-${VERSION}-1-${ARCHLINUX_ARCH}.pkg.tar.zst"
TARBALL="skynet-edr-${VERSION}-${TARGET}.tar.gz"
CHECKSUMS="checksums.txt"
BASE_URL="https://github.com/${OWNER}/${REPO_NAME}/releases/download/${TAG}"

prepare_work_dir() {
  if [ -z "$WORK_DIR" ]; then
    WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/skynet-edr-public-release.XXXXXX")
    return
  fi
  if [ -L "$WORK_DIR" ]; then
    echo "--work-dir must not be a symlink: $WORK_DIR" >&2
    exit 2
  fi
  if [ -e "$WORK_DIR" ] && [ ! -d "$WORK_DIR" ]; then
    echo "--work-dir must be a directory: $WORK_DIR" >&2
    exit 2
  fi
  mkdir -p "$WORK_DIR"
  if [ "$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" -ne 0 ]; then
    echo "--work-dir must be fresh/empty so release assets cannot clobber existing files or symlinks: $WORK_DIR" >&2
    exit 2
  fi
}

fetch_asset() {
  asset=$1
  case "$asset" in
    */*|*..*|'' ) echo "refusing unsafe asset basename: $asset" >&2; exit 2 ;;
  esac
  if [ -e "$asset" ] || [ -L "$asset" ]; then
    echo "refusing to overwrite existing asset path: $asset" >&2
    exit 2
  fi
  tmp="${asset}.download"
  curl -fsSL --proto '=https' --tlsv1.2 --output "$tmp" "${BASE_URL}/${asset}"
  mv "$tmp" "$asset"
}

validate_checksum_manifest() {
  manifest=$1
  expected="$CHECKSUMS $DEB $RPM $ARCH $TARBALL"
  entries=$(awk '{name=$2; sub(/^\*/, "", name); print name}' "$manifest")
  count=$(printf '%s\n' "$entries" | sed '/^$/d' | wc -l | tr -d ' ')
  if [ "$count" -lt 4 ] || [ "$count" -gt 5 ]; then
    echo "checksum manifest must reference only the five expected release basenames and include the four package assets, found $count entries" >&2
    exit 1
  fi
  for entry in $entries; do
    case "$entry" in
      */*|*..*|'' ) echo "checksum manifest contains unsafe path: $entry" >&2; exit 1 ;;
    esac
    allowed=false
    for asset in $expected; do
      if [ "$entry" = "$asset" ]; then
        allowed=true
      fi
    done
    if [ "$allowed" != true ]; then
      echo "checksum manifest references unexpected basename: $entry" >&2
      exit 1
    fi
  done
  for required in "$DEB" "$RPM" "$ARCH" "$TARBALL"; do
    if ! printf '%s\n' "$entries" | grep -Fxq "$required"; then
      echo "checksum manifest missing expected asset: $required" >&2
      exit 1
    fi
  done
}

assert_version() {
  binary=$1
  expected_output=$2
  output=$($binary --version)
  if [ "$output" != "$expected_output" ]; then
    echo "unexpected version output from $binary: $output != $expected_output" >&2
    exit 1
  fi
}

prepare_work_dir
WORK_DIR=$(CDPATH= cd -- "$WORK_DIR" && pwd)

printf 'verifying public release %s/%s %s in %s\n' "$OWNER" "$REPO_NAME" "$TAG" "$WORK_DIR"
cd "$WORK_DIR"

for asset in "$CHECKSUMS" "$DEB" "$RPM" "$ARCH" "$TARBALL"; do
  fetch_asset "$asset"
done

validate_checksum_manifest "$CHECKSUMS"
sha256sum -c "$CHECKSUMS"

dpkg-deb -x "$DEB" deb-root
assert_version ./deb-root/usr/bin/skynet-edr "skynet-edr ${VERSION}"
assert_version ./deb-root/usr/bin/skynet-edr-daemon "skynet-edr-daemon ${VERSION}"
./deb-root/usr/bin/skynet-edr-daemon status

tar -xzf "$TARBALL"
if [ ! -d "skynet-edr-${VERSION}-${TARGET}" ] || [ -L "skynet-edr-${VERSION}-${TARGET}" ]; then
  echo "tarball did not extract expected directory: skynet-edr-${VERSION}-${TARGET}" >&2
  exit 1
fi
cd "skynet-edr-${VERSION}-${TARGET}"
sha256sum -c SHA256SUMS
assert_version ./bin/skynet-edr "skynet-edr ${VERSION}"
assert_version ./bin/skynet-edr-daemon "skynet-edr-daemon ${VERSION}"
./bin/skynet-edr-daemon status
cd "$WORK_DIR"

rpm -qpl "$RPM" | grep -q '^/usr/bin/skynet-edr$'
rpm -qpl "$RPM" | grep -q '^/usr/bin/skynet-edr-daemon$'
rpm -qpl "$RPM" | grep -q '^/usr/lib/systemd/system/skynet-edr.service$'

tar --zstd -tf "$ARCH" | grep -q '^usr/bin/skynet-edr$'
tar --zstd -tf "$ARCH" | grep -q '^usr/bin/skynet-edr-daemon$'
tar --zstd -tf "$ARCH" | grep -q '^usr/lib/systemd/system/skynet-edr.service$'

echo "public release verification passed: ${OWNER}/${REPO_NAME} ${TAG}"
