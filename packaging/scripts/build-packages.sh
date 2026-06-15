#!/usr/bin/env sh
set -eu

VERSION="${SKYNET_EDR_VERSION:-$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"] == "skynet-edr-cli"))')}"
ARCH="${NFPM_ARCH:-amd64}"

mkdir -p dist
cargo build --release --workspace --bins

if ! command -v nfpm >/dev/null 2>&1; then
  echo "nfpm is required to build deb/rpm/arch packages" >&2
  exit 1
fi

SKYNET_EDR_VERSION="$VERSION" NFPM_ARCH="$ARCH" nfpm package \
  --config packaging/nfpm.yaml \
  --packager deb \
  --target "dist/skynet-edr_${VERSION}_${ARCH}.deb"

SKYNET_EDR_VERSION="$VERSION" NFPM_ARCH="$ARCH" nfpm package \
  --config packaging/nfpm.yaml \
  --packager rpm \
  --target "dist/skynet-edr-${VERSION}-1.${ARCH}.rpm"

SKYNET_EDR_VERSION="$VERSION" NFPM_ARCH="$ARCH" nfpm package \
  --config packaging/nfpm.yaml \
  --packager archlinux \
  --target "dist/skynet-edr-${VERSION}-1-${ARCH}.pkg.tar.zst"
