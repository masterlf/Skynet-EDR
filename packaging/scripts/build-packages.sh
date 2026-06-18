#!/usr/bin/env sh
set -eu

VERSION="${SKYNET_EDR_VERSION:-$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"] == "skynet-edr-cli"))')}"
DEB_ARCH="${NFPM_ARCH:-amd64}"
RPM_ARCH="${NFPM_RPM_ARCH:-x86_64}"
ARCHLINUX_ARCH="${NFPM_ARCHLINUX_ARCH:-x86_64}"
NFPM_RENDERED="dist/nfpm.${VERSION}.yaml"

mkdir -p dist
cargo build --release --workspace --bins

if ! command -v nfpm >/dev/null 2>&1; then
  echo "nfpm is required to build deb/rpm/arch packages" >&2
  exit 1
fi

python3 - "$VERSION" <<'PY'
import re
import sys
from pathlib import Path
version = sys.argv[1]
source = Path('packaging/nfpm.yaml')
target = Path('dist') / f'nfpm.{version}.yaml'
text = source.read_text()
text = re.sub(r'^version:.*$', f'version: {version}', text, flags=re.MULTILINE)
target.write_text(text)
PY

NFPM_ARCH="$DEB_ARCH" nfpm package \
  --config "$NFPM_RENDERED" \
  --packager deb \
  --target "dist/skynet-edr_${VERSION}_${DEB_ARCH}.deb"

NFPM_ARCH="$RPM_ARCH" nfpm package \
  --config "$NFPM_RENDERED" \
  --packager rpm \
  --target "dist/skynet-edr-${VERSION}-1.${RPM_ARCH}.rpm"

NFPM_ARCH="$ARCHLINUX_ARCH" nfpm package \
  --config "$NFPM_RENDERED" \
  --packager archlinux \
  --target "dist/skynet-edr-${VERSION}-1-${ARCHLINUX_ARCH}.pkg.tar.zst"
