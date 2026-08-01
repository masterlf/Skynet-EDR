#!/usr/bin/env sh
set -eu

VERSION="${SKYNET_EDR_VERSION:-$(cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"] == "skynet-edr-cli"))')}"
DEB_ARCH="${NFPM_ARCH:-amd64}"
RPM_ARCH="${NFPM_RPM_ARCH:-x86_64}"
ARCHLINUX_ARCH="${NFPM_ARCHLINUX_ARCH:-x86_64}"
NFPM_RENDERED="dist/nfpm.${VERSION}.yaml"
CARGO_RELEASE_DIR="${CARGO_TARGET_DIR:-target}/release"
STAGED_HERMES_PLUGIN="dist/staging/nfpm/hermes-plugin/skynet-edr"

mkdir -p dist
cargo build --locked --release --workspace --bins

if ! command -v nfpm >/dev/null 2>&1; then
  echo "nfpm is required to build deb/rpm/arch packages" >&2
  exit 1
fi

rm -rf dist/staging/nfpm/hermes-plugin/skynet-edr
packaging/scripts/stage-hermes-plugin-payload.sh integrations/hermes/skynet-edr "$STAGED_HERMES_PLUGIN"

python3 - "$VERSION" "$CARGO_RELEASE_DIR" <<'PY'
import re
import sys
from pathlib import Path
version = sys.argv[1]
release_dir = sys.argv[2]
source = Path('packaging/nfpm.yaml')
target = Path('dist') / f'nfpm.{version}.yaml'
text = source.read_text()
text = re.sub(r'^version:.*$', f'version: {version}', text, flags=re.MULTILINE)
text = text.replace('./target/release/', f'{release_dir}/')
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
