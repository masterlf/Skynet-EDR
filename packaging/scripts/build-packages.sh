#!/usr/bin/env sh
set -eu

PRODUCT_VERSION="${SKYNET_EDR_PRODUCT_VERSION:-$(cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"] == "skynet-edr-cli"))')}"
DEB_VERSION="${SKYNET_EDR_DEB_VERSION:-0.6.0~alpha.3}"
DEB_ARCH="${NFPM_ARCH:-amd64}"
RPM_ARCH="${NFPM_RPM_ARCH:-x86_64}"
ARCHLINUX_ARCH="${NFPM_ARCHLINUX_ARCH:-x86_64}"
NFPM_PRODUCT_RENDERED="dist/nfpm.${PRODUCT_VERSION}.yaml"
NFPM_DEB_RENDERED="dist/nfpm.${PRODUCT_VERSION}.deb.yaml"
NFPM_ARCH_RENDERED="dist/nfpm.${PRODUCT_VERSION}.archlinux.yaml"
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
python3 packaging/scripts/create-hermes-plugin-manifest.py \
  "$STAGED_HERMES_PLUGIN" "dist/staging/nfpm/hermes-plugin/manifest.json"

python3 - "$PRODUCT_VERSION" "$DEB_VERSION" "$CARGO_RELEASE_DIR" <<'PY'
import re
import sys
from pathlib import Path
product_version, deb_version, release_dir = sys.argv[1:]
source = Path('packaging/nfpm.yaml')
product_target = Path('dist') / f'nfpm.{product_version}.yaml'
deb_target = Path('dist') / f'nfpm.{product_version}.deb.yaml'
arch_target = Path('dist') / f'nfpm.{product_version}.archlinux.yaml'
text = source.read_text(encoding='utf-8').replace('./target/release/', f'{release_dir}/')
product_text = re.sub(r'^version:.*$', f'version: {product_version}', text, flags=re.MULTILINE)
deb_text = re.sub(r'^version:.*$', f'version: {deb_version}\nversion_schema: none', text, flags=re.MULTILINE)
arch_version = product_version.replace('-', '.')
arch_text = re.sub(r'^version:.*$', f'version: {arch_version}\nversion_schema: none', text, flags=re.MULTILINE)
product_target.write_text(product_text, encoding='utf-8')
deb_target.write_text(deb_text, encoding='utf-8')
arch_target.write_text(arch_text, encoding='utf-8')
PY

NFPM_ARCH="$DEB_ARCH" nfpm package \
  --config "$NFPM_DEB_RENDERED" \
  --packager deb \
  --target "dist/skynet-edr_${PRODUCT_VERSION}_${DEB_ARCH}.deb"

NFPM_ARCH="$RPM_ARCH" nfpm package \
  --config "$NFPM_PRODUCT_RENDERED" \
  --packager rpm \
  --target "dist/skynet-edr-${PRODUCT_VERSION}-1.${RPM_ARCH}.rpm"

NFPM_ARCH="$ARCHLINUX_ARCH" nfpm package \
  --config "$NFPM_ARCH_RENDERED" \
  --packager archlinux \
  --target "dist/skynet-edr-${PRODUCT_VERSION}-1-${ARCHLINUX_ARCH}.pkg.tar.zst"
