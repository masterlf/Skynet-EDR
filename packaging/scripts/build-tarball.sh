#!/usr/bin/env sh
set -eu

mkdir -p dist
cargo build --release --workspace --bins

VERSION="${SKYNET_EDR_VERSION:-$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"] == "skynet-edr-cli"))')}"
TARGET="${SKYNET_EDR_TARGET:-$(rustc -vV | awk '/host:/ {print $2}')}"
NAME="skynet-edr-${VERSION}-${TARGET}"
ROOT="dist/${NAME}"

rm -rf "$ROOT"
install -d "$ROOT/bin" "$ROOT/packaging/config" "$ROOT/packaging/systemd" "$ROOT/packaging/sysusers" "$ROOT/packaging/tmpfiles" "$ROOT/packaging/tarball" "$ROOT/docs"
install -m 0755 target/release/skynet-edr "$ROOT/bin/skynet-edr"
install -m 0755 target/release/skynet-edr-daemon "$ROOT/bin/skynet-edr-daemon"
install -m 0644 packaging/config/config.toml "$ROOT/packaging/config/config.toml"
install -m 0644 packaging/systemd/skynet-edr.service "$ROOT/packaging/systemd/skynet-edr.service"
install -m 0644 packaging/sysusers/skynet-edr.conf "$ROOT/packaging/sysusers/skynet-edr.conf"
install -m 0644 packaging/tmpfiles/skynet-edr.conf "$ROOT/packaging/tmpfiles/skynet-edr.conf"
install -m 0755 packaging/tarball/install.sh "$ROOT/install.sh"
install -m 0755 packaging/tarball/uninstall.sh "$ROOT/uninstall.sh"
install -m 0755 packaging/tarball/install.sh "$ROOT/packaging/tarball/install.sh"
install -m 0755 packaging/tarball/uninstall.sh "$ROOT/packaging/tarball/uninstall.sh"
install -m 0644 README.md "$ROOT/README.md"
install -m 0644 docs/INSTALL.md "$ROOT/docs/INSTALL.md"
install -m 0644 docs/PACKAGING.md "$ROOT/docs/PACKAGING.md"
install -m 0644 docs/INSTALL.md "$ROOT/README.install.md"
install -m 0644 LICENSE "$ROOT/LICENSE"

(
  cd "$ROOT"
  sha256sum bin/skynet-edr bin/skynet-edr-daemon install.sh uninstall.sh > SHA256SUMS
)

tar -C dist -czf "dist/${NAME}.tar.gz" "$NAME"
echo "built dist/${NAME}.tar.gz"
