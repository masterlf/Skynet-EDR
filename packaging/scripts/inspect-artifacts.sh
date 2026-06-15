#!/usr/bin/env sh
set -eu

DIST_DIR="${1:-dist}"

require_one() {
  pattern="$1"
  matches=$(find "$DIST_DIR" -maxdepth 1 -type f -name "$pattern" | sort)
  count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
  if [ "$count" -ne 1 ]; then
    echo "expected exactly one artifact matching $pattern in $DIST_DIR, found $count" >&2
    printf '%s\n' "$matches" >&2
    exit 1
  fi
  printf '%s\n' "$matches"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required inspection command not found: $1" >&2
    exit 1
  fi
}

grep_listing() {
  listing="$1"
  expected="$2"
  if ! grep -q "$expected" "$listing"; then
    echo "artifact listing $listing missing expected path: $expected" >&2
    exit 1
  fi
}

tarball=$(require_one 'skynet-edr-*.tar.gz')
deb=$(require_one 'skynet-edr_*.deb')
rpm=$(require_one 'skynet-edr-*.rpm')
arch=$(require_one 'skynet-edr-*.pkg.tar.zst')

mkdir -p "$DIST_DIR/inspection"

require_cmd tar
tar -tzf "$tarball" > "$DIST_DIR/inspection/tarball.txt"
grep_listing "$DIST_DIR/inspection/tarball.txt" '/bin/skynet-edr$'
grep_listing "$DIST_DIR/inspection/tarball.txt" '/bin/skynet-edr-daemon$'
grep_listing "$DIST_DIR/inspection/tarball.txt" '/SHA256SUMS$'

require_cmd dpkg-deb
dpkg-deb --contents "$deb" > "$DIST_DIR/inspection/deb.txt"
grep_listing "$DIST_DIR/inspection/deb.txt" './usr/bin/skynet-edr$'
grep_listing "$DIST_DIR/inspection/deb.txt" './usr/bin/skynet-edr-daemon$'
grep_listing "$DIST_DIR/inspection/deb.txt" './etc/skynet-edr/config.toml$'
grep_listing "$DIST_DIR/inspection/deb.txt" './usr/lib/systemd/system/skynet-edr.service$'

require_cmd rpm
rpm -qpl "$rpm" > "$DIST_DIR/inspection/rpm.txt"
grep_listing "$DIST_DIR/inspection/rpm.txt" '^/usr/bin/skynet-edr$'
grep_listing "$DIST_DIR/inspection/rpm.txt" '^/usr/bin/skynet-edr-daemon$'
grep_listing "$DIST_DIR/inspection/rpm.txt" '^/etc/skynet-edr/config.toml$'
grep_listing "$DIST_DIR/inspection/rpm.txt" '^/usr/lib/systemd/system/skynet-edr.service$'

require_cmd zstd
tar --zstd -tf "$arch" > "$DIST_DIR/inspection/archlinux.txt"
grep_listing "$DIST_DIR/inspection/archlinux.txt" '^usr/bin/skynet-edr$'
grep_listing "$DIST_DIR/inspection/archlinux.txt" '^usr/bin/skynet-edr-daemon$'
grep_listing "$DIST_DIR/inspection/archlinux.txt" '^etc/skynet-edr/config.toml$'
grep_listing "$DIST_DIR/inspection/archlinux.txt" '^usr/lib/systemd/system/skynet-edr.service$'

sha256sum "$tarball" "$deb" "$rpm" "$arch" > "$DIST_DIR/checksums.txt"

echo "artifact inspection passed"
