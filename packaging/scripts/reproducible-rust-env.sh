#!/usr/bin/env sh
# Source this file from release builders before invoking Cargo.

repo_root=$(pwd -P)
cargo_home=${CARGO_HOME:-${HOME:?HOME is required}/.cargo}
if [ -d "$cargo_home" ]; then
  cargo_home=$(CDPATH= cd -- "$cargo_home" && pwd -P)
fi

remap_flags="--remap-path-prefix=$repo_root=/usr/src/skynet-edr --remap-path-prefix=$cargo_home=/usr/local/cargo"
case " ${RUSTFLAGS:-} " in
  *" --remap-path-prefix=$repo_root=/usr/src/skynet-edr "*) ;;
  *) RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }$remap_flags" ;;
esac
export RUSTFLAGS
unset repo_root cargo_home remap_flags