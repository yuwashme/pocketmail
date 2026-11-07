#!/bin/sh
# Run from the repository root. Keep the product build and its caches isolated.
set -eu
export CARGO_TARGET_DIR="$PWD/packaging/build/cargo"
export ZIG_GLOBAL_CACHE_DIR="$CARGO_TARGET_DIR/zig" CARGO_ZIGBUILD_CACHE_DIR="$CARGO_TARGET_DIR/zigbuild"
sep=$(printf '\037')
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$PWD=/src${sep}--remap-path-prefix=$HOME=/build"
export CFLAGS_aarch64_unknown_linux_musl="-ffile-prefix-map=$HOME=/build"
cargo zigbuild --locked --offline --release --target aarch64-unknown-linux-musl
python3 packaging/build.py --arch rtd1296 "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/synology-mail-server"
