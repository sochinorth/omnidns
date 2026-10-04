#!/bin/sh
# Host build with ASan/UBSan and unit tests (build dir: build/host).
#   scripts/host-deps.sh first, then: scripts/host-build.sh [extra cmake args]
# OMNI_PREFIX overrides the libubox/libuci prefix; OMNI_SDKBIN may point at an
# OpenWrt SDK's staging_dir/host/bin when cmake/ninja are not installed.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${OMNI_PREFIX:-$ROOT/third_party/host-prefix}
[ -n "$OMNI_SDKBIN" ] && PATH=$PATH:$OMNI_SDKBIN
cmake -S "$ROOT" -B "$ROOT/build/host" -G Ninja \
	-DCMAKE_BUILD_TYPE=Debug -DHOST_TESTS=ON -DSANITIZE=ON \
	-DCMAKE_PREFIX_PATH="$PREFIX" "$@" >/dev/null
ninja -C "$ROOT/build/host"
export LD_LIBRARY_PATH=$PREFIX/lib
ctest --test-dir "$ROOT/build/host" --output-on-failure ${CTEST_ARGS:-}
