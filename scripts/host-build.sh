#!/bin/sh
# Host build + unit tests with sanitizers.
#   scripts/host-build.sh [extra cmake args]   (build dir: build/host)
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SDKBIN=${OMNI_SDKBIN:-/home/sochinorth/omnidns/openwrt-sdk/staging_dir/host/bin}
command -v cmake >/dev/null 2>&1 || PATH=$PATH:$SDKBIN
PREFIX=${OMNI_PREFIX:-/home/sochinorth/omnidns/third_party/host-prefix}
cmake -S "$ROOT" -B "$ROOT/build/host" -G Ninja \
	-DCMAKE_BUILD_TYPE=Debug -DHOST_TESTS=ON -DSANITIZE=ON \
	-DCMAKE_PREFIX_PATH="$PREFIX" "$@" >/dev/null
ninja -C "$ROOT/build/host"
export LD_LIBRARY_PATH=$PREFIX/lib
# the SDK ctest wrapper LD_PRELOADs runas.so, which leaks into the tests
export ASAN_OPTIONS=${ASAN_OPTIONS:+$ASAN_OPTIONS:}verify_asan_link_order=0
ctest --test-dir "$ROOT/build/host" --output-on-failure ${CTEST_ARGS:-}
