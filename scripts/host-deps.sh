#!/bin/sh
# Build libubox and libuci for the host into third_party/host-prefix.
# libmnl and libnftnl come from the system (e.g. libmnl-dev, libnftnl-dev).
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${OMNI_PREFIX:-$ROOT/third_party/host-prefix}
SRC=$ROOT/third_party
mkdir -p "$SRC"
for repo in libubox uci; do
	[ -d "$SRC/$repo" ] || git clone --depth 1 "https://git.openwrt.org/project/$repo.git" "$SRC/$repo"
done
cmake -S "$SRC/libubox" -B "$SRC/build-libubox" -DCMAKE_INSTALL_PREFIX="$PREFIX" \
	-DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF
cmake --build "$SRC/build-libubox" --target install
cmake -S "$SRC/uci" -B "$SRC/build-uci" -DCMAKE_INSTALL_PREFIX="$PREFIX" \
	-DCMAKE_PREFIX_PATH="$PREFIX" -DBUILD_LUA=OFF -DBUILD_STATIC=OFF
cmake --build "$SRC/build-uci" --target install
