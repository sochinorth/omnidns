#!/bin/sh
# The full pre-merge gate; run it from any checkout, the same way every time:
#
#   scripts/gate.sh [--quick]
#
#   1. clean sanitized build (build/host) + ctest, in a private netns
#      (scripts/host-build.sh)
#   2. tests/integ/test_integ.py against build/host/omnidns
#   3. clean unsanitized Release build (build/rel)
#   4. tests/integ/test_mem.py and test_perf.py against build/rel/omnidns
#
# --quick skips step 4 (the slow part). Stops at the first failing step and
# exits non-zero. Prints the compiler warning count of both builds; full logs
# are kept in build/gate-*.log. OMNI_PREFIX and OMNI_SDKBIN are honoured as in
# scripts/host-build.sh.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${OMNI_PREFIX:-$ROOT/third_party/host-prefix}
[ -n "${OMNI_SDKBIN:-}" ] && PATH=$PATH:$OMNI_SDKBIN
QUICK=0
for a in "$@"; do
	case $a in
	--quick) QUICK=1 ;;
	*) echo "usage: $0 [--quick]" >&2; exit 2 ;;
	esac
done

LOG=$ROOT/build/gate
mkdir -p "$ROOT/build"
START=$(date +%s)
SUMMARY=""

note() { SUMMARY="$SUMMARY$1
"; }

# step NAME LOGFILE CMD...: run CMD with its output shown and logged; on
# failure print the summary so far and exit
step() {
	name=$1 log=$2
	shift 2
	echo "==== $name"
	t0=$(date +%s)
	set +e
	{ "$@"; echo $? >"$log.rc"; } 2>&1 | tee "$log"
	rc=$(cat "$log.rc")
	set -e
	rm -f "$log.rc"
	if [ "$rc" -ne 0 ]; then
		note "FAIL  $name (exit $rc, log: ${log#$ROOT/})"
		printf '\n==== gate summary\n%s' "$SUMMARY"
		exit 1
	fi
	note "ok    $name ($(( $(date +%s) - t0 ))s)"
}

warnings() {	# compiler/linker diagnostics in a build log
	grep -Ec '(^|: )warning: ' "$1" || true
}

rm -rf "$ROOT/build/host"
# in a private netns with only lo: the unit tests' loopback traffic must not
# depend on the host's (WSL2's is flaky); nftables tests nest their own
step "sanitized build + ctest" "$LOG-host.log" \
	unshare -rn sh -c 'ip link set lo up && exec "$1"' sh "$ROOT/scripts/host-build.sh"
WHOST=$(warnings "$LOG-host.log")
note "      sanitized build: $WHOST compiler warning(s)"

step "test_integ (sanitized)" "$LOG-integ.log" \
	python3 "$ROOT/tests/integ/test_integ.py" "$ROOT/build/host/omnidns"

rel_build() {
	cmake -S "$ROOT" -B "$ROOT/build/rel" -G Ninja -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_PREFIX_PATH="$PREFIX" >/dev/null &&
	ninja -C "$ROOT/build/rel"
}
rm -rf "$ROOT/build/rel"
step "Release build" "$LOG-rel.log" rel_build
WREL=$(warnings "$LOG-rel.log")
note "      Release build: $WREL compiler warning(s)"

if [ "$QUICK" = 1 ]; then
	note "skip  test_mem, test_perf (--quick)"
else
	step "test_mem (Release)" "$LOG-mem.log" \
		python3 "$ROOT/tests/integ/test_mem.py" "$ROOT/build/rel/omnidns"
	step "test_perf (Release)" "$LOG-perf.log" \
		python3 "$ROOT/tests/integ/test_perf.py" "$ROOT/build/rel/omnidns"
fi

printf '\n==== gate summary\n%s' "$SUMMARY"
echo "compiler warnings: sanitized $WHOST, Release $WREL"
echo "gate passed in $(( $(date +%s) - START ))s"
