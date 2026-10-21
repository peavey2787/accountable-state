#!/usr/bin/env bash
# Real-time arena benchmark: launches two native peers and measures them.
#   ./scripts/bench-realtime-linux.sh            # default epoch (20 ticks = 333 ms)
#   GV_ARENA_EPOCH_TICKS=10 ./scripts/bench-realtime-linux.sh
#   BENCH_SECONDS=60 ./scripts/bench-realtime-linux.sh results.json
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo 'ERROR: Rust Cargo is required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'ERROR: Python 3 is required' >&2; exit 1; }
DIR="$(mktemp -d "${TMPDIR:-/tmp}/gv-arena-bench.XXXXXXXX")"
export GV_DEMO_DIR="$DIR/data" GV_ARENA_DISABLE_BROWSER=1
./scripts/play-arena-linux.sh > "$DIR/launcher.log" 2>&1 &
LAUNCH_PID=$!
cleanup() {
  kill "$LAUNCH_PID" 2>/dev/null || true
  wait "$LAUNCH_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
set +e
python3 scripts/bench-realtime.py "${1:-}"
RESULT=$?
set -e
if [ "$RESULT" -ne 0 ]; then
  echo "bench failed; logs: $DIR" >&2
  tail -n 20 "$DIR/data/alice.log" >&2 || true
fi
exit "$RESULT"
