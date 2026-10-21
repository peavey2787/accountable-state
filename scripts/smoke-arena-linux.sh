#!/usr/bin/env bash
# Fail-closed REAL native two-process smoke test. No mocked peer links.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo 'ERROR: Rust Cargo is required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'ERROR: Python 3 is required' >&2; exit 1; }
# Avoid clobbering a running interactive arena or its identities/credentials.
DIR="$(mktemp -d "${TMPDIR:-/tmp}/gv-arena-smoke.XXXXXXXX")"
LAUNCH_LOG="$DIR/launcher.log"
export GV_DEMO_DIR="$DIR/data" GV_ARENA_DISABLE_BROWSER=1
./scripts/play-arena-linux.sh > "$LAUNCH_LOG" 2>&1 &
LAUNCH_PID=$!
cleanup() {
  kill "$LAUNCH_PID" 2>/dev/null || true
  wait "$LAUNCH_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
set +e
python3 - "$LAUNCH_PID" <<'PY'
import json, os, sys, time, urllib.request
pid = int(sys.argv[1]); t0 = time.monotonic()
PORTS = {"alice": 9001, "bob": 9002}
def now(): return time.monotonic() - t0
def get(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/state", timeout=2) as r:
        return json.load(r)
def post(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="POST", headers={"Origin": f"http://127.0.0.1:{port}"})
    urllib.request.urlopen(req, timeout=2).read()
def states():
    out = {}
    for k, p in PORTS.items():
        try: out[k] = get(p)
        except Exception: return None
    return out
def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr); sys.exit(1)
def alive():
    try: os.kill(pid, 0)
    except ProcessLookupError: fail("launcher terminated early")
def wait(cond, what, limit):
    start = now()
    while now() - start < limit:
        alive()
        st = states()
        if st:
            if any(s.get("verdict") == "error" for s in st.values()):
                fail(f"match interrupted while waiting for {what}: {[(k, s.get('phase')) for k, s in st.items()]}")
            if cond(st): return st
        time.sleep(0.1)
    fail(f"timed out after {limit}s waiting for {what}; last: {[(k, s.get('tick'), s.get('accepted'), s.get('phase')) for k, s in (states() or {}).items()]}")

# 1. Cold start: two processes find each other, handshake, and start the 60 Hz sim.
st = wait(lambda s: all(v["tick"] >= 60 for v in s.values()), "both peers live", 100)
live_at = now()
rates = [v["tickHz"] for v in st.values() if v["tickHz"]]
if not rates or min(rates) < 50: fail(f"simulation is not running at 60 Hz: {rates}")
# 2. Real input through the same HTTP endpoint as the browser; both certify it.
you = {k: v["you"] for k, v in st.items()}
toward = {0: 2, 1: 1}
for k, p in PORTS.items(): post(p, f"/controls?controls={toward[you[k]]}")
time.sleep(0.4)
for p in PORTS.values(): post(p, "/controls?controls=0")
def settled(s):
    a, b = s["alice"], s["bob"]
    return a["accepted"] >= 1 and a["verifiedTick"] == b["verifiedTick"] and a["pendingTicks"] is None and b["pendingTicks"] is None
st = wait(settled, "both peers to certify the same epoch", 30)
a, b = st["alice"], st["bob"]
if a["checkpoint"] != b["checkpoint"]: fail("peers certified DIFFERENT checkpoints at the same tick")
cert_at = now()
# 3. Commit-lock-reveal: one player hides for 5 s, then opens; both replay it.
post(PORTS["alice"], "/hide")
wait(lambda s: s["bob"]["hide"] is not None and s["alice"]["hide"] is not None, "hide to be agreed", 10)
end = get(PORTS["alice"])["hide"]["end"]
st = wait(lambda s: s["alice"]["hide"] is None and s["bob"]["hide"] is None and s["alice"]["verifiedTick"] >= end and s["bob"]["verifiedTick"] >= end, "reveal and certification of the hidden window", 40)
hide_at = now()
for p in PORTS.values(): post(p, "/controls?controls=0")
st = wait(lambda s: s["alice"]["verifiedTick"] == s["bob"]["verifiedTick"] and s["alice"]["pendingTicks"] is None and s["bob"]["pendingTicks"] is None, "final agreement", 20)
a, b = st["alice"], st["bob"]
if a["checkpoint"] != b["checkpoint"]: fail("peers disagree after the hidden window")
if a["rejected"] or b["rejected"]: fail(f"unexpected violations: {a['rejected']}, {b['rejected']}")
fa = [a["finalityMs"], b["finalityMs"]]
print(f"TIMING cold-start->live={live_at:.1f}s live->first-certified={cert_at-live_at:.1f}s hide-cycle={hide_at-cert_at:.1f}s")
print(f"PASS: real encrypted P2P match at {min(rates):.0f} Hz: both peers certified identical checkpoint at tick {a['verifiedTick']}; commit-reveal hide cycle verified; no violations; finality {fa[0]}/{fa[1]} ms")
sys.exit(0)
PY
RESULT=$?
set -e
if [ "$RESULT" -ne 0 ]; then
  echo '====== launcher ======' >&2
  tail -n 70 "$LAUNCH_LOG" >&2 || true
  for f in alice bob; do
    echo "====== $f ======" >&2
    tail -n 100 "$DIR/data/$f.log" >&2 || true
  done
  echo "Full logs: $DIR" >&2
  exit "$RESULT"
fi
echo "Smoke test successful. Temporary logs: $DIR"
