#!/usr/bin/env python3
"""Benchmark driver for the real-time arena. Run through bench-realtime-linux.sh,
which launches the two peers. Everything is measured through the same HTTP
endpoints a browser uses, so the numbers include the whole local pipeline.

Reports: tick rate and jitter, input-to-screen latency, finality latency (from
the moment a tick was played to the moment both players' signatures agreed),
bandwidth, CPU, rollbacks and the hide (commit-reveal) catch-up."""
import json, os, random, statistics, subprocess, sys, time, urllib.request

A, B = 9001, 9002
OUT = sys.argv[1] if len(sys.argv) > 1 else None
DURATION = float(os.environ.get("BENCH_SECONDS", "20"))

def get(p):
    with urllib.request.urlopen(f"http://127.0.0.1:{p}/state", timeout=3) as r:
        return json.load(r)
def post(p, path):
    req = urllib.request.Request(f"http://127.0.0.1:{p}{path}", method="POST", headers={"Origin": f"http://127.0.0.1:{p}"})
    urllib.request.urlopen(req, timeout=3).read()
def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))] if xs else None
def summary(xs, unit=""):
    if not xs: return "n/a"
    return f"n={len(xs)} p50={pct(xs,.5):.1f} p95={pct(xs,.95):.1f} max={max(xs):.1f}{unit}"
def pids():
    out = subprocess.run("pgrep -f '[g]v-edge-p2p-demo run'", shell=True, capture_output=True, text=True).stdout.split()
    return [int(p) for p in out]
def cpu_ticks(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return int(f[11]) + int(f[12])
    except Exception:
        return 0
HZ = os.sysconf("SC_CLK_TCK")

t0 = time.time()
while True:
    try:
        if get(A)["tick"] > 90 and get(B)["tick"] > 90: break
    except Exception: pass
    if time.time() - t0 > 90: print("bench: peers never came up", file=sys.stderr); sys.exit(1)
    time.sleep(0.3)
you = {p: get(p)["you"] for p in (A, B)}
epoch_ticks = int(os.environ.get("GV_ARENA_EPOCH_TICKS", "20"))
res = {"epoch_ticks": epoch_ticks, "epoch_ms": round(epoch_ticks * 1000 / 60)}

# ---- 1. idle: nothing may be sent or certified -------------------------------
a0 = get(A)["accepted"]; time.sleep(3)
s = get(A)
res["idle_epochs_in_3s"] = s["accepted"] - a0
res["idle_kbps"] = (s["txKbps"], s["rxKbps"])

# ---- 2. input -> screen latency (browser path: POST, next tick, next poll) ---
def pos(s, i): f = s["fighters"][i]; return (f["x"], f["y"])
lat = []
me = you[A]
for n in range(60):
    before = pos(get(A), me)
    # alternate vertical directions so every tap really moves (never blocked)
    d = 4 if n % 2 == 0 else 8
    if before[1] <= -7: d = 8
    if before[1] >= 7: d = 4
    t = time.time(); post(A, f"/controls?controls={d}")
    moved = None
    while time.time() - t < 0.4:
        if pos(get(A), me) != before: moved = (time.time() - t) * 1000; break
        time.sleep(0.001)
    post(A, "/controls?controls=0")
    if moved is not None: lat.append(moved)
    time.sleep(0.22)
res["input_to_screen_ms"] = {"n": len(lat), "p50": pct(lat, .5), "p95": pct(lat, .95), "max": max(lat) if lat else None}

# ---- 3. sustained play: both players moving and fighting ---------------------
cpu0 = {p: cpu_ticks(p) for p in pids()}; w0 = time.time()
fin, fin_seen, hz, jit, tx, rx, stall, send = [], set(), [], [], [], [], [], []
rnd = random.Random(1)
end = time.time() + DURATION
next_input = {A: 0, B: 0}
masks = [1, 2, 4, 8, 16, 32, 2 | 16, 4 | 16, 1 | 32]
while time.time() < end:
    now = time.time()
    for p in (A, B):
        if now >= next_input[p]:
            post(p, f"/controls?controls={rnd.choice(masks)}")
            next_input[p] = now + rnd.uniform(0.08, 0.45)
    for p in (A, B):
        s = get(p)
        key = (p, s["verifiedTick"])
        if s["finalityMs"] is not None and key not in fin_seen and s["pendingTicks"] is not None:
            fin_seen.add(key); fin.append(s["finalityMs"])
        if s["tickHz"]: hz.append(s["tickHz"])
        if s["jitterMs"] is not None: jit.append(s["jitterMs"])
        if s["txKbps"] is not None: tx.append(s["txKbps"]); rx.append(s["rxKbps"])
        if s["inboxStallUs"] is not None: stall.append(s["inboxStallUs"] / 1000)
        if s["sendAvgUs"] is not None: send.append(s["sendAvgUs"] / 1000)
    time.sleep(0.04)
for p in (A, B): post(p, "/controls?controls=0")
time.sleep(2.0)
cpu1 = {p: cpu_ticks(p) for p in pids()}; wall = time.time() - w0
sa, sb = get(A), get(B)
res["sustained"] = {
    "seconds": round(wall, 1),
    "tick_hz": {"min": min(hz), "median": statistics.median(hz), "max": max(hz)} if hz else None,
    "tick_jitter_ms": {"median": statistics.median(jit), "max": max(jit)} if jit else None,
    "finality_ms": {"n": len(fin), "p50": pct(fin, .5), "p95": pct(fin, .95), "max": max(fin) if fin else None},
    "tx_kbps": {"median": statistics.median(tx), "max": max(tx)} if tx else None,
    "rx_kbps": {"median": statistics.median(rx), "max": max(rx)} if rx else None,
    "session_send_ms_avg": statistics.median(send) if send else None,
    "inbox_stall_ms_max": max(stall) if stall else None,
    "cpu_percent_per_process": {str(p): round(100 * (cpu1.get(p, 0) - cpu0.get(p, 0)) / HZ / wall, 1) for p in cpu0},
    "certified_epochs": sa["accepted"], "disputed": sa["disputed"], "violations": (sa["rejected"], sb["rejected"]),
    "rollbacks": (sa["rollbacks"], sb["rollbacks"]), "max_rollback_ticks": (sa["maxRollback"], sb["maxRollback"]),
    "messages_lost_to_fanout_lag": (sa["lagged"], sb["lagged"]),
    "hydra_worst_send_ms": (sa["hydraSendMaxUs"]/1000, sb["hydraSendMaxUs"]/1000), "hydra_worst_recv_ms": (sa["hydraRecvMaxUs"]/1000, sb["hydraRecvMaxUs"]/1000),
    "hydra_slow_calls": (sa["hydraSlowCalls"], sb["hydraSlowCalls"]),
    "retransmits": (sa["retransmits"], sb["retransmits"]), "bad_frames": (sa["badFrames"], sb["badFrames"]),
    "send_errors": (sa["sendErrors"], sb["sendErrors"]), "stream_suppressed": (sa["suppressed"], sb["suppressed"]),
}
res["agree_after_play"] = (sa["verifiedTick"] == sb["verifiedTick"] and sa["checkpoint"] == sb["checkpoint"]
                           and [f["x"] for f in sa["fighters"]] == [f["x"] for f in sb["fighters"]])

# ---- 4. hide: commit-lock-reveal catch-up ------------------------------------
t_req = time.time(); post(A, "/hide")
while get(A)["hide"] is None and time.time() - t_req < 5: time.sleep(0.02)
h = get(A)["hide"]
t_start = time.time()
while get(A)["tick"] < h["end"]: time.sleep(0.02)
t_end = time.time()
while time.time() - t_end < 30:
    sa, sb = get(A), get(B)
    if sa["hide"] is None and sb["hide"] is None and sa["verifiedTick"] >= h["end"] and sb["verifiedTick"] >= h["end"]: break
    time.sleep(0.02)
t_done = time.time()
res["hide"] = {"window_s": round((h["end"] - h["start"]) / 60, 2), "catch_up_after_window_ms": round((t_done - t_end) * 1000),
               "violations": (sa["rejected"], sb["rejected"])}
time.sleep(1.0)
sa, sb = get(A), get(B)
res["agree_after_hide"] = (sa["verifiedTick"] == sb["verifiedTick"] and sa["checkpoint"] == sb["checkpoint"])

# ---- report ------------------------------------------------------------------
sus = res["sustained"]
print(f"=== real-time arena benchmark · epoch {epoch_ticks} ticks ({res['epoch_ms']} ms) ===")
print(f"idle:            {res['idle_epochs_in_3s']} epochs in 3 s, tx/rx {res['idle_kbps'][0]}/{res['idle_kbps'][1]} kbps")
print(f"input->screen:   {summary(lat, ' ms')}  (HTTP post + next 60 Hz tick + poll)")
print(f"tick rate:       median {sus['tick_hz']['median']:.1f} Hz (min {sus['tick_hz']['min']:.1f}, max {sus['tick_hz']['max']:.1f}), jitter median {sus['tick_jitter_ms']['median']:.2f} ms max {sus['tick_jitter_ms']['max']:.2f} ms")
print(f"finality:        {summary(fin, ' ms')}  (tick played -> both signatures agree); over 100 ms: {sum(1 for f in fin if f > 100)}")
print(f"bandwidth:       tx median {sus['tx_kbps']['median']:.1f} / max {sus['tx_kbps']['max']:.1f} kbps, rx median {sus['rx_kbps']['median']:.1f} / max {sus['rx_kbps']['max']:.1f} kbps (payload)")
print(f"cpu:             {sus['cpu_percent_per_process']} % of one core")
print(f"session:         avg encrypted send {sus['session_send_ms_avg']} ms, worst inbox stall {sus['inbox_stall_ms_max']} ms, fan-out lag drops {sus['messages_lost_to_fanout_lag']}")
print(f"hydra:           worst send {sus['hydra_worst_send_ms']} ms, worst receive {sus['hydra_worst_recv_ms']} ms, calls over 100 ms {sus['hydra_slow_calls']}")
print(f"transport:       retransmits {sus['retransmits']}, bad frames {sus['bad_frames']}, send errors {sus['send_errors']}, silenced stream frames {sus['stream_suppressed']}")
print(f"rollbacks:       {sus['rollbacks']} (max depth {sus['max_rollback_ticks']} ticks) · certified epochs {sus['certified_epochs']} · violations {sus['violations']}")
print(f"agreement:       after play {res['agree_after_play']}, after hide {res['agree_after_hide']}")
print(f"hide:            {res['hide']['window_s']} s window, all hidden epochs certified {res['hide']['catch_up_after_window_ms']} ms after it closed, violations {res['hide']['violations']}")
if OUT:
    with open(OUT, "w") as f: json.dump(res, f, indent=2)
ok = res["agree_after_play"] and res["agree_after_hide"] and sus["violations"] == (0, 0) and res["hide"]["violations"] == (0, 0)
sys.exit(0 if ok else 1)
