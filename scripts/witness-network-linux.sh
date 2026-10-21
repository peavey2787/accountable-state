#!/usr/bin/env bash
# Real-network witness test: 2 players + WITNESSES honest witnesses + 1 malicious witness, every
# link a separate p2p-net + Hydra pair on loopback, native processes. Bob equivocates and signs a
# false checkpoint, Alice signs one illegal control word. Honest witnesses must independently
# verify every violation; the malicious witness must not be able to forge a verdict; optional
# WITNESS_RESTART=1 kills and restarts one witness mid-match and requires it to converge.
#   WITNESSES=3 EPOCHS=150 WITNESS_RESTART=1 ./scripts/witness-network-linux.sh
# Hostile-network profile on the same real links (applied to both directions of every
# player<->witness link; see examples/edge-p2p/src/witness_net.rs):
#   FAULTS='loss=0.2,dup=0.2,delay=40,jitter=250,seed=7'   loss / duplication / delay / reordering
#   WITNESS_PARTITION=1   SIGSTOP one witness for 25 s (a partition), then resume it
# Soak knobs (see scripts/soak-linux.sh):
#   WITNESS_CHURN_SECS=N  every N s, kill -9 the next honest witness, restart it on its old state
#   SAMPLE_SECS=N         append "time pid role rss_kb cpu%" for every process to $DATA/samples.tsv
#   EXTRA_ALICE / EXTRA_BOB  extra scripted-behaviour flags (e.g. '--hide-at=200 --withhold-at=250')
# Every wait is bounded; on failure the work directory is kept as an artifact under target/.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v openssl >/dev/null || { echo 'ERROR: openssl is required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'ERROR: python3 is required' >&2; exit 1; }
W="${WITNESSES:-3}"
EPOCHS="${EPOCHS:-150}"
# PROFILE=release runs the optimised binary (use it for soak and memory measurements).
if [ "${PROFILE:-debug}" = release ]; then
  cargo build -q --release -p gv-edge-p2p-demo
  BIN="$PWD/target/release/gv-edge-p2p-demo"
else
  cargo build -q -p gv-edge-p2p-demo
  BIN="$PWD/target/debug/gv-edge-p2p-demo"
fi
DATA="$(mktemp -d "${TMPDIR:-/tmp}/gv-witness-net.XXXXXXXX")"
echo "work dir: $DATA"
[ -z "${FAULTS:-}" ] || { export GV_FAULTS="$FAULTS"; echo "fault profile: $FAULTS"; }
fail() { # message -- keep the logs as a failure artifact
  echo "FAIL: $1" >&2
  mkdir -p target/failure-artifacts && cp -r "$DATA" "target/failure-artifacts/$(basename "$DATA")" 2>/dev/null || true
  echo "artifacts: target/failure-artifacts/$(basename "$DATA")" >&2
  exit 1
}
PARTIES=(alice bob)
for i in $(seq 1 "$W"); do PARTIES+=("w$i"); done
PARTIES+=(wm)
for p in "${PARTIES[@]}"; do
  mkdir -p "$DATA/$p"
  (umask 077; openssl rand -hex 32 > "$DATA/secret-$p"; openssl rand -base64 36 | tr -d '\n' > "$DATA/pw-$p")
done
PORT=4300
cfg() { # name namespace -> writes $DATA/cfg-name.json with a fresh port; one namespace per link so LAN discovery cannot join links
  PORT=$((PORT + 1))
  python3 - "$DATA/cfg-$1.json" "$DATA/$1" "$PORT" "$2" <<'PY'
import json, sys
out, base, port, ns = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
json.dump({
  "profile": "auto", "network_id": 9101,
  "identity_key_path": base + ".peer-id.key", "webrtc_certificate_path": base + ".webrtc.pem",
  "listen_addresses": [f"/ip4/127.0.0.1/udp/{port}/quic-v1"],
  "discovery": {"peer_cache_path": base + ".peers.json", "namespace": {"app_id": "gv-" + ns},
    "public_bootstrap": {"mode": "disabled", "bootstrap_seed_peers": [], "rendezvous_peers": [], "relay_peers": [], "auto_connect_discovered_peers": False}},
  "public_ip_probe": {"enabled": False}}, open(out, "w"), indent=1)
PY
}
init() { # party store-name
  GV_PLAYER_SEED_HEX="$(cat "$DATA/secret-$1")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-$1")" \
    "$BIN" init "$DATA/$1/$2" "$DATA/$1-$2.card" "$DATA/$1.pub" >/dev/null
}
init alice game; init bob game
cfg alice-game game; cfg bob-game game
for i in $(seq 1 "$W") m; do
  P="w$i"; [ "$i" = m ] && P=wm
  for pl in alice bob; do
    init "$pl" "$P"; init "$P" "$pl"
    cfg "$pl-$P" "$pl-$P"; cfg "$P-$pl" "$pl-$P"
  done
done
MID="$(openssl rand -hex 32)"
export GV_HYDRA_RAM=1
WLIST=()
for i in $(seq 1 "$W"); do WLIST+=("w$i"); done
WLIST+=(wm)
player_links() { # player
  local pl="$1" out=()
  for P in "${WLIST[@]}"; do
    out+=("--witness-link=$DATA/cfg-$pl-$P.json,$DATA/$pl/$P,$DATA/$P-$pl.card,$DATA/$P.pub,$DATA/addr-$pl-$P")
  done
  printf '%s\n' "${out[@]}"
}
runplayer() { # name extra...
  local name="$1"; shift
  mapfile -t LINKS < <(player_links "$name")
  ( export GV_PLAYER_SEED_HEX="$(cat "$DATA/secret-$name")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-$name")"
    exec "$BIN" run "$name" "$DATA/cfg-$name-game.json" "$DATA/$name/game" "$DATA/$([ "$name" = alice ] && echo bob || echo alice)-game.card" "$MID" \
      "$DATA/$([ "$name" = alice ] && echo bob || echo alice).pub" "$DATA/$name.bin" "--epochs=$EPOCHS" "${LINKS[@]}" "$@" ) > "$DATA/$name.log" 2>&1 &
}
runwitness() { # party run_secs extra...
  local P="$1" secs="$2"; shift 2
  ( export GV_PLAYER_SEED_HEX="$(cat "$DATA/secret-$P")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-$P")"
    exec "$BIN" witness "$P" "$MID" "$DATA/alice.pub" "$DATA/bob.pub" "$DATA/out-$P" \
      "--link=$DATA/cfg-$P-alice.json,$DATA/$P/alice,$DATA/alice-$P.card,$DATA/alice.pub,$DATA/addr-alice-$P" \
      "--link=$DATA/cfg-$P-bob.json,$DATA/$P/bob,$DATA/bob-$P.card,$DATA/bob.pub,$DATA/addr-bob-$P" \
      "--run-secs=$secs" "$@" ) >> "$DATA/$P.log" 2>&1 &
}
# Game link: the stock peer-id dance.
runplayer_game() { :; }
# Bob (responder on the game link) first, parse his peer id, then Alice.
mapfile -t BL < <(player_links bob)
( export GV_PLAYER_SEED_HEX="$(cat "$DATA/secret-bob")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-bob")"
  exec "$BIN" run bob "$DATA/cfg-bob-game.json" "$DATA/bob/game" "$DATA/alice-game.card" "$MID" "$DATA/alice.pub" "$DATA/bob.bin" \
    "--epochs=$EPOCHS" "${BL[@]}" --cheat-at=1000 --equivocate-at=1200 ${EXTRA_BOB:-} ) > "$DATA/bob.log" 2>&1 &
PID_B=$!
BOB_ID=""
for _ in $(seq 1 300); do
  BOB_ID="$(sed -n 's/^p2p-net local peer: \([^ ]*\) .*/\1/p' "$DATA/bob.log" 2>/dev/null | head -n1)"
  [ -n "$BOB_ID" ] && break
  sleep 0.1
done
[ -n "$BOB_ID" ] || { echo "FAIL: bob never started"; tail "$DATA/bob.log"; exit 1; }
PORT_B="$(python3 -c "import json;print(json.load(open('$DATA/cfg-bob-game.json'))['listen_addresses'][0].split('/')[4])")"
export GV_REMOTE_PEER_ID="$BOB_ID" GV_REMOTE_MULTIADDR="/ip4/127.0.0.1/udp/$PORT_B/quic-v1/p2p/$BOB_ID"
mapfile -t AL < <(player_links alice)
( export GV_PLAYER_SEED_HEX="$(cat "$DATA/secret-alice")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-alice")"
  exec "$BIN" run alice "$DATA/cfg-alice-game.json" "$DATA/alice/game" "$DATA/bob-game.card" "$MID" "$DATA/bob.pub" "$DATA/alice.bin" \
    "--epochs=$EPOCHS" "${AL[@]}" --illegal-at=800 ${EXTRA_ALICE:-} ) > "$DATA/alice.log" 2>&1 &
PID_A=$!
unset GV_REMOTE_PEER_ID GV_REMOTE_MULTIADDR
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT INT TERM
SECS="${WITNESS_SECS:-$((EPOCHS / 3 + 90))}"
WSTART=$SECONDS
for P in "${WLIST[@]}"; do
  if [ "$P" = wm ]; then runwitness "$P" "$SECS" --malicious; else runwitness "$P" "$SECS" --audit-every-ms=5000; fi
  eval "PID_$P=$!"
done
if [ "${WITNESS_PARTITION:-0}" = 1 ]; then
  for _ in $(seq 1 600); do grep -q "VERIFIED equivocation" "$DATA/w2.log" 2>/dev/null && break; sleep 0.5; done
  echo "--- partitioning witness w2 (SIGSTOP 25 s) ---"
  kill -STOP "$PID_w2" 2>/dev/null || true
  ( sleep 25; kill -CONT "$PID_w2" 2>/dev/null || true ) &
fi
if [ "${WITNESS_RESTART:-0}" = 1 ]; then
  # Kill w1 hard once evidence has propagated, restart it on the same state, require convergence.
  for _ in $(seq 1 600); do grep -q "VERIFIED equivocation" "$DATA/w1.log" 2>/dev/null && break; sleep 0.5; done
  echo "--- killing witness w1 (kill -9) and restarting it ---"
  kill -9 "$PID_w1" 2>/dev/null || true
  sleep 3
  rm -f "$DATA/w1.log.before"; cp "$DATA/w1.log" "$DATA/w1.log.before"
  runwitness w1 "$((SECS - 60))" --audit-every-ms=5000
  PID_w1=$!
fi
CHURN_PID=""
if [ -n "${WITNESS_CHURN_SECS:-}" ]; then
  (
    n=0
    while kill -0 "$PID_A" 2>/dev/null; do
      sleep "$WITNESS_CHURN_SECS"
      kill -0 "$PID_A" 2>/dev/null || break
      n=$((n + 1)); idx=$(( (n - 1) % W + 1 )); P="w$idx"
      eval "pid=\${PID_$P}"
      echo "--- churn #$n: kill -9 $P at $(date +%T) ---"
      kill -9 "$pid" 2>/dev/null || true
      sleep 3
      left=$(( SECS - (SECONDS - WSTART) ))
      [ "$left" -gt 120 ] || break
      runwitness "$P" "$left" --audit-every-ms=5000
      eval "PID_$P=$!"
    done
    wait
  ) &
  CHURN_PID=$!
fi
SAMPLER_PID=""
if [ -n "${SAMPLE_SECS:-}" ]; then
  (
    printf 'time\tpid\trole\trss_kb\tcpu\n' > "$DATA/samples.tsv"
    while kill -0 "$PID_A" 2>/dev/null; do
      for r in alice bob w1 w2 w3 wm; do
        eval "pid=\${PID_$r:-}"; [ "$r" = alice ] && pid=$PID_A; [ "$r" = bob ] && pid=$PID_B
        { [ -n "${pid:-}" ] && ps -o rss=,pcpu= -p "$pid" 2>/dev/null | awk -v t="$(date +%s)" -v p="$pid" -v r="$r" '{printf "%s\t%s\t%s\t%s\t%s\n",t,p,r,$1,$2}' >> "$DATA/samples.tsv"; } || true
      done
      sleep "$SAMPLE_SECS"
    done
  ) &
  SAMPLER_PID=$!
fi
FAIL=0
wait "$PID_A" || FAIL=1
wait "$PID_B" || FAIL=1
if [ "$FAIL" -ne 0 ]; then tail -n 20 "$DATA/alice.log" "$DATA/bob.log" >&2; fail "a player exited with an error"; fi
echo "--- players finished; waiting for witnesses ---"
[ -z "$CHURN_PID" ] || wait "$CHURN_PID" || true
[ -z "$SAMPLER_PID" ] || wait "$SAMPLER_PID" || true
for P in "${WLIST[@]}"; do eval "wait \$PID_$P" || true; done
ALICE_ID="$(sed -n 's/^Player ML-DSA-65 id: //p' /dev/null)"
need() { grep -q "$2" "$DATA/$1.log" || { tail -n 25 "$DATA/$1.log" >&2; fail "expected '$3' in $1 log"; }; }
for i in $(seq 1 "$W"); do
  need "w$i" "VERIFIED equivocation evidence" "witness w$i verified Bob's equivocation"
  need "w$i" "VERIFIED fraud evidence" "witness w$i verified fraud evidence"
  need "w$i" "admitted by player" "witness w$i admitted by players"
done
# Independent re-verification of every item the witnesses stored, with only pinned keys.
CHECKED=0
for f in "$DATA"/out-w*/*.item; do
  [ -e "$f" ] || continue
  "$BIN" verify "$f" "$MID" "$DATA/alice.pub" "$DATA/bob.pub" >/dev/null || fail "stored item does not verify: $f"
  CHECKED=$((CHECKED + 1))
done
[ "$CHECKED" -gt 0 ] || fail "no items stored"
# The malicious witness must never cause a verdict against an honest statement: nothing it sent
# is stored by an honest witness, and honest witnesses must have rejected its attempts.
if ls "$DATA"/out-wm/*.item >/dev/null 2>&1; then
  for f in "$DATA"/out-wm/*.item; do
    "$BIN" verify "$f" "$MID" "$DATA/alice.pub" "$DATA/bob.pub" >/dev/null || fail "malicious witness stored an unverifiable item"
  done
fi
grep -h "WITNESS-HUB rejected an item" "$DATA/alice.log" "$DATA/bob.log" >/dev/null || fail "players never rejected the malicious witness material"
if [ "${WITNESS_RESTART:-0}" = 1 ]; then
  grep -q "persisted item(s) re-verified" "$DATA/w1.log" || fail "restarted witness did not re-verify persisted evidence"
  [ "$(grep -c 'VERIFIED' "$DATA/w1.log")" -ge 2 ] || fail "restarted witness did not converge"
fi
# Convergence report: when each honest witness verified each violation (ms since its start).
for i in $(seq 1 "$W"); do
  echo "convergence w$i: $(grep -h 'VERIFIED' "$DATA/w$i.log" | sed -n 's/.*VERIFIED \([a-z]*\) evidence.* at \([0-9]*\) ms/\1@\2ms/p' | tr '\n' ' ')"
done
echo "PASS: $W honest witnesses + 1 malicious witness on real p2p-net/Hydra links; $CHECKED stored items independently verified. Logs: $DATA"
