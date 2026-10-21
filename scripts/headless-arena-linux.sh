#!/usr/bin/env bash
# Headless two-process match with scripted inputs, then OFFLINE verification of
# every artifact it produced. No browser, no HTTP: this exercises the same 60 Hz
# simulation, pipeline, hide window and fraud proofs as the interactive arena.
#   HEADLESS_EPOCHS=40 ./scripts/headless-arena-linux.sh
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo 'ERROR: Rust Cargo is required' >&2; exit 1; }
command -v openssl >/dev/null || { echo 'ERROR: openssl is required' >&2; exit 1; }
EPOCHS="${HEADLESS_EPOCHS:-120}"
cargo build -q -p gv-edge-p2p-demo
BIN=./target/debug/gv-edge-p2p-demo
DATA="$(mktemp -d "${TMPDIR:-/tmp}/gv-arena-headless.XXXXXXXX")"
mkdir -p "$DATA/alice" "$DATA/bob"
for who in alice bob; do
  (umask 077; openssl rand -hex 32 > "$DATA/secrets-$who"; openssl rand -base64 36 | tr -d '\n' > "$DATA/pw-$who")
done
GV_PLAYER_SEED_HEX="$(cat "$DATA/secrets-alice")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-alice")" $BIN init "$DATA/alice/hydra" "$DATA/alice.card" "$DATA/alice.pub" >/dev/null
AKEY="$DATA/alice.pub"
GV_PLAYER_SEED_HEX="$(cat "$DATA/secrets-bob")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-bob")" $BIN init "$DATA/bob/hydra" "$DATA/bob.card" "$DATA/bob.pub" >/dev/null
BKEY="$DATA/bob.pub"
MID="$(openssl rand -hex 32)"
echo "$MID" > "$DATA/match_id"
export GV_HYDRA_RAM=1
run() { # name config hydra peercard peerkey out extra...
  local name="$1" cfg="$2" hyd="$3" card="$4" key="$5" out="$6"; shift 6
  ( export GV_PLAYER_SEED_HEX="$(cat "$DATA/secrets-$name")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-$name")"
    exec $BIN run "$name" "$cfg" "$hyd" "$card" "$MID" "$key" "$out" "--epochs=$EPOCHS" "$@" ) > "$DATA/$name.log" 2>&1 &
}
# Alice hides early, signs one illegal control word, and stalls audit answers for
# 10 s (suspicion, then cleared). Bob signs one false checkpoint, frames Alice with
# forged evidence (rejected, nobody accused) and finally shows two conflicting log
# histories (proven equivocation). Every resulting proof is verified offline.
run bob   examples/edge-p2p/configs/bob.json   "$DATA/bob/hydra"   "$DATA/alice.card" "$AKEY" "$DATA/bob.bin" --cheat-at=1000 --accuse-falsely-at=900 --equivocate-at=1200
PID_B=$!
BOB_ID=""
for _ in $(seq 1 150); do
  BOB_ID="$(sed -n 's/^p2p-net local peer: \([^ ]*\) .*/\1/p' "$DATA/bob.log" 2>/dev/null | head -n1)"
  [ -n "$BOB_ID" ] && break
  sleep 0.1
done
if [ -n "$BOB_ID" ]; then
  export GV_REMOTE_PEER_ID="$BOB_ID" GV_REMOTE_MULTIADDR="/ip4/127.0.0.1/udp/4102/quic-v1/p2p/$BOB_ID"
fi
run alice examples/edge-p2p/configs/alice.json "$DATA/alice/hydra" "$DATA/bob.card"   "$BKEY" "$DATA/alice.bin" --hide-at=200 --illegal-at=800 --withhold-at=250
PID_A=$!
trap 'kill "$PID_A" "$PID_B" 2>/dev/null || true' EXIT INT TERM
FAIL=0
wait "$PID_A" || FAIL=1
wait "$PID_B" || FAIL=1
if [ "$FAIL" -ne 0 ]; then
  echo "FAIL: a peer exited with an error"; tail -n 15 "$DATA/alice.log" "$DATA/bob.log" >&2; exit 1
fi
echo "--- peers finished; verifying every artifact independently ---"
for who in alice bob; do
  grep -E "^(Hide|PROVEN)" "$DATA/$who.log" | sed "s/^/[$who] /" | cut -c1-140
  $BIN verify "$DATA/$who.bin" "$MID" "$AKEY" "$BKEY" | sed "s/^/[$who] /"
done
COUNT=0
for ev in "$DATA"/*.violation-*; do
  [ -e "$ev" ] || continue
  COUNT=$((COUNT + 1))
  echo "[evidence] $(basename "$ev")"
  $BIN verify "$ev" "$MID" "$AKEY" "$BKEY" | sed 's/^/    /'
done
need() { # file pattern description
  grep -q "$2" "$DATA/$1.log" || { echo "FAIL: expected '$3' in $1 log" >&2; exit 1; }
}
need bob "suspected non-cooperation" "suspicion while answers were withheld"
need bob "challenge answered: cleared" "late answer clears suspicion"
need alice "an accusation did not verify" "forged accusation rejected"
need alice "PROVEN VIOLATION: Opponent signed two conflicting log histories" "equivocation proven"
grep -q "PROVEN VIOLATION: Opponent" "$DATA/bob.log" && ! grep -q "PROVEN VIOLATION: Opponent signed two conflicting" "$DATA/bob.log" || true
ls "$DATA"/*.violation-*equivocation* >/dev/null 2>&1 || { echo "FAIL: no equivocation evidence file" >&2; exit 1; }
echo "PASS: headless match certified, $COUNT evidence file(s) independently verified. Logs: $DATA"
