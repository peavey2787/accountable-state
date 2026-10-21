#!/usr/bin/env bash
# Local two-peer browser arena demonstration; Linux only.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo 'Rust Cargo required (>=1.98)' >&2; exit 1; }
command -v openssl >/dev/null || { echo 'openssl required' >&2; exit 1; }
# The simulation always runs at 60 Hz. Cryptographic finality trails it by one
# epoch: GV_ARENA_EPOCH_TICKS ticks (20 = 333 ms of play per checkpoint).
EPOCH_TICKS="${GV_ARENA_EPOCH_TICKS:-20}"
case "$EPOCH_TICKS" in *[!0-9]*|'') echo 'GV_ARENA_EPOCH_TICKS must be a number that divides 300 (6..120)' >&2; exit 1;; esac
if [ "$EPOCH_TICKS" -lt 6 ] || [ "$EPOCH_TICKS" -gt 120 ] || [ $((300 % EPOCH_TICKS)) -ne 0 ]; then
  echo 'GV_ARENA_EPOCH_TICKS must divide 300 (6, 10, 12, 15, 20, 25, 30, 50, 60, 75, 100)' >&2; exit 1
fi
# Fail before launching browsers if the demonstration binary does not compile.
cargo build -q -p gv-edge-p2p-demo
DATA="${GV_DEMO_DIR:-.arena-local}"
mkdir -p "$DATA/alice" "$DATA/bob"
DATA="$(realpath "$DATA")"
if [ ! -e "$DATA/secrets-alice" ]; then
  (umask 077; openssl rand -hex 32 > "$DATA/secrets-alice"; openssl rand -base64 36 | tr -d '\n' > "$DATA/pw-alice")
fi
if [ ! -e "$DATA/secrets-bob" ]; then
  (umask 077; openssl rand -hex 32 > "$DATA/secrets-bob"; openssl rand -base64 36 | tr -d '\n' > "$DATA/pw-bob")
fi
# Reusing an accepted match history requires --resume. New demo launches get a
# new match ID by default; identities may be reused if the secrets are retained.
(umask 077; openssl rand -hex 32 > "$DATA/match-id")
export GV_PLAYER_SEED_HEX="$(cat "$DATA/secrets-alice")"
export GV_HYDRA_PASSWORD="$(cat "$DATA/pw-alice")"
GV_PLAYER_SEED_HEX="$(cat "$DATA/secrets-alice")" ./target/debug/gv-edge-p2p-demo init "$DATA/alice/hydra" "$DATA/alice.card" "$DATA/alice.pub" >/dev/null
AKEY="$DATA/alice.pub"
GV_PLAYER_SEED_HEX="$(cat "$DATA/secrets-bob")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-bob")" ./target/debug/gv-edge-p2p-demo init "$DATA/bob/hydra" "$DATA/bob.card" "$DATA/bob.pub" >/dev/null
BKEY="$DATA/bob.pub"
MID="$(cat "$DATA/match-id")"
MATCH_ARTIFACT="$DATA/match-${MID:0:16}"
# Two peer processes, each with its own persistent Hydra credentials and keys.
# The sample configs have different libp2p identities, ports and peer caches.
# HYDRA rewrites its whole encrypted state on every message. Keep this match's
# throwaway session state on RAM-backed storage (identity stays on disk).
export GV_HYDRA_RAM="${GV_HYDRA_RAM:-1}"
# Bob starts first. Alice then dials him directly, so the demo does not wait for
# LAN discovery (1-6 s, variable). If Bob's peer ID never shows up, Alice simply
# falls back to normal discovery.
(
  export GV_PLAYER_SEED_HEX="$(cat "$DATA/secrets-bob")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-bob")"
  exec ./target/debug/gv-edge-p2p-demo run bob examples/edge-p2p/configs/bob.json "$DATA/bob/hydra" "$DATA/alice.card" "$MID" "$AKEY" "$MATCH_ARTIFACT-bob.bin" --ui-port=9002 "--epoch-ticks=$EPOCH_TICKS"
) > "$DATA/bob.log" 2>&1 &
PID_B=$!
BOB_ID=""
for _ in $(seq 1 150); do
  BOB_ID="$(sed -n 's/^p2p-net local peer: \([^ ]*\) .*/\1/p' "$DATA/bob.log" 2>/dev/null | head -n1)"
  [ -n "$BOB_ID" ] && break
  sleep 0.1
done
(
  export GV_PLAYER_SEED_HEX="$(cat "$DATA/secrets-alice")" GV_HYDRA_PASSWORD="$(cat "$DATA/pw-alice")"
  if [ -n "$BOB_ID" ]; then
    export GV_REMOTE_PEER_ID="$BOB_ID" GV_REMOTE_MULTIADDR="/ip4/127.0.0.1/udp/4102/quic-v1/p2p/$BOB_ID"
  fi
  exec ./target/debug/gv-edge-p2p-demo run alice examples/edge-p2p/configs/alice.json "$DATA/alice/hydra" "$DATA/bob.card" "$MID" "$BKEY" "$MATCH_ARTIFACT-alice.bin" --ui-port=9001 "--epoch-ticks=$EPOCH_TICKS"
) > "$DATA/alice.log" 2>&1 &
PID_A=$!
cleanup() { kill "$PID_A" "$PID_B" 2>/dev/null || true; wait "$PID_A" "$PID_B" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
printf '\nArena UI:\n  Alice: http://127.0.0.1:9001\n  Bob:   http://127.0.0.1:9002\n\nLogs: %s/{alice,bob}.log\n60 Hz simulation · checkpoint every %s ticks\nPress Ctrl+C to end.\n' "$DATA" "$EPOCH_TICKS"
# The browsers are deliberately optional for headless/SSH testing.
if [ "${GV_ARENA_DISABLE_BROWSER:-0}" != "1" ] && command -v xdg-open >/dev/null 2>&1 && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
  (sleep 3; xdg-open http://127.0.0.1:9001 >/dev/null 2>&1 || true; xdg-open http://127.0.0.1:9002 >/dev/null 2>&1 || true) &
fi
wait "$PID_A" "$PID_B"
