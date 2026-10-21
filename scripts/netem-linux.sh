#!/usr/bin/env bash
# Runs a real native test inside an unprivileged network namespace whose loopback interface has
# Linux `tc netem` impairment (kernel-level delay, jitter, loss, duplication, reordering) applied
# to every packet. Needs unshare(1) with user+net namespaces and /sbin/tc; no root required.
#   ./scripts/netem-linux.sh headless                       # two-player match + offline verification
#   ./scripts/netem-linux.sh witness                        # 2 players + 3 honest + 1 malicious witness
#   NETEM='delay 60ms 30ms loss 8% duplicate 3% reorder 20% 40%' ./scripts/netem-linux.sh headless
set -euo pipefail
cd "$(dirname "$0")/.."
TC=/sbin/tc; [ -x "$TC" ] || TC="$(command -v tc || true)"
[ -x "$TC" ] || { echo 'SKIP: tc (iproute2) not installed' >&2; exit 2; }
command -v unshare >/dev/null || { echo 'SKIP: unshare not installed' >&2; exit 2; }
MODE="${1:-headless}"
export NETEM="${NETEM:-delay 40ms 25ms distribution normal loss 5% duplicate 2% reorder 20% 50%}"
case "$MODE" in
  headless) INNER="HEADLESS_EPOCHS=${HEADLESS_EPOCHS:-120} ./scripts/headless-arena-linux.sh" ;;
  witness) INNER="WITNESSES=3 EPOCHS=${EPOCHS:-150} ./scripts/witness-network-linux.sh" ;;
  *) echo "usage: $0 headless|witness" >&2; exit 1 ;;
esac
# Build outside the namespace so cargo can reach its registry/cache normally.
cargo build -q -p gv-edge-p2p-demo
probe="$(unshare -Urn bash -c "ip link set lo up && $TC qdisc add dev lo root netem delay 1ms && $TC qdisc show dev lo" 2>&1 || true)"
echo "$probe" | grep -q netem || { echo "SKIP: this kernel/user cannot apply netem in a user namespace: $probe" >&2; exit 2; }
echo "netem profile on lo: $NETEM"
unshare -Urn bash -c "ip link set lo up && $TC qdisc add dev lo root netem $NETEM && $TC qdisc show dev lo && $INNER"
