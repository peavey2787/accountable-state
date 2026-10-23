#!/usr/bin/env sh
# ThreadSanitizer over the concurrent code: the proof queue's service and worker pool.
# Needs a nightly toolchain with rust-src; prints an explicit gate message when unavailable.
set -eu
cd "$(dirname "$0")/.."
if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
  echo "GATE NOT RUN: nightly toolchain unavailable; ThreadSanitizer did not run"
  exit 0
fi
host=$(rustc -vV | sed -n 's/^host: //p')
RUSTFLAGS="-Zsanitizer=thread" RUSTDOCFLAGS="-Zsanitizer=thread" \
  cargo +nightly test -Zbuild-std --target "$host" --locked -p gv-proof-queue \
  --test service --test service_accounting
