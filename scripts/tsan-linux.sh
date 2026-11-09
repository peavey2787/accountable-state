#!/usr/bin/env sh
# ThreadSanitizer over the concurrent code: the proof queue's service and worker pool.
# A required release gate: needs a nightly toolchain with rust-src and fails without one.
set -eu
cd "$(dirname "$0")/.."
if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
  echo "FAIL: ThreadSanitizer gate needs a nightly toolchain (rustup toolchain install nightly --component rust-src)"
  exit 1
fi
host=$(rustc -vV | sed -n 's/^host: //p')
RUSTFLAGS="-Zsanitizer=thread" RUSTDOCFLAGS="-Zsanitizer=thread" \
  cargo +nightly test -Zbuild-std --target "$host" --locked -p gv-proof-queue \
  --test service --test service_accounting
