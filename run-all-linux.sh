#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
# 1. Reproducible release validation: exactly the committed Cargo.lock.
# Known-vulnerable dependencies fail validation (RustSec advisory database).
cargo audit
# Formatting is checked, never rewritten: formatting errors must cause failure.
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
if command -v node >/dev/null 2>&1; then
  node scripts/verify-vectors.mjs
  node scripts/verify-event-codec.mjs
  node scripts/bench-packing.mjs
else
  echo "INFO: Node.js unavailable; independent JS vectors not run"
fi
# 2. Compatibility with the newest p2p-net main (Cargo.lock is left unchanged).
sh scripts/newest-main-compat.sh
