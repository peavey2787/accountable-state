#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
# Always build against the newest p2p-net main, not the last locked commit.
cargo update -p p2p-net
# Known-vulnerable dependencies fail validation (RustSec advisory database).
cargo audit
# Formatting is checked, never rewritten: formatting errors must cause failure.
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
if command -v node >/dev/null 2>&1; then
  node scripts/verify-arena-ui.mjs
  node scripts/verify-vectors.mjs
  node scripts/verify-event-codec.mjs
  node scripts/bench-packing.mjs
else
  echo "INFO: Node.js unavailable; independent JS vectors not run"
fi
