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
# Browser/WASM: lint the wasm target and run the binding inside a real WebAssembly runtime.
cargo clippy -p gv-wasm --target wasm32-unknown-unknown --locked -- -D warnings
command -v wasm-pack >/dev/null 2>&1 || { echo "FAIL: wasm-pack is required for the WASM binding tests"; exit 1; }
(cd adapters/wasm && wasm-pack test --node)
if command -v node >/dev/null 2>&1; then
  node scripts/verify-vectors.mjs
  node scripts/verify-event-codec.mjs
  node scripts/bench-packing.mjs
else
  echo "INFO: Node.js unavailable; independent JS vectors not run"
fi
# 2. Compatibility with the newest p2p-net main (Cargo.lock is left unchanged).
sh scripts/newest-main-compat.sh
