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
# Every gate below is required: a missing tool is a FAIL, never a silent skip.
command -v node >/dev/null 2>&1 || { echo "FAIL: Node.js is required for the independent JS vectors"; exit 1; }
node scripts/verify-vectors.mjs
node scripts/verify-event-codec.mjs
node scripts/bench-packing.mjs
# 2. Compatibility with the newest p2p-net main (Cargo.lock is left unchanged).
sh scripts/newest-main-compat.sh
# 3. Engine host smoke: Unity-style .NET P/Invoke of the C ABI.
sh scripts/capi-dotnet-smoke.sh
# 4. Native host: a real C client of the C ABI, and ThreadSanitizer.
command -v "${CC:-cc}" >/dev/null 2>&1 || { echo "FAIL: a C compiler is required for the C ABI client"; exit 1; }
sh scripts/capi-c-smoke.sh
sh scripts/tsan-linux.sh
