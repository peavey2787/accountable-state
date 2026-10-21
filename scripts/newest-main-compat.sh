#!/usr/bin/env sh
# Compatibility check: build and test against the newest p2p-net main. The committed
# Cargo.lock (reproducible release validation) is restored afterwards, pass or fail.
set -eu
cd "$(dirname "$0")/.."
backup=$(mktemp)
cp Cargo.lock "$backup"
trap 'cp "$backup" Cargo.lock; rm -f "$backup"' EXIT
cargo update -p p2p-net
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
