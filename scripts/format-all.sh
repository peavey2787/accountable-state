#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
cargo fmt --all
cargo fmt --all -- --check
