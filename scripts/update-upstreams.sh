#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
echo "Updating p2p-net and hydra-msg git HEADs (default branches). Review git diff/Cargo.lock before release."
cargo update -p p2p-net
cargo update -p hydra-msg
cargo test -p gv-edge
cargo test -p gv-edge-p2p-demo
