#!/usr/bin/env sh
# Compile and run a real C client against gv_proofs.h and the cdylib, with warnings as errors.
set -eu
cd "$(dirname "$0")/.."
cargo build --locked -p gv-capi
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
lib=target/debug
${CC:-cc} -std=c11 -Wall -Wextra -Werror -pedantic -Iadapters/c/include \
  adapters/c/tests/c/smoke.c -L"$lib" -lgv_capi -o "$dir/smoke"
LD_LIBRARY_PATH="$lib" "$dir/smoke"
