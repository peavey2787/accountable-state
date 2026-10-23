#!/usr/bin/env sh
# Unity-style host check: P/Invoke the C ABI from .NET against the freshly built library.
set -eu
cd "$(dirname "$0")/.."
if ! command -v dotnet >/dev/null 2>&1; then
  echo "GATE NOT RUN: dotnet SDK unavailable; the .NET/Unity P/Invoke smoke test did not run"
  exit 0
fi
cargo build -p gv-capi --locked
LD_LIBRARY_PATH="$PWD/target/debug:${LD_LIBRARY_PATH:-}" \
DYLD_LIBRARY_PATH="$PWD/target/debug:${DYLD_LIBRARY_PATH:-}" \
  dotnet run --project adapters/c/dotnet-smoke/Smoke.csproj
