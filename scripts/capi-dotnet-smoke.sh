#!/usr/bin/env sh
# Unity-style host check: P/Invoke the C ABI from .NET against the freshly built library.
set -eu
cd "$(dirname "$0")/.."
if ! command -v dotnet >/dev/null 2>&1; then
  echo "FAIL: the .NET/Unity P/Invoke gate needs the .NET SDK (dotnet)"
  exit 1
fi
cargo build -p gv-capi --locked
LD_LIBRARY_PATH="$PWD/target/debug:${LD_LIBRARY_PATH:-}" \
DYLD_LIBRARY_PATH="$PWD/target/debug:${DYLD_LIBRARY_PATH:-}" \
  dotnet run --project adapters/c/dotnet-smoke/Smoke.csproj
