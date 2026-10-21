@echo off
setlocal
cd /d "%~dp0"
REM Always build against the newest p2p-net main, not the last locked commit.
cargo update -p p2p-net || exit /b 1
REM Known-vulnerable dependencies fail validation (RustSec advisory database).
cargo audit || exit /b 1
REM Formatting is checked, never rewritten: formatting errors must cause failure.
cargo fmt --all -- --check || exit /b 1
cargo clippy --workspace --all-targets --all-features -- -D warnings || exit /b 1
cargo test --workspace --all-targets || exit /b 1
where node >nul 2>nul
if errorlevel 1 (
  echo INFO: Node.js unavailable; independent JS vectors not run
  exit /b 0
)
node scripts\verify-arena-ui.mjs || exit /b 1
node scripts\verify-vectors.mjs || exit /b 1
node scripts\verify-event-codec.mjs || exit /b 1
node scripts\bench-packing.mjs || exit /b 1
