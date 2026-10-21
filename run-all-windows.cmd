@echo off
setlocal
cd /d "%~dp0"
REM 1. Reproducible release validation: exactly the committed Cargo.lock.
REM Known-vulnerable dependencies fail validation (RustSec advisory database).
cargo audit || exit /b 1
REM Formatting is checked, never rewritten: formatting errors must cause failure.
cargo fmt --all -- --check || exit /b 1
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings || exit /b 1
cargo test --workspace --all-targets --all-features --locked || exit /b 1
where node >nul 2>nul
if errorlevel 1 (
  echo INFO: Node.js unavailable; independent JS vectors not run
) else (
  node scripts\verify-vectors.mjs || exit /b 1
  node scripts\verify-event-codec.mjs || exit /b 1
  node scripts\bench-packing.mjs || exit /b 1
)
REM 2. Compatibility with the newest p2p-net main (Cargo.lock is left unchanged).
call scripts\newest-main-compat.cmd || exit /b 1
