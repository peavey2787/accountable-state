@echo off
REM Compatibility check: build and test against the newest p2p-net main. The committed
REM Cargo.lock (reproducible release validation) is restored afterwards, pass or fail.
setlocal
cd /d "%~dp0.."
set "LOCK_BACKUP=%TEMP%\accountable-state-Cargo.lock.%RANDOM%%RANDOM%"
copy /y Cargo.lock "%LOCK_BACKUP%" >nul || exit /b 1
call :check
set "RESULT=%ERRORLEVEL%"
copy /y "%LOCK_BACKUP%" Cargo.lock >nul || exit /b 1
del "%LOCK_BACKUP%"
exit /b %RESULT%

:check
cargo update -p p2p-net || exit /b 1
cargo clippy --workspace --all-targets --all-features -- -D warnings || exit /b 1
cargo test --workspace --all-targets --all-features || exit /b 1
exit /b 0
