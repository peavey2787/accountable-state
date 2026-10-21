@echo off
setlocal
cd /d "%~dp0\.."
where cargo >nul 2>&1 || (echo Cargo not found. & exit /b 1)
echo Updating default-branch Git dependencies. Review Cargo.lock before release.
cargo update -p p2p-net || exit /b 1
cargo update -p hydra-msg || exit /b 1
cargo test -p gv-edge || exit /b 1
cargo test -p gv-edge-p2p-demo || exit /b 1
