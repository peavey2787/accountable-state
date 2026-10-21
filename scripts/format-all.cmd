@echo off
setlocal
cd /d "%~dp0.."
cargo fmt --all
if errorlevel 1 exit /b 1
cargo fmt --all -- --check
exit /b %errorlevel%
