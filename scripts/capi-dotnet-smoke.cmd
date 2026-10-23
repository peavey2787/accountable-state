@echo off
REM Unity-style host check: P/Invoke the C ABI from .NET against the freshly built library.
setlocal
cd /d "%~dp0.."
where dotnet >nul 2>nul
if errorlevel 1 (
  echo GATE NOT RUN: dotnet SDK unavailable; the .NET/Unity P/Invoke smoke test did not run
  exit /b 0
)
cargo build -p gv-capi --locked || exit /b 1
set "PATH=%CD%\target\debug;%PATH%"
dotnet run --project adapters\c\dotnet-smoke\Smoke.csproj || exit /b 1
