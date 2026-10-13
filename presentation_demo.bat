@echo off
setlocal
chcp 65001 >nul
pushd "%~dp0"
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
where uv >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Khong tim thay uv. Hay cai uv va mo lai terminal.
    set "presentation_exit=1"
    goto finish
)
uv sync --locked --inexact
if errorlevel 1 (
    set "presentation_exit=1"
    goto finish
)
uv run --no-sync python scripts/generate_presentation_diagrams.py %*
set "presentation_exit=%errorlevel%"
:finish
popd
if not defined CRYSTALBALL_DEMO_NO_PAUSE pause
exit /b %presentation_exit%
