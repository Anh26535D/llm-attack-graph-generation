@echo off
setlocal
chcp 65001 >nul
pushd "%~dp0"
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
set "PYTHONUNBUFFERED=1"
where uv >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Khong tim thay uv. Hay cai uv va mo lai terminal.
    set "paper_exit=1"
    goto finish
)
if not exist ".env" (
    copy /y ".env.example" ".env" >nul
    echo [ERROR] Da tao .env. Dien GEMINI_API_KEY, OPENROUTER_API_KEY va OPENROUTER_API_KEY_V2 de sinh moi ca 9 hinh.
    echo De ve lai output da luu, khong can dien key; chay lai voi --resume PATH --render-only.
    set "paper_exit=1"
    goto finish
)
uv sync --locked --inexact --extra dev --extra gemini --extra openrouter --extra paper
if errorlevel 1 (
    set "paper_exit=1"
    goto finish
)
uv run --no-sync python scripts/run_paper_experiment.py %*
set "paper_exit=%errorlevel%"
:finish
popd
if not defined CRYSTALBALL_DEMO_NO_PAUSE pause
exit /b %paper_exit%
