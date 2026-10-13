@echo off
setlocal
chcp 65001 >nul
pushd "%~dp0"
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
set "PYTHONUNBUFFERED=1"
echo === CrystalBall - SolarWinds Detailed API Demo ===
echo Mac dinh: bao cao SolarWinds day du, graph chi tiet, nhan nut va canh.
echo Tuy chon: --figure N / --nine / --cve / --report / --evasion / --check
echo.
where uv >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Khong tim thay uv. Hay cai uv va mo lai terminal.
    set "demo_exit=1"
    goto finish
)
if not exist ".env" (
    copy /y ".env.example" ".env" >nul
    echo [ERROR] Da tao .env. Hay dien API key va dat LLM_BACKEND=gemini, openrouter hoac openrouter_v2.
    set "demo_exit=1"
    goto finish
)
echo [1/2] Kiem tra thu vien...
set "demo_embedding_extra=--extra embeddings"
for %%A in (%*) do (
    if /I "%%~A"=="--figure" set "demo_embedding_extra="
    if /I "%%~A"=="--nine" set "demo_embedding_extra="
)
uv sync --locked --inexact --extra dev %demo_embedding_extra% --extra gemini --extra openrouter --extra paper
if errorlevel 1 (
    echo [ERROR] Khong cai duoc thu vien. Kiem tra ket noi mang va thong bao phia tren.
    set "demo_exit=1"
    goto finish
)
echo.
echo [2/2] Chay demo...
uv run --no-sync python scripts/demo_online.py %*
set "demo_exit=%errorlevel%"
:finish
echo.
if not "%demo_exit%"=="0" echo Demo chua hoan tat. Xem thong bao loi phia tren.
popd
if not defined CRYSTALBALL_DEMO_NO_PAUSE pause
exit /b %demo_exit%
