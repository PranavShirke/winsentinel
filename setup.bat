@echo off
REM WinSentinel one-click setup: virtual environment, dependencies, .env with a fresh SECRET_KEY,
REM and the dashboard admin password. Safe to run again.
setlocal
cd /d "%~dp0"

set "BASE_PY="
where py >nul 2>&1 && set "BASE_PY=py"
if not defined BASE_PY (where python >nul 2>&1 && set "BASE_PY=python")
if not defined BASE_PY (
    echo Python 3.10+ was not found. Install it from https://www.python.org/downloads/ and run this again.
    pause
    exit /b 1
)

echo [1/4] Creating virtual environment...
if not exist ".venv\Scripts\python.exe" %BASE_PY% -m venv .venv
if errorlevel 1 goto :fail
set "PY=.venv\Scripts\python.exe"

echo [2/4] Installing dependencies...
"%PY%" -m pip install --upgrade pip >nul
"%PY%" -m pip install -r requirements.txt
if errorlevel 1 goto :fail

echo [3/4] Preparing .env ...
if not exist ".env" copy ".env.example" ".env" >nul
powershell -NoProfile -Command "$e = Get-Content .env; if (-not ($e | Where-Object { $_ -match '^SECRET_KEY=.+' })) { $k = & '.venv\Scripts\python.exe' -c 'import secrets; print(secrets.token_hex(32))'; $e = $e -replace '^SECRET_KEY=.*', ('SECRET_KEY=' + $k); $e | Set-Content .env -Encoding utf8; Write-Host 'Generated a new SECRET_KEY.' } else { Write-Host 'SECRET_KEY already set.' }"

echo [4/4] Set the dashboard administrator password (at least 12 characters):
"%PY%" main.py set-password
if errorlevel 1 goto :fail

echo.
echo Setup complete. Start WinSentinel with run.bat (it asks for Administrator rights).
pause
exit /b 0

:fail
echo.
echo Setup failed. See the messages above.
pause
exit /b 1
