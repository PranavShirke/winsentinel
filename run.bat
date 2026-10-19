@echo off
REM WinSentinel launcher: starts the dashboard with Administrator rights.
REM Administrator is needed to read the Windows Security log (brute-force detection),
REM BitLocker status and Defender exclusions. WinSentinel itself stays read-only.
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b
)

set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY (where py >nul 2>&1 && set "PY=py")
if not defined PY (where python >nul 2>&1 && set "PY=python")
if not defined PY (
    echo Python was not found. Run setup.bat first, or install Python 3.10+ from python.org.
    pause
    exit /b 1
)

echo Starting WinSentinel as Administrator on http://127.0.0.1:5000
"%PY%" main.py serve
pause
