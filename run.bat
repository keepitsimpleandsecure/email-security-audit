@echo off
REM ---- MX Sentinel: one-click launcher for Windows ----
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found on PATH. Install it from https://python.org and re-run.
    pause
    exit /b 1
)

if not exist ".venv\" (
    echo Creating virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat
echo Installing/updating dependencies...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

echo Starting MX Sentinel at http://127.0.0.1:5000 ...
start "" "http://127.0.0.1:5000"
python mx_sentinel\app.py

pause
