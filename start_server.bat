@echo off
setlocal
cd /d "%~dp0"
set PULSE_HMS_HOST=127.0.0.1
set PULSE_HMS_PORT=5000
set PULSE_HMS_DEBUG=1

echo Starting Pulse HMS on http://%PULSE_HMS_HOST%:%PULSE_HMS_PORT%
echo Keep this window open while using the web app.
echo.

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" app.py
) else (
    python app.py
)

echo.
echo Server stopped. Press any key to close this window.
pause >nul
