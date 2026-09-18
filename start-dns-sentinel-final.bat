@echo off
setlocal

cd /d "%~dp0"

echo ============================================
echo    DNS Sentinel - Security Operations
echo ============================================
echo.

:: Check if running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Administrator privileges required. Starting with elevation...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo Starting DNS Sentinel server...
echo.

:: Activate virtual environment and start Python server
start "DNS Sentinel Server" "%~dp0.venv\Scripts\python.exe" "%~dp0dns-sentinel-windows.py"

echo Waiting for server to start...
timeout /t 5 /nobreak >nul

:: Open dashboard in default browser
echo Opening dashboard...
start "" "http://127.0.0.1:8080/pro"

echo.
echo ============================================
echo    DNS Sentinel is now running
echo ============================================
echo.
echo Dashboard: http://127.0.0.1:8080/pro
echo.
echo To stop the server, close the DNS Sentinel Server window.
echo.
pause