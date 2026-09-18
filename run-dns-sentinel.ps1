$ErrorActionPreference = "Stop"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python was not found. Install Python 3.11+ and enable 'Add Python to PATH'." -ForegroundColor Red
    exit 1
}

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host "Starting DNS Sentinel. Administrator privileges are required for port 53." -ForegroundColor Cyan
.\.venv\Scripts\python.exe .\dns-sentinel-windows-updated.py