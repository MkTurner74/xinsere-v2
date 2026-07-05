# Xinsere demo — start script (Windows PowerShell)
# First run:  py -m venv .venv ; .\.venv\Scripts\python -m pip install -r requirements.txt
# Then:       .\run.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
  Write-Host "Creating venv + installing deps..." -ForegroundColor Cyan
  py -m venv .venv
  .\.venv\Scripts\python -m pip install --upgrade pip
  .\.venv\Scripts\python -m pip install -r requirements.txt
}

# On-chain grants need AWS creds (to read the signer key from Secrets Manager).
# Verify + download reads also hit Amoy. Make sure you're signed in to the
# Xinsere AWS account (aws sts get-caller-identity => account 058264449111).
Write-Host "Starting Xinsere demo on http://127.0.0.1:8000" -ForegroundColor Green
.\.venv\Scripts\python -m uvicorn app:app --host 0.0.0.0 --port 8000
