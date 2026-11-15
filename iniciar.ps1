# Arranca LlaveSegura en local: http://localhost:8612  (usa localhost, no 127.0.0.1: Face ID/Windows Hello lo necesita)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path .venv)) {
    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt
}
.\.venv\Scripts\python.exe -m streamlit run app.py --server.port 8612 --server.address localhost
