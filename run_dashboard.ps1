# Launch Sentinel-AI Streamlit Web Dashboard
$pythonPath = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Test-Path "C:\Users\Deepan\AppData\Local\Python\bin\python3.exe") { "C:\Users\Deepan\AppData\Local\Python\bin\python3.exe" } else { "py" }
Write-Host "Starting SENTINEL-AI Interactive Web Dashboard on http://localhost:8501..." -ForegroundColor Cyan
& $pythonPath -m streamlit run "$PSScriptRoot\web\app.py"
