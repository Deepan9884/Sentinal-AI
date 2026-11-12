# Launch Sentinel-AI CLI Demo
$pythonPath = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Test-Path "C:\Users\Deepan\AppData\Local\Python\bin\python3.exe") { "C:\Users\Deepan\AppData\Local\Python\bin\python3.exe" } else { "py" }
& $pythonPath "$PSScriptRoot\demo.py"
