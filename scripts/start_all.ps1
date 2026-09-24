$Root = Resolve-Path "$PSScriptRoot\.."
Write-Host "Starting AgentGuard backend and frontend..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "$Root\scripts\run_backend.ps1"
Start-Sleep -Seconds 2
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "$Root\scripts\run_frontend.ps1"
Write-Host "Backend: http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host "Swagger: http://127.0.0.1:8000/docs" -ForegroundColor Cyan
Write-Host "Frontend: http://127.0.0.1:5173" -ForegroundColor Cyan
