# Compila Credential Audit Tool en un ejecutable .exe standalone para Windows.
$ErrorActionPreference = "Stop"

Write-Host "Instalando dependencias..." -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

Write-Host "Compilando ejecutable con PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --console `
    --name "CredentialAuditTool" `
    --collect-all rich `
    --add-data "core/winrm_helper.ps1;core" `
    main.py

Write-Host ""
Write-Host "Listo. Ejecutable generado en dist\CredentialAuditTool.exe" -ForegroundColor Green
