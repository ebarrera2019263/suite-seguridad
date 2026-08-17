# Compila Remote Patch Tool en un ejecutable .exe standalone para Windows.
$ErrorActionPreference = "Stop"

Write-Host "Instalando dependencias..." -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

Write-Host "Compilando ejecutable con PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --console `
    --name "RemotePatchTool" `
    --collect-all rich `
    --add-data "core/remote_scripts;core/remote_scripts" `
    main.py

Write-Host ""
Write-Host "Listo. Ejecutable generado en dist\RemotePatchTool.exe" -ForegroundColor Green
