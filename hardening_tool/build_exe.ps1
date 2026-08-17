# Compila IP Hardening Tool en un ejecutable .exe standalone para Windows.
$ErrorActionPreference = "Stop"

Write-Host "Instalando dependencias..." -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

Write-Host "Compilando ejecutable con PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --console `
    --name "IPHardeningTool" `
    --collect-all rich `
    main.py

Write-Host ""
Write-Host "Listo. Ejecutable generado en dist\IPHardeningTool.exe" -ForegroundColor Green
Write-Host "Debe ejecutarse como Administrador (lo pedira automaticamente via UAC)." -ForegroundColor Yellow
