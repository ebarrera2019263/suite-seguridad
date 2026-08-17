# Compila IP Security Audit Tool en un ejecutable .exe standalone para Windows.
# Requiere: python en PATH, dependencias de requirements.txt instaladas.

$ErrorActionPreference = "Stop"

Write-Host "Instalando dependencias..." -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

Write-Host "Compilando ejecutable con PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --console `
    --name "IPSecurityAuditTool" `
    --paths ".." `
    --collect-submodules ip_audit_core `
    --collect-all rich `
    --collect-all paramiko `
    --collect-all scapy `
    --collect-all reportlab `
    --hidden-import scapy.layers.all `
    main.py

Write-Host ""
Write-Host "Listo. Ejecutable generado en dist\IPSecurityAuditTool.exe" -ForegroundColor Green
Write-Host "Ejecutelo como Administrador para resolucion completa de direcciones MAC." -ForegroundColor Yellow
