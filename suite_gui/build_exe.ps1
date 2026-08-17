# Compila la Suite de Seguridad Interna (GUI unica) en un ejecutable .exe
# standalone para Windows. Junta ip_audit_core (paquete COMPARTIDO en la raiz
# del repo, --paths ..) + hardening_core + credential_core + remote_patch_core
# (estos tres, copias locales de los core/ originales) detras de una sola
# interfaz grafica.
$ErrorActionPreference = "Stop"

Write-Host "Instalando dependencias..." -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

Write-Host "Compilando ejecutable con PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --windowed `
    --name "SuiteSeguridadInterna" `
    --paths ".." `
    --collect-submodules ip_audit_core `
    --collect-all rich `
    --collect-all paramiko `
    --collect-all scapy `
    --collect-all cryptography `
    --collect-all reportlab `
    --hidden-import scapy.layers.all `
    --add-data "remote_patch_core/remote_scripts;remote_patch_core/remote_scripts" `
    --add-data "credential_core/winrm_helper.ps1;credential_core" `
    app.py

Write-Host ""
Write-Host "Listo. Ejecutable generado en dist\SuiteSeguridadInterna.exe" -ForegroundColor Green
Write-Host "Para el diagnostico/correccion de hardening local, ejecutelo como Administrador." -ForegroundColor Yellow
