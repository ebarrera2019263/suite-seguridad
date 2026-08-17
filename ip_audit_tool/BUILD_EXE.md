# Generar el ejecutable .exe

## Opción 1: script automático (Windows / PowerShell)

```powershell
cd ip_audit_tool
.\build_exe.ps1
```

## Opción 2: manual

```bash
cd ip_audit_tool
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python -m PyInstaller --noconfirm --onefile --console `
    --name "IPSecurityAuditTool" `
    --collect-all rich `
    --collect-all paramiko `
    --collect-all scapy `
    --hidden-import scapy.layers.all `
    main.py
```

El ejecutable queda en `dist/IPSecurityAuditTool.exe`.

## Uso del .exe

Abrir una terminal (PowerShell/CMD) **como Administrador** (necesario solo
para resolución completa de direcciones MAC vía ARP; el resto de
funciones trabaja sin privilegios elevados) y ejecutar, por ejemplo:

```bat
IPSecurityAuditTool.exe --targets 192.168.1.0/24 --output-dir reportes
```

o

```bat
IPSecurityAuditTool.exe --file ips.txt --skip-mac
```

Los reportes JSON/HTML se generan junto a la carpeta desde la que se
ejecuta el `.exe` (o en la ruta indicada con `--output-dir`).

### Notas

- El primer arranque del `.exe` puede tardar unos segundos más (extracción
  de dependencias empaquetadas por PyInstaller).
- Si Windows Defender / SmartScreen marca el binario como desconocido
  (comportamiento normal para ejecutables no firmados generados con
  PyInstaller), permita la ejecución explícitamente o firme el binario
  con un certificado de su organización.
- Para resolución de MAC vía ARP se recomienda tener [Npcap](https://npcap.com/)
  instalado en modo compatible WinPcap.
