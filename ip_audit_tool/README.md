# IP Security Audit Tool

Herramienta de auditoría de seguridad para redes internas: descubre hosts,
genera inventario (IP, MAC, hostname, SO estimado, tipo de dispositivo),
identifica puertos/servicios expuestos y correlaciona hallazgos con una
base local de configuraciones riesgosas y versiones vulnerables conocidas
(SSH, TLS/SSL, acceso remoto, gestión/MDM, riesgo de fuerza bruta).

## ⚠️ Uso ético y legal (lectura obligatoria)

- Ejecute esta herramienta **únicamente** sobre redes y equipos de su
  propiedad, o para los que cuente con **autorización explícita y por
  escrito** (contrato de pentesting, orden de trabajo, etc.).
- Escanear redes de terceros sin autorización es **ilegal** en la mayoría
  de las jurisdicciones (en España, arts. 197 bis y 264 del Código Penal;
  en muchos países latinoamericanos, delitos informáticos equivalentes).
- La herramienta **no realiza intentos de autenticación** (no prueba
  usuarios/contraseñas) contra ningún servicio: el "riesgo de fuerza
  bruta" se reporta únicamente como **exposición** (puerto sensible
  accesible), nunca como resultado de un ataque real.
- El escaneo de puertos y banners puede ser detectado por IDS/IPS y
  generar alertas; coordine la ventana de ejecución con el equipo de
  operaciones/seguridad correspondiente.
- El programa solicita una confirmación interactiva de autorización antes
  de escanear (se puede omitir con `--yes` en entornos ya autorizados y
  automatizados).

## Requisitos

- Python 3.10+ (recomendado 3.11/3.12).
- Windows: para resolución de dirección **MAC** vía ARP con Scapy se
  requiere:
  - Ejecutar la terminal / el `.exe` como **Administrador**.
  - Tener instalado [Npcap](https://npcap.com/) (modo compatible WinPcap).
  - Si no se cumplen estos requisitos, la herramienta sigue funcionando
    pero recurre a leer la tabla ARP del sistema (`arp -a`), que solo
    contiene MACs de hosts ya contactados, o puede omitirse con `--skip-mac`.
- Linux/macOS: para ARP vía Scapy se requiere `sudo`/root; en caso
  contrario se usa el fallback de tabla ARP local (`arp -n`).
- Conectividad de red hacia los objetivos (ICMP y/o TCP permitidos).

## Instalación

```bash
cd ip_audit_tool
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

## Uso

```bash
# Rango CIDR completo
python main.py --targets 192.168.1.0/24

# Varias IPs sueltas
python main.py --targets 10.0.0.5,10.0.0.6,10.0.0.10

# Desde archivo (ver ips.example.txt)
python main.py --file ips.txt --output-dir reportes --threads 30

# Sin privilegios de administrador (omite resolución de MAC)
python main.py --targets 192.168.1.0/24 --skip-mac

# Automatizado (sin prompt de confirmación etica), para pipelines ya autorizados
python main.py --file ips.txt --yes
```

### Parámetros principales

| Parámetro | Descripción |
|---|---|
| `--targets` | IPs / CIDR / rangos separados por coma |
| `--file` | Archivo de texto con un objetivo por línea |
| `--ports` | Lista/rango de puertos personalizados (ej: `22,80,443,1000-1010`) |
| `--threads` | Hosts analizados en paralelo (default 20) |
| `--port-timeout` | Timeout por puerto en segundos (default 0.9) |
| `--output-dir` | Carpeta de salida de reportes (default `reportes`) |
| `--formats` | `json`, `html`, `pdf` o combinación separada por coma (default `json,html,pdf`) |
| `--skip-mac` | Omite resolución de MAC (no requiere privilegios elevados) |
| `--yes` | Omite la confirmación interactiva de autorización |

## Qué evalúa

1. **Inventario**: IP, MAC (ARP/Scapy o tabla ARP), hostname (DNS inverso
   y NetBIOS), SO estimado (TTL + heurística de puertos/banners), tipo de
   dispositivo (servidor/estación de trabajo/indeterminado).
2. **Parches desactualizados**: banners de SSH/FTP/HTTP comparados contra
   una tabla local curada de versiones con CVEs conocidos.
3. **Gestión remota / MDM**: puertos típicos de administración (WinRM,
   RPC/SMB, WSUS, IPMI, Webmin, Cockpit, etc.) expuestos.
4. **SSL/TLS**: certificados caducados o autofirmados, protocolos
   obsoletos (SSLv3/TLS1.0/TLS1.1) y cifrados débiles (RC4/DES/3DES/MD5…).
5. **SSH**: versión del banner y, vía negociación de protocolo (sin
   autenticar), algoritmos KEX/cifrado/MAC débiles.
6. **Conexiones remotas expuestas**: RDP, VNC, Telnet, SSH, TeamViewer/
   AnyDesk (heurístico por puerto).
7. **Riesgo de fuerza bruta**: reporta exposición de servicios propensos
   (RDP/SSH/FTP/SMB/DB) — **sin intentar autenticarse jamás**.

## Reportes

- **Consola**: tablas con `rich` (inventario + hallazgos por host).
- **JSON**: `reportes/reporte_<timestamp>.json`, estructura completa por
  host (ideal para integrarse con otras herramientas/SIEM).
- **HTML**: `reportes/reporte_<timestamp>.html`, informe ejecutivo/técnico
  con severidad codificada por color y recomendaciones de mitigación.

## Limitaciones conocidas

- La detección de versiones/CVEs se basa en una tabla local curada, **no**
  en una fuente en vivo (NVD/Vulners). Para cobertura exhaustiva,
  complementar con `nmap --script vuln`, Nessus, OpenVAS o Vulners API.
- La detección de AnyDesk/TeamViewer es heurística por puerto (estas
  herramientas suelen usar conexiones salientes/relay y no siempre son
  detectables por puerto local).
- Los protocolos SSLv3/TLS1.0/1.1 pueden no probarse si el OpenSSL local
  los tiene deshabilitados en compilación (no es un falso negativo del
  servidor remoto, es una limitación del cliente usado para probar).
- El escaneo de puertos es TCP connect (no SYN stealth), por lo que no
  requiere privilegios elevados pero es más detectable por IDS.

## Generar el ejecutable (.exe) para Windows

Ver [BUILD_EXE.md](BUILD_EXE.md) para instrucciones detalladas, o ejecutar:

```powershell
build_exe.ps1
```

El binario resultante queda en `dist/IPSecurityAuditTool.exe` y no requiere
tener Python instalado en el equipo donde se ejecute. Para la resolución
de MAC vía ARP, siga requiriendo ejecutarse como Administrador y tener
Npcap instalado en esa máquina.
