# IP Hardening Tool (local)

Herramienta de **endurecimiento (hardening) local**: audita la
configuración de seguridad del equipo Windows en el que se ejecuta y,
**con confirmación explícita del usuario para cada cambio**, corrige lo
que encuentra mal configurado.

## Alcance — solo el equipo local

Esta herramienta **no tiene ninguna capacidad de red hacia otras
máquinas**. No acepta direcciones IP, rangos, ni nombres de host remotos
como parámetro. Todo lo que audita y corrige es exclusivamente la
configuración del equipo Windows donde se ejecuta el `.exe` (registro,
servicios y características de Windows locales). Es el complemento
"reparador" del [`ip_audit_tool`](../ip_audit_tool) (que sí escanea red);
ambos son deliberadamente herramientas separadas: una detecta desde
afuera, esta corrige desde adentro, máquina por máquina, con supervisión
humana.

## ⚠️ Uso ético y de seguridad (lectura obligatoria)

- Ejecútela únicamente en equipos de su propiedad o de los que sea
  **administrador autorizado**.
- **Requiere privilegios de Administrador** (se lo pedirá automáticamente
  vía UAC). Modifica registro de Windows, servicios y características
  opcionales — son cambios reales sobre el sistema.
- **Cada corrección se confirma individualmente**: la herramienta nunca
  aplica un cambio sin que usted escriba "s" explícitamente para ese
  hallazgo puntual. Use `--dry-run` si solo quiere el diagnóstico, sin que
  se le pregunte nada.
- Antes de aplicar correcciones, se ofrece crear un **punto de
  restauración de Windows** (puede fallar/no estar disponible en algunos
  equipos — Windows Server no lo trae por defecto — la herramienta avisa
  y continúa igual).
- Cada corrección aplicada queda registrada en un **script de reversión**
  (`deshacer_<fecha>.ps1`) en la carpeta de reportes, por si necesita
  deshacer manualmente algún cambio.
- Si está conectado por **Escritorio Remoto (RDP)** a la máquina, la
  herramienta lo detecta y pide una confirmación reforzada antes de tocar
  Firewall/RDP/WinRM, porque un cambio mal aplicado podría cortar su
  propia sesión. Asegúrese de tener otra vía de acceso (consola física,
  iDRAC/iLO, otra sesión) antes de confirmar esos cambios.
- Algunas correcciones (SMBv1, UAC, protocolos TLS) **requieren reiniciar
  el equipo** para completarse del todo; la herramienta lo indica en cada
  caso.
- La herramienta **no** desinstala software de terceros (AnyDesk,
  TeamViewer, VNC) ni deshabilita RDP por completo: son decisiones de
  negocio que quedan reportadas como recomendación manual, nunca
  aplicadas automáticamente.
- **No** instala actualizaciones de Windows automáticamente (puede
  implicar tiempo prolongado y reinicios); solo reporta si parecen
  desactualizadas.

## Qué audita y corrige

| Categoría | Verificación | Corrección automática (con confirmación) |
|---|---|---|
| Parches | SMBv1 habilitado | Sí — deshabilita la característica |
| Parches | Protección en tiempo real de Defender apagada | Sí (si no hay otro AV activo) |
| Parches | Actualizaciones posiblemente desactualizadas | No — solo recomendación |
| Conexiones remotas | RDP sin NLA | Sí — activa NLA |
| Conexiones remotas | RDP habilitado | No — solo recomendación (evita cortar el propio acceso) |
| Conexiones remotas | Servidor Telnet instalado | Sí — deshabilita la característica |
| SSL/TLS | Protocolos obsoletos (SSLv2/SSLv3/TLS1.0/1.1) sin deshabilitar | Sí — vía registro SCHANNEL |
| SSL/TLS | Suites de cifrado débiles (RC4/DES/3DES/MD5) | Sí — `Disable-TlsCipherSuite` |
| SSH | Algoritmos KEX/cifrado/MAC débiles en sshd_config (si OpenSSH Server está instalado) | Sí — reescribe sshd_config (con respaldo) |
| Gestión/MDM | Firewall de Windows deshabilitado en algún perfil | Sí — activa los 3 perfiles |
| Gestión/MDM | WinRM permite auth básica / tráfico sin cifrar | Sí |
| Gestión/MDM | Software de acceso remoto de terceros instalado | No — solo recomendación |
| Fuerza bruta / config. por defecto | Cuenta Guest habilitada | Sí — la deshabilita |
| Fuerza bruta / config. por defecto | UAC deshabilitado | Sí — lo reactiva |
| Fuerza bruta / config. por defecto | Contraseña de autologon en texto plano | Sí — la elimina del registro |
| Fuerza bruta / config. por defecto | LLMNR / NetBIOS habilitados | Sí |

## Instalación

```bash
cd hardening_tool
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Uso

```bash
# Diagnostico + correccion interactiva (pide confirmacion por cada hallazgo)
python main.py

# Solo diagnostico, sin ofrecer aplicar nada
python main.py --dry-run

# Sin punto de restauracion (mas rapido, menos seguro)
python main.py --skip-restore-point
```

O bien, doble clic en `IPHardeningTool.exe` (ver [MANUAL_USUARIO.md](MANUAL_USUARIO.md)
para el paso a paso de cada pregunta).

### Parámetros

| Parámetro | Descripción |
|---|---|
| `--dry-run` | Solo diagnostica y genera reporte; nunca ofrece aplicar correcciones |
| `--yes` | Omite la confirmación ética inicial (las correcciones individuales se siguen confirmando una por una) |
| `--skip-restore-point` | No intenta crear un punto de restauración de Windows |
| `--no-elevate` | No intenta relanzarse como Administrador automáticamente |
| `--output-dir` | Carpeta de salida para JSON/HTML/script de reversión (default `reportes_hardening`) |
| `--no-pause` | No espera Enter al finalizar (para scripts/automatización ya validada) |

## Reportes generados

- **Consola**: tabla de todas las verificaciones (rich).
- **JSON**: `reportes_hardening/diagnostico_<fecha>.json`.
- **HTML**: `reportes_hardening/diagnostico_<fecha>.html`, informe con
  severidad codificada por color, estado, corrección aplicada y detalle.
- **`deshacer_<fecha>.ps1`**: solo si se aplicó al menos una corrección;
  contiene los comandos exactos para revertir cada cambio.

## Generar el ejecutable .exe

```powershell
.\build_exe.ps1
```

Genera `dist/IPHardeningTool.exe`. Al ejecutarlo, si no tiene privilegios
de Administrador, se ofrece relanzar automáticamente vía UAC.
