# Credential Audit Tool

Herramienta para **validar** (no para atacar en producción) si la
política de contraseñas de la organización resistiría intentos de
adivinación básicos. Prueba una lista curada y **pequeña** de
contraseñas débiles/comunes contra **cuentas locales** (nunca de
dominio) de los equipos indicados, vía SMB (`net use`) y WinRM. Si
encuentra una contraseña válida, evalúa su fortaleza y, con esa misma
credencial, obtiene el sistema operativo exacto y las contraseñas WiFi
ya guardadas en ese equipo.

## ⚠️ Uso exclusivo autorizado — lectura obligatoria

- Esta herramienta realiza **intentos de autenticación REALES**. Puede
  **bloquear cuentas** según la política de bloqueo configurada — de
  hecho, un bloqueo durante la prueba es una **señal positiva**: significa
  que la política está funcionando.
- Úsela **únicamente** contra equipos explícitamente designados para esta
  prueba (por ejemplo, máquinas dejadas a propósito con vulnerabilidades
  para validar una remediación), **nunca** contra la población general de
  usuarios de la organización sin coordinación previa con IT.
- Por diseño, solo prueba **cuentas locales** (`\\IP\usuario`), nunca
  cuentas de dominio: así, si se bloquea una cuenta, el impacto queda
  limitado a esa máquina puntual, no a toda la organización.
- Si el número de equipos resueltos supera 5, pide confirmar explícitamente
  el número exacto — pensado para frenar un CIDR que se coló más amplio de
  lo previsto, no para escaneos masivos.
- El reporte generado (JSON/HTML) **contiene contraseñas reales en texto
  plano** cuando se encuentran — es el objetivo explícito de la prueba.
  Trátelo como secreto: guárdelo cifrado, compártalo solo con quien deba
  verlo, y **rote de inmediato** cualquier contraseña listada.

## Qué hace

1. Inventario básico (IP, MAC, hostname, SO estimado por TTL) sin
   autenticar — igual criterio que `ip_audit_tool`.
2. Por cada usuario indicado (siempre incluye `Administrator`), prueba la
   lista de contraseñas vía `net use` (SMB) y, si no la encuentra, vía
   WinRM — con una espera configurable entre intentos (`--delay`).
3. Si una contraseña funciona: evalúa su fortaleza (longitud, variedad de
   caracteres, patrones comunes) y, con esa credencial, intenta obtener el
   SO exacto (WinRM o WMI/DCOM) y las contraseñas WiFi guardadas
   (`netsh wlan show profile key=clear`, ejecutado remotamente).
4. Si una cuenta se bloquea durante la prueba, se reporta como hallazgo
   positivo: la política de bloqueo está funcionando.

## Instalación

```bash
cd credential_audit_tool
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Uso

```bash
python main.py --targets 172.16.68.50,172.16.68.51 --users svc_backup,invitado
```

O sin argumentos, para que lo pregunte interactivamente (también funciona
con el `.exe` de doble clic).

### Parámetros

| Parámetro | Descripción |
|---|---|
| `--targets` | IPs separadas por coma, o un CIDR (usar con cuidado) |
| `--file` | Archivo de texto con una IP por línea |
| `--users` | Usuarios locales a probar (siempre incluye `Administrator`) |
| `--users-file` | Archivo con un usuario por línea |
| `--wordlist` | Lista de contraseñas propia (si no, usa la incorporada) |
| `--delay` | Segundos entre intentos sobre la misma cuenta (default 2.0) |
| `--max-attempts` | Tope de contraseñas a probar por cuenta (0 = toda la lista) |
| `--threads` | Equipos en paralelo (default 4; los intentos dentro de una cuenta son siempre secuenciales) |
| `--output-dir` | Carpeta de reportes (default `reportes_credenciales`) |
| `--yes` | Omite la confirmación ética inicial (y la de alcance si aplica) |
| `--no-pause` | No espera Enter al finalizar |

## Generar el .exe

```powershell
.\build_exe.ps1
```
