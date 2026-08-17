"""Prueba de credenciales SMB (cuentas LOCALES de cada equipo) usando el
comando nativo de Windows 'net use'. No se usa ninguna libreria de
terceros: es exactamente el mismo mecanismo de autenticacion que usaria
cualquier usuario legitimo al conectarse a un recurso compartido, por eso
respeta fielmente la politica de bloqueo de cuentas configurada.

IMPORTANTE: se apunta siempre a '\\\\IP\\usuario' (sin dominio) para forzar
la validacion contra el SAM LOCAL del equipo, nunca contra Active
Directory -- así el radio de impacto de un bloqueo de cuenta queda
limitado a esa maquina puntual."""
from __future__ import annotations

import re
import subprocess
import time
from typing import Optional

_LOCKED_RE = re.compile(r"\b1909\b")                 # ERROR_ACCOUNT_LOCKED_OUT
_BAD_CREDS_RE = re.compile(r"\b1326\b")              # ERROR_LOGON_FAILURE (password incorrecta)
_UNREACHABLE_RE = re.compile(r"\b53\b|\b1231\b|\b1203\b")  # host/red no alcanzable
_ACCESS_DENIED_RE = re.compile(r"\b5\b")             # ERROR_ACCESS_DENIED
# Password CORRECTA pero expirada / forzada a cambiar: la autenticacion tuvo
# exito -> la contrasena debil SI se encontro (si no se mapea, se pierde como FN).
_PASSWORD_OK_BUT_EXPIRED_RE = re.compile(r"\b1330\b|\b1907\b")
_ACCOUNT_DISABLED_RE = re.compile(r"\b1331\b")       # ERROR_ACCOUNT_DISABLED (terminal, no martillar)
_SESSION_CONFLICT_RE = re.compile(r"\b1219\b")       # multiples conexiones a la misma IP


def _cleanup(ip: str) -> None:
    try:
        subprocess.run(
            ["net", "use", f"\\\\{ip}\\IPC$", "/delete", "/y"],
            capture_output=True, text=True, timeout=8,
        )
    except Exception:
        pass


def try_smb_login(ip: str, username: str, password: str, timeout_s: float = 8.0) -> str:
    """Devuelve: 'success' | 'fail' | 'locked' | 'unreachable' | 'denied' |
    'disabled' | 'session_conflict' | 'error:<msg>'"""
    user_arg = f"{ip}\\{username}"
    # La contrasena SI va como argumento de linea de comandos aca (riesgo
    # conocido y documentado, ver README/COBERTURA_LIMITES): se intento
    # evitarlo con "net use ... * ..." (que le pide la password a net.exe
    # por su prompt interactivo) pasandola por stdin, pero se verifico en
    # vivo que ese prompt de net.exe usa una lectura de consola que NO
    # funciona con stdin redirigido por pipe -- el proceso queda colgado
    # indefinidamente (hasta el timeout de subprocess) esperando una
    # consola real que nunca llega, rompiendo por completo cada intento.
    # Revertido a pasarla directo: funciona, al costo de quedar visible en
    # el argv del proceso "net.exe" (Administrador de tareas, Sysmon Event
    # ID 1, Script Block Logging) mientras ese proceso puntual esta vivo.
    cmd = ["net", "use", f"\\\\{ip}\\IPC$", password, f"/user:{user_arg}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return "unreachable"
    except Exception as exc:
        return f"error:{exc}"

    output = f"{proc.stdout}\n{proc.stderr}"

    if proc.returncode == 0:
        _cleanup(ip)
        return "success"
    ## Orden importa: los estados especificos (bloqueo, expirada-pero-correcta,
    ## deshabilitada, conflicto) se evaluan ANTES que "password incorrecta".
    if _LOCKED_RE.search(output):
        return "locked"
    if _PASSWORD_OK_BUT_EXPIRED_RE.search(output):
        _cleanup(ip)
        return "success"  # la contrasena era correcta (solo expirada) -> se encontro
    if _ACCOUNT_DISABLED_RE.search(output):
        return "disabled"
    if _SESSION_CONFLICT_RE.search(output):
        return "session_conflict"
    if _UNREACHABLE_RE.search(output):
        return "unreachable"
    if _BAD_CREDS_RE.search(output):
        return "fail"
    if _ACCESS_DENIED_RE.search(output):
        return "denied"
    return f"error:{output.strip()[:200]}"


def crack_smb_account(
    ip: str,
    username: str,
    wordlist,
    delay_s: float = 2.0,
    max_attempts: Optional[int] = None,
):
    """Prueba cada palabra del wordlist contra una cuenta local. Devuelve
    (resultado, contrasena_encontrada_o_None, intentos_realizados)."""
    attempts = 0
    saw_denied = False
    limit = max_attempts or len(wordlist)
    for password in wordlist[:limit]:
        attempts += 1
        outcome = try_smb_login(ip, username, password)

        ## Conflicto de sesion (1219): una conexion previa a esta IP hace fallar
        ## todo net use posterior (incluido el intento con la password correcta).
        ## Se limpia y se reintenta la MISMA password una vez antes de continuar.
        if outcome == "session_conflict":
            _cleanup(ip)
            outcome = try_smb_login(ip, username, password)

        if outcome == "success":
            return "cracked", password, attempts
        if outcome == "locked":
            return "locked", None, attempts
        if outcome == "disabled":
            return "disabled", None, attempts  # cuenta deshabilitada: no tiene sentido seguir
        if outcome == "unreachable":
            return "unreachable", None, attempts
        if outcome == "denied":
            # ACCESS_DENIED (5) es ambiguo: puede ser "password correcta pero sin
            # permiso sobre IPC$", o -- el caso mas comun -- que el equipo fuerce
            # el modelo "solo Invitado" (ForceGuest), donde CUALQUIER intento con
            # CUALQUIER password devuelve este mismo codigo sin comparar nada.
            # Antes se cortaba la prueba aca mismo, en el primer intento (casi
            # siempre la password vacia, la primera del wordlist), sin llegar a
            # probar el resto de la wordlist. Ahora se anota y se sigue probando;
            # si alguna palabra posterior da 'success' igual gana (arriba).
            saw_denied = True
        time.sleep(delay_s)
    return ("denied" if saw_denied else "not_found"), None, attempts
