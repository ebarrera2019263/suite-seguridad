"""Prueba de credenciales SMB (cuentas LOCALES de cada equipo).

Version multiplataforma: usa la libreria pura-Python 'smbprotocol'
(smbclient) para autenticar por SMB2/3, en vez del comando nativo de Windows
'net use' -- asi la suite corre igual desde Windows, macOS o Linux. El
mecanismo de autenticacion sigue siendo NTLM sobre SMB, por lo que respeta
fielmente la politica de bloqueo de cuentas configurada en el equipo
destino (el codigo NTSTATUS que devuelve el servidor se mapea abajo a los
mismos estados que antes se leian de la salida de net.exe).

IMPORTANTE: se autentica siempre como 'IP\\usuario' (el dominio NTLM es la
propia IP del equipo), lo que fuerza la validacion contra el SAM LOCAL de esa
maquina y nunca contra Active Directory -- asi el radio de impacto de un
bloqueo de cuenta queda limitado a esa maquina puntual.

Ventaja de seguridad respecto a la version 'net use': la contrasena ya NO
viaja como argumento de linea de comandos (antes quedaba visible en el argv
del proceso net.exe); smbprotocol la maneja en memoria dentro del proceso.
"""
from __future__ import annotations

import socket
from typing import Optional

import smbclient
from smbprotocol.exceptions import SMBAuthenticationError, SMBResponseException

# Codigos NTSTATUS que devuelve el servidor en la respuesta SESSION_SETUP.
# Se mapean a los mismos estados que la version anterior deducia de los
# codigos de error de net.exe (1326/1909/1331/...).
_STATUS_LOGON_FAILURE = 0xC000006D        # password/usuario incorrectos
_STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234   # cuenta bloqueada por politica
_STATUS_ACCOUNT_DISABLED = 0xC0000072     # cuenta deshabilitada (terminal)
_STATUS_ACCOUNT_EXPIRED = 0xC0000193      # cuenta expirada (terminal)
_STATUS_PASSWORD_EXPIRED = 0xC0000071     # password CORRECTA pero expirada
_STATUS_PASSWORD_MUST_CHANGE = 0xC0000224  # password CORRECTA, forzada a cambiar
_STATUS_ACCESS_DENIED = 0xC0000022        # acceso denegado (ambiguo: ver crack)
_STATUS_NO_SUCH_USER = 0xC0000064         # el usuario no existe -> como 'fail'

# Password correcta (aunque expirada / a cambiar): la autenticacion tuvo
# exito, asi que la contrasena debil SI se encontro.
_SUCCESS_STATUSES = {_STATUS_PASSWORD_EXPIRED, _STATUS_PASSWORD_MUST_CHANGE}


def _cleanup(ip: str) -> None:
    """Cierra cualquier sesion SMB cacheada por smbclient para esta IP, para
    que el siguiente intento negocie una autenticacion nueva y limpia."""
    try:
        smbclient.delete_session(ip)
    except Exception:
        pass


def try_smb_login(ip: str, username: str, password: str, timeout_s: float = 8.0) -> str:
    """Devuelve: 'success' | 'fail' | 'locked' | 'unreachable' | 'denied' |
    'disabled' | 'session_conflict' | 'error:<msg>'"""
    # El dominio NTLM = IP del equipo -> valida contra el SAM LOCAL, nunca AD.
    user_arg = f"{ip}\\{username}"
    # Sesion nueva por intento: register_session autentica de inmediato y
    # lanza excepcion si las credenciales fallan.
    try:
        smbclient.register_session(
            ip,
            username=user_arg,
            password=password,
            connection_timeout=int(max(1, timeout_s)),
            auth_protocol="ntlm",
        )
    except SMBResponseException as exc:
        status = getattr(exc, "status", None)
        if status in _SUCCESS_STATUSES:
            return "success"  # la contrasena era correcta (solo expirada) -> se encontro
        if status == _STATUS_ACCOUNT_LOCKED_OUT:
            return "locked"
        if status in (_STATUS_ACCOUNT_DISABLED, _STATUS_ACCOUNT_EXPIRED):
            return "disabled"
        if status == _STATUS_ACCESS_DENIED:
            return "denied"
        if status in (_STATUS_LOGON_FAILURE, _STATUS_NO_SUCH_USER):
            return "fail"
        return f"error:{str(exc)[:200]}"
    except SMBAuthenticationError as exc:
        # smbprotocol no siempre expone el NTSTATUS exacto para fallos de la
        # capa NTLM/SPNEGO; se inspecciona el texto como respaldo.
        lowered = str(exc).lower()
        if any(s in lowered for s in ("lock", "1909", "bloque")):
            return "locked"
        if any(s in lowered for s in ("expired", "must change", "expirada")):
            return "success"
        if any(s in lowered for s in ("disabled", "deshabilit")):
            return "disabled"
        return "fail"
    except (socket.timeout, TimeoutError):
        return "unreachable"
    except (ConnectionError, OSError):
        return "unreachable"
    except ValueError as exc:
        # smbprotocol reporta el fallo de conexion TCP (puerto 445 cerrado,
        # host caido, timeout de conexion) como un ValueError con el texto
        # "Failed to connect to '<ip>:445': ...". Mapearlo a 'unreachable'
        # es clave: si no, el ataque de diccionario probaria toda la wordlist
        # contra un host que ni siquiera responde.
        lowered = str(exc).lower()
        if "connect" in lowered or "timed out" in lowered or "timeout" in lowered:
            return "unreachable"
        return f"error:{str(exc)[:200]}"
    except Exception as exc:
        lowered = str(exc).lower()
        # Modelo "solo Invitado" (ForceGuest, comun en Windows en workgroup):
        # el servidor autentica CUALQUIER usuario como guest en vez de comparar
        # la contrasena. smbprotocol rechaza esa sesion guest cuando exige
        # firma/cifrado. Semanticamente es un ACCESS_DENIED -> 'denied'.
        if "guest" in lowered:
            return "denied"
        return f"error:{str(exc)[:200]}"

    # register_session no lanzo excepcion -> autenticacion exitosa.
    _cleanup(ip)
    return "success"


def crack_smb_account(
    ip: str,
    username: str,
    wordlist,
    delay_s: float = 2.0,
    max_attempts: Optional[int] = None,
):
    """Prueba cada palabra del wordlist contra una cuenta local. Devuelve
    (resultado, contrasena_encontrada_o_None, intentos_realizados)."""
    import time

    attempts = 0
    saw_denied = False
    limit = max_attempts or len(wordlist)
    for password in wordlist[:limit]:
        attempts += 1
        outcome = try_smb_login(ip, username, password)

        ## Conflicto de sesion: una conexion previa a esta IP puede hacer
        ## fallar el intento. Se limpia y se reintenta la MISMA password una
        ## vez antes de continuar.
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
            # ACCESS_DENIED es ambiguo: puede ser "password correcta pero sin
            # permiso sobre IPC$", o -- el caso mas comun -- que el equipo
            # fuerce el modelo "solo Invitado" (ForceGuest), donde CUALQUIER
            # intento con CUALQUIER password devuelve este mismo codigo sin
            # comparar nada. Se anota y se sigue probando; si alguna palabra
            # posterior da 'success' igual gana (arriba).
            saw_denied = True
        time.sleep(delay_s)
    return ("denied" if saw_denied else "not_found"), None, attempts
