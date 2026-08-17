"""Ejecucion remota via WinRM.

Version multiplataforma: en vez de invocar 'powershell.exe' local (solo
Windows) con Invoke-Command, se conecta al servicio WinRM del equipo remoto
con la libreria pura-Python 'pywinrm' (WSMan/HTTP sobre 5985). El contenido
de cada script remote_scripts/<x>.ps1 se ejecuta EN EL EQUIPO REMOTO; su
objeto de resultado se serializa a JSON alli mismo y se devuelve. Asi la
herramienta corre igual desde Windows, macOS o Linux.

Requiere SIEMPRE credenciales explicitas (usuario + contrasena) de un
administrador del equipo remoto: pywinrm no puede heredar la sesion Windows
actual como hacia Invoke-Command, y ademas desde macOS/Linux no existe tal
sesion. La contrasena se mantiene en memoria dentro del proceso, nunca en el
argv de un subproceso."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Tuple

import winrm
from winrm.exceptions import (
    InvalidCredentialsError,
    WinRMError,
    WinRMOperationTimeoutError,
    WinRMTransportError,
)

_SCRIPTS_DIR = Path(__file__).parent / "remote_scripts"

# Envoltura que corre EN EL EQUIPO REMOTO: ejecuta el contenido del script y
# serializa su objeto de resultado a JSON, con el mismo protocolo de salida
# (RESULT:SUCCESS / RESULT:FAIL:<msg>) que consumia la version anterior.
_REMOTE_WRAPPER = """$ErrorActionPreference = 'Stop'
try {{
    $result = & {{
{body}
    }}
    Write-Output 'RESULT:SUCCESS'
    $result | ConvertTo-Json -Compress -Depth 5
}}
catch {{
    Write-Output "RESULT:FAIL:$($_.Exception.Message)"
}}"""


def run_remote_script(
    ip: str,
    script_name: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout_s: float = 40.0,
) -> Tuple[bool, str, Optional[dict]]:
    """Ejecuta remote_scripts/<script_name> en `ip` via WinRM.
    Devuelve (ok, mensaje, datos_json_o_None)."""
    script_path = _SCRIPTS_DIR / script_name
    if not script_path.exists():
        return False, f"Script remoto no encontrado: {script_name}", None

    if not username:
        return (
            False,
            "Se requieren credenciales WinRM (usuario y contrasena) de un administrador "
            "del equipo remoto. Marque 'Usar credenciales distintas a esta sesion' e "
            "ingrese, por ejemplo, 'IP\\Administrador' o 'DOMINIO\\usuario'.",
            None,
        )

    body = script_path.read_text(encoding="utf-8")
    remote_script = _REMOTE_WRAPPER.format(body=body)
    op_timeout = int(max(1, timeout_s))

    try:
        session = winrm.Session(
            f"http://{ip}:5985/wsman",
            auth=(username, password or ""),
            transport="ntlm",
            operation_timeout_sec=op_timeout,
            read_timeout_sec=op_timeout + 5,
        )
        result = session.run_ps(remote_script)
    except InvalidCredentialsError as exc:
        return False, f"Credenciales rechazadas por WinRM (401): {exc}", None
    except (WinRMOperationTimeoutError,):
        return False, f"Tiempo de espera agotado conectando a {ip} (¿WinRM habilitado? ¿firewall bloqueando 5985?).", None
    except (WinRMTransportError, WinRMError, ConnectionError, OSError) as exc:
        return False, f"No se pudo conectar a WinRM en {ip} (¿Enable-PSRemoting? ¿firewall 5985/5986?): {exc}", None
    except Exception as exc:
        return False, str(exc), None

    stdout = (result.std_out or b"").decode("utf-8", errors="replace")
    stderr = (result.std_err or b"").decode("utf-8", errors="replace")
    lines = stdout.splitlines()

    fail_line = next((l for l in lines if l.startswith("RESULT:FAIL:")), None)
    if fail_line is not None:
        return False, fail_line[len("RESULT:FAIL:"):].strip(), None

    if not any(l.strip() == "RESULT:SUCCESS" for l in lines):
        return False, (stderr or stdout or "Fallo desconocido").strip()[:400], None

    json_lines = [l for l in lines if l.strip() and l.strip() != "RESULT:SUCCESS"]
    data = None
    if json_lines:
        try:
            data = json.loads("\n".join(json_lines))
        except Exception as exc:
            return True, f"OK (no se pudo interpretar el detalle JSON devuelto: {exc})", None
    return True, "OK", data


def test_connectivity(ip: str, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, str, Optional[dict]]:
    return run_remote_script(ip, "test_connectivity.ps1", username, password, timeout_s=20.0)


def block_rdp(ip: str, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, str, Optional[dict]]:
    return run_remote_script(ip, "block_rdp.ps1", username, password)


def harden_tls(ip: str, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, str, Optional[dict]]:
    return run_remote_script(ip, "harden_tls.ps1", username, password)


def undo_block_rdp(ip: str, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, str, Optional[dict]]:
    return run_remote_script(ip, "undo_block_rdp.ps1", username, password)


def undo_harden_tls(ip: str, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, str, Optional[dict]]:
    return run_remote_script(ip, "undo_harden_tls.ps1", username, password)
