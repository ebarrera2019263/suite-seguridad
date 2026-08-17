"""Ejecucion remota via WinRM (Invoke-Command). Todas las llamadas pasan
por _invoke.ps1, que corre localmente en ESTA maquina pero le indica a
PowerShell que ejecute el contenido de un script contra ComputerName.
La contrasena (si se usan credenciales alternativas) se pasa por STDIN,
nunca como argumento de linea de comandos, para que no quede visible en
el listado de procesos de otros usuarios mientras el subproceso corre."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional, Tuple

_SCRIPTS_DIR = Path(__file__).parent / "remote_scripts"
_INVOKE_WRAPPER = _SCRIPTS_DIR / "_invoke.ps1"


def run_remote_script(
    ip: str,
    script_name: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout_s: float = 40.0,
) -> Tuple[bool, str, Optional[dict]]:
    """Ejecuta remote_scripts/<script_name> contra `ip` via WinRM.
    Devuelve (ok, mensaje, datos_json_o_None)."""
    script_path = _SCRIPTS_DIR / script_name
    if not script_path.exists():
        return False, f"Script remoto no encontrado: {script_name}", None

    cmd = [
        "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(_INVOKE_WRAPPER),
        "-ComputerName", ip,
        "-ScriptPath", str(script_path),
    ]
    stdin_input = None
    if username:
        cmd += ["-Username", username]
        stdin_input = (password or "") + "\n"

    try:
        proc = subprocess.run(
            cmd, input=stdin_input, capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return False, f"Tiempo de espera agotado conectando a {ip} (¿WinRM habilitado? ¿firewall bloqueando 5985?).", None
    except Exception as exc:
        return False, str(exc), None

    lines = (proc.stdout or "").splitlines()

    fail_line = next((l for l in lines if l.startswith("RESULT:FAIL:")), None)
    if fail_line is not None:
        return False, fail_line[len("RESULT:FAIL:"):].strip(), None

    if not any(l.strip() == "RESULT:SUCCESS" for l in lines):
        return False, (proc.stderr or proc.stdout or "Fallo desconocido").strip()[:400], None

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
