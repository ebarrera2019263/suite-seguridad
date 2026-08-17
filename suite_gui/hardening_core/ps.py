"""Helper para invocar PowerShell localmente (Windows). Todas las llamadas
apuntan siempre a 'localhost' de forma implicita: ningun modulo de esta
herramienta acepta un host remoto como parametro."""
from __future__ import annotations

import json
import subprocess
from typing import Any, Optional


def run_ps(command: str, timeout: float = 25.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_ps_json(command: str, timeout: float = 25.0) -> Optional[Any]:
    """Ejecuta un comando de PowerShell y parsea la salida como JSON.
    Devuelve None si el comando falla o el modulo/cmdlet no existe (por
    ejemplo, en versiones antiguas de Windows)."""
    try:
        proc = run_ps(f"{command} | ConvertTo-Json -Compress -Depth 4", timeout=timeout)
    except Exception:
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except Exception:
        return None
