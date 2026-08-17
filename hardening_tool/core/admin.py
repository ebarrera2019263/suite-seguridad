"""Privilegios de administrador, deteccion de sesion remota, y
auto-elevacion. Todo referido siempre al proceso/equipo local."""
from __future__ import annotations

import ctypes
import os
import sys


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_remote_session() -> bool:
    """True si la sesion actual llego por RDP (variable de entorno
    SESSIONNAME empieza con 'RDP-'). Sirve para advertir antes de tocar
    firewall/RDP, ya que un cambio mal aplicado podria cortar la propia
    sesion desde la que se esta trabajando."""
    session = os.environ.get("SESSIONNAME", "")
    return session.upper().startswith("RDP-")


def relaunch_as_admin() -> bool:
    """Reintenta el proceso actual con privilegios elevados (UAC).
    Devuelve True si se lanzo el proceso elevado (el proceso actual debe
    terminar despues); False si fallo."""
    try:
        if getattr(sys, "frozen", False):
            executable = sys.executable
            params = " ".join(f'"{a}"' for a in sys.argv[1:])
        else:
            executable = sys.executable
            params = " ".join(f'"{a}"' for a in [sys.argv[0], *sys.argv[1:]])

        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1
        )
        # ShellExecuteW devuelve un valor > 32 si tuvo exito.
        return int(result) > 32
    except Exception:
        return False
