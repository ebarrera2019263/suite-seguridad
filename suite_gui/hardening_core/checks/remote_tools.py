"""Deteccion (solo informativa) de software de acceso remoto de terceros
instalado. NUNCA se desinstala automaticamente: puede ser una herramienta
de soporte legitima y autorizada por la organizacion; la decision de
mantenerla o quitarla es del administrador."""
from __future__ import annotations

import winreg

from ..models import CheckResult, Severity
from ..registry_helpers import read_value

_UNINSTALL_PATHS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]

_WATCHED_PRODUCTS = ["anydesk", "teamviewer", "realvnc", "tightvnc", "ultravnc", "vnc"]


def _enum_installed_display_names():
    names = []
    for path in _UNINSTALL_PATHS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as root:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    display_name = read_value(winreg.HKEY_LOCAL_MACHINE, f"{path}\\{subkey_name}", "DisplayName")
                    if display_name:
                        names.append(str(display_name))
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return names


def check_remote_access_software() -> CheckResult:
    installed = _enum_installed_display_names()
    matches = sorted({n for n in installed if any(p in n.lower() for p in _WATCHED_PRODUCTS)})
    vulnerable = bool(matches)
    return CheckResult(
        check_id="remote_access_software",
        title="Software de acceso remoto de terceros instalado",
        category="Gestion de dispositivos (MDM) y agentes",
        severity=Severity.MEDIUM,
        vulnerable=vulnerable,
        detail=f"Detectado: {', '.join(matches)}." if vulnerable else "No se detecto software de acceso remoto de terceros conocido.",
        recommendation=(
            "Verificar si este software esta autorizado por la organizacion. Si no lo "
            "esta, desinstalarlo. Si es legitimo, asegurar contrasena fuerte/autenticacion "
            "de dos factores y mantenerlo actualizado. Esta herramienta NO lo desinstala "
            "automaticamente: puede tratarse de una herramienta de soporte en uso."
        ),
        fixable=False,
        manual_only=True,
    )
