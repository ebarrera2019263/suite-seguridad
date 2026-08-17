"""Verificaciones de RDP local. Deliberadamente NO se ofrece deshabilitar
RDP por completo de forma automatica: es una decision de negocio (puede
cortar el acceso remoto legitimo del propio equipo) y solo se reporta
como recomendacion manual."""
from __future__ import annotations

import winreg

from ..models import CheckResult, Severity
from ..registry_helpers import read_value, write_dword

_RDP_PATH = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
_RDP_ENABLED_PATH = r"SYSTEM\CurrentControlSet\Control\Terminal Server"


def check_rdp_nla() -> CheckResult:
    value = read_value(winreg.HKEY_LOCAL_MACHINE, _RDP_PATH, "UserAuthentication")
    vulnerable = value in (None, 0)
    detail = (
        "UserAuthentication no esta definido (puede depender del valor por defecto del SO)."
        if value is None
        else f"UserAuthentication = {value} ({'NLA activo' if value == 1 else 'NLA inactivo'})."
    )
    return CheckResult(
        check_id="rdp_nla",
        title="RDP sin Network Level Authentication (NLA)",
        category="Conexiones remotas no autorizadas/expuestas",
        severity=Severity.HIGH,
        vulnerable=vulnerable,
        detail=detail,
        recommendation=(
            "Activar NLA para RDP: exige autenticacion antes de establecer la sesion "
            "completa, reduciendo superficie de ataque frente a exploits pre-autenticacion "
            "y fuerza bruta automatizada."
        ),
        fixable=True,
    )


def fix_rdp_nla():
    previous = read_value(winreg.HKEY_LOCAL_MACHINE, _RDP_PATH, "UserAuthentication")
    ok = write_dword(winreg.HKEY_LOCAL_MACHINE, _RDP_PATH, "UserAuthentication", 1)
    message = "NLA activado para RDP." if ok else "No se pudo escribir en el registro (verifique privilegios de administrador)."
    prev_val = 0 if previous is None else previous
    undo = (
        f'Set-ItemProperty -Path "HKLM:\\{_RDP_PATH}" -Name UserAuthentication -Value {prev_val} '
        "-Type DWord  # revierte NLA a su valor previo"
    )
    return ok, message, undo


def check_rdp_enabled() -> CheckResult:
    """Informativo unicamente: si RDP esta habilitado, se reporta como
    exposicion pero NO se ofrece deshabilitarlo automaticamente."""
    value = read_value(winreg.HKEY_LOCAL_MACHINE, _RDP_ENABLED_PATH, "fDenyTSConnections")
    enabled = value == 0
    return CheckResult(
        check_id="rdp_enabled",
        title="Escritorio remoto (RDP) habilitado",
        category="Conexiones remotas no autorizadas/expuestas",
        severity=Severity.MEDIUM,
        vulnerable=enabled,
        detail="RDP esta habilitado en este equipo." if enabled else "RDP esta deshabilitado.",
        recommendation=(
            "Si RDP no es necesario, deshabilitarlo (Configuracion > Sistema > Escritorio "
            "remoto). Si es necesario, restringir el acceso por firewall/VPN a IPs de "
            "administracion conocidas y mantener NLA activo. Esta herramienta NO lo "
            "deshabilita automaticamente porque podria cortar el propio acceso remoto "
            "al equipo."
        ),
        fixable=False,
        manual_only=True,
    )
