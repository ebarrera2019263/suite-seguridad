"""Verificaciones de TLS/SSL local: protocolos obsoletos via SCHANNEL y
cifrados debiles en el orden de suites del sistema."""
from __future__ import annotations

import winreg
from typing import List

from ..models import CheckResult, Severity
from ..ps import run_ps, run_ps_json
from ..registry_helpers import read_value, write_dword

_SCHANNEL_BASE = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
_OBSOLETE_PROTOCOLS = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]
_SIDES = ["Client", "Server"]

_WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]


def _protocol_explicitly_disabled(name: str) -> bool:
    for side in _SIDES:
        path = f"{_SCHANNEL_BASE}\\{name}\\{side}"
        enabled = read_value(winreg.HKEY_LOCAL_MACHINE, path, "Enabled")
        disabled_by_default = read_value(winreg.HKEY_LOCAL_MACHINE, path, "DisabledByDefault")
        if not (enabled == 0 and disabled_by_default == 1):
            return False
    return True


def _protocol_explicitly_enabled(name: str) -> bool:
    """True si el protocolo esta FORZADO a activo por registro (Enabled=1) en
    cualquiera de los dos lados. Este es el unico caso que un scanner marcaria
    con certeza (el servidor lo negociaria)."""
    for side in _SIDES:
        path = f"{_SCHANNEL_BASE}\\{name}\\{side}"
        if read_value(winreg.HKEY_LOCAL_MACHINE, path, "Enabled") == 1:
            return True
    return False


def check_obsolete_tls_protocols() -> CheckResult:
    ## Distinguir tres estados por protocolo evita el falso positivo HIGH
    ## permanente: SSLv2/SSLv3 estan OFF por defecto en todo Windows soportado
    ## SIN necesidad de claves de registro, asi que "clave ausente" NO es una
    ## vulnerabilidad que un pentest vea. Solo "Enabled=1 explicito" es un
    ## hallazgo real (HIGH); "no deshabilitado explicitamente" es una
    ## recomendacion de endurecimiento belt-and-suspenders (BAJA).
    forced_on = [p for p in _OBSOLETE_PROTOCOLS if _protocol_explicitly_enabled(p)]
    not_hardened = [
        p for p in _OBSOLETE_PROTOCOLS
        if p not in forced_on and not _protocol_explicitly_disabled(p)
    ]

    if forced_on:
        return CheckResult(
            check_id="tls_obsolete_protocols",
            title="Protocolos SSL/TLS obsoletos FORZADOS a activo",
            category="Seguridad en capa de red y cifrado (SSL/TLS)",
            severity=Severity.HIGH,
            vulnerable=True,
            detail=f"Estan explicitamente habilitados (Enabled=1) via registro: {', '.join(forced_on)}. Un scanner los negociaria.",
            recommendation="Deshabilitar explicitamente estos protocolos (Enabled=0, DisabledByDefault=1) en SCHANNEL Cliente y Servidor. Requiere reinicio.",
            fixable=True,
        )

    if not_hardened:
        return CheckResult(
            check_id="tls_obsolete_protocols",
            title="Protocolos SSL/TLS obsoletos sin deshabilitar explicitamente (endurecimiento recomendado)",
            category="Seguridad en capa de red y cifrado (SSL/TLS)",
            severity=Severity.LOW,
            vulnerable=True,
            detail=(
                f"No estan deshabilitados explicitamente via registro: {', '.join(not_hardened)}. "
                "OJO: SSLv2/SSLv3 (y en Windows recientes tambien TLS1.0/1.1) suelen estar OFF por "
                "defecto del sistema operativo, asi que un pentest podria NO marcarlos. Se recomienda "
                "deshabilitarlos explicitamente igual (belt-and-suspenders), pero no es un hallazgo critico."
            ),
            recommendation=(
                "Deshabilitar explicitamente SSLv2, SSLv3, TLS 1.0 y TLS 1.1 en el registro "
                "SCHANNEL (Cliente y Servidor) y dejar unicamente TLS 1.2/1.3. Puede requerir reinicio."
            ),
            fixable=True,
        )

    return CheckResult(
        check_id="tls_obsolete_protocols",
        title="Protocolos SSL/TLS obsoletos sin deshabilitar explicitamente",
        category="Seguridad en capa de red y cifrado (SSL/TLS)",
        severity=Severity.LOW,
        vulnerable=False,
        detail="SSLv2/SSLv3/TLS1.0/TLS1.1 estan explicitamente deshabilitados via SCHANNEL.",
        recommendation="Ninguna accion requerida.",
        fixable=False,
    )


def fix_obsolete_tls_protocols():
    ok_all = True
    for name in _OBSOLETE_PROTOCOLS:
        for side in _SIDES:
            path = f"{_SCHANNEL_BASE}\\{name}\\{side}"
            ok = write_dword(winreg.HKEY_LOCAL_MACHINE, path, "Enabled", 0)
            ok = write_dword(winreg.HKEY_LOCAL_MACHINE, path, "DisabledByDefault", 1) and ok
            ok_all = ok_all and ok
    if ok_all:
        message = (
            "Protocolos obsoletos deshabilitados explicitamente (Enabled=0, DisabledByDefault=1). "
            "Reinicie el equipo para que el cambio surta efecto por completo."
        )
    else:
        message = (
            "Algunas escrituras de registro SCHANNEL fallaron (revise privilegios de administrador); "
            "el endurecimiento pudo quedar PARCIAL. Verifique manualmente antes de re-escanear."
        )
    undo_lines = []
    for name in _OBSOLETE_PROTOCOLS:
        for side in _SIDES:
            path = f"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\{name}\\{side}"
            undo_lines.append(
                f'Remove-ItemProperty -Path "HKLM:\\{path}" -Name Enabled,DisabledByDefault '
                f'-ErrorAction SilentlyContinue  # revierte {name} ({side}) al valor por defecto del SO'
            )
    undo = "\n".join(undo_lines)
    return ok_all, message, undo


def check_weak_cipher_suites() -> CheckResult:
    data = run_ps_json("Get-TlsCipherSuite | Select-Object Name")
    if data is None:
        return CheckResult(
            check_id="tls_weak_ciphers",
            title="Cifrados TLS debiles habilitados",
            category="Seguridad en capa de red y cifrado (SSL/TLS)",
            severity=Severity.MEDIUM,
            vulnerable=False,
            determinable=False,
            detail="Get-TlsCipherSuite no disponible en este sistema (requiere Windows 8.1/2012 R2 o superior).",
            recommendation="Revisar manualmente la politica de cifrado local (Group Policy > Cifrados SSL).",
            fixable=False,
        )

    suites = data if isinstance(data, list) else [data]
    weak = [s.get("Name") for s in suites if any(k in str(s.get("Name")) for k in _WEAK_CIPHER_KEYWORDS)]
    vulnerable = bool(weak)
    return CheckResult(
        check_id="tls_weak_ciphers",
        title="Cifrados TLS debiles habilitados",
        category="Seguridad en capa de red y cifrado (SSL/TLS)",
        severity=Severity.MEDIUM,
        vulnerable=vulnerable,
        detail=f"Suites debiles habilitadas: {', '.join(weak)}." if vulnerable else "No se detectaron suites de cifrado debiles habilitadas.",
        recommendation="Deshabilitar las suites de cifrado que usan RC4/DES/3DES/MD5/EXPORT/NULL.",
        fixable=True,
    )


def fix_weak_cipher_suites():
    data = run_ps_json("Get-TlsCipherSuite | Select-Object Name")
    suites: List[str] = []
    if data:
        items = data if isinstance(data, list) else [data]
        suites = [s.get("Name") for s in items if any(k in str(s.get("Name")) for k in _WEAK_CIPHER_KEYWORDS)]

    if not suites:
        return True, "No habia suites debiles que deshabilitar.", "# nada que deshacer"

    ok_all = True
    undo_lines = []
    for suite in suites:
        proc = run_ps(f"Disable-TlsCipherSuite -Name '{suite}'")
        ok_all = ok_all and proc.returncode == 0
        undo_lines.append(f"Enable-TlsCipherSuite -Name '{suite}'  # NO recomendado: cifrado debil")

    message = f"Se deshabilitaron {len(suites)} suites de cifrado debiles."
    return ok_all, message, "\n".join(undo_lines)
