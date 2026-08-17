"""LLMNR y NetBIOS sobre TCP/IP: protocolos de resolucion de nombres
heredados, vector clasico de poisoning/captura de credenciales (ej.
herramientas tipo Responder) dentro de la red local."""
from __future__ import annotations

import winreg

from ..models import CheckResult, Severity
from ..ps import run_ps, run_ps_json
from ..registry_helpers import delete_value, read_value, write_dword

_DNS_CLIENT_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"


def check_llmnr() -> CheckResult:
    value = read_value(winreg.HKEY_LOCAL_MACHINE, _DNS_CLIENT_POLICY_PATH, "EnableMulticast")
    vulnerable = value in (None, 1)
    return CheckResult(
        check_id="llmnr_enabled",
        title="LLMNR habilitado",
        category="Riesgo de fuerza bruta / configuraciones por defecto",
        severity=Severity.MEDIUM,
        vulnerable=vulnerable,
        detail=(
            "No hay politica que deshabilite LLMNR (valor por defecto de Windows: habilitado)."
            if value is None
            else f"EnableMulticast = {value}."
        ),
        recommendation=(
            "Deshabilitar LLMNR: permite a un atacante en la misma red responder "
            "falsamente a consultas de nombre y capturar hashes de credenciales "
            "(tecnica comun con herramientas como Responder)."
        ),
        fixable=True,
    )


def fix_llmnr():
    ok = write_dword(winreg.HKEY_LOCAL_MACHINE, _DNS_CLIENT_POLICY_PATH, "EnableMulticast", 0)
    message = "LLMNR deshabilitado." if ok else "No se pudo modificar el registro."
    undo = (
        f'Remove-ItemProperty -Path "HKLM:\\{_DNS_CLIENT_POLICY_PATH}" -Name EnableMulticast '
        "-ErrorAction SilentlyContinue  # vuelve al comportamiento por defecto (LLMNR habilitado)"
    )
    return ok, message, undo


def check_netbios() -> CheckResult:
    data = run_ps_json(
        "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' "
        "| Select-Object Description, TcpipNetbiosOptions"
    )
    if data is None:
        return CheckResult(
            check_id="netbios_enabled",
            title="NetBIOS sobre TCP/IP habilitado",
            category="Riesgo de fuerza bruta / configuraciones por defecto",
            severity=Severity.LOW,
            vulnerable=False,
            determinable=False,
            detail="No se pudieron consultar los adaptadores de red.",
            recommendation="Verificar manualmente en las propiedades TCP/IP avanzadas del adaptador.",
            fixable=False,
        )

    adapters = data if isinstance(data, list) else [data]
    # TcpipNetbiosOptions: 0=usar DHCP/por defecto (habilitado), 1=habilitado, 2=deshabilitado
    exposed = [a.get("Description") for a in adapters if a.get("TcpipNetbiosOptions") in (0, 1, None)]
    vulnerable = bool(exposed)
    return CheckResult(
        check_id="netbios_enabled",
        title="NetBIOS sobre TCP/IP habilitado",
        category="Riesgo de fuerza bruta / configuraciones por defecto",
        severity=Severity.LOW,
        vulnerable=vulnerable,
        detail=f"Adaptadores con NetBIOS activo: {', '.join(str(a) for a in exposed)}." if vulnerable else "NetBIOS sobre TCP/IP deshabilitado en todos los adaptadores.",
        recommendation="Deshabilitar NetBIOS sobre TCP/IP en los adaptadores de red para reducir exposicion a enumeracion y poisoning de nombres.",
        fixable=True,
    )


def fix_netbios():
    proc = run_ps(
        "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' "
        "| ForEach-Object { $_ | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} }"
    )
    ok = proc.returncode == 0
    message = "NetBIOS sobre TCP/IP deshabilitado en los adaptadores activos." if ok else (proc.stderr or "").strip()[:300]
    undo = (
        "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | "
        "ForEach-Object { $_ | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=0} }"
        "  # vuelve al valor por defecto"
    )
    return ok, message, undo
