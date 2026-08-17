"""Estado de la proteccion en tiempo real de Windows Defender. Si hay otro
antivirus de terceros activo, no se toca Defender (Windows lo desactiva
automaticamente por diseno en ese caso)."""
from __future__ import annotations

from ..models import CheckResult, Severity
from ..ps import run_ps, run_ps_json

# Respaldo para Windows Server, donde el namespace WMI root/SecurityCenter2
# NO EXISTE (es exclusivo de SKUs cliente): sin esto, un servidor con un EDR
# corporativo real (p.ej. ESET PROTECT) pero Defender apagado se marcaba
# como CRITICO por "sin ningun antivirus", un falso positivo. Lista
# best-effort por nombre de servicio, no exhaustiva (mismo criterio que
# _WATCHED_PRODUCTS en remote_tools.py); un nombre que no exista en el
# equipo simplemente no matchea, sin error (-ErrorAction SilentlyContinue).
_THIRD_PARTY_AV_SERVICES = [
    "ekrn",  # ESET (Endpoint/PROTECT)
    "CSFalconService",  # CrowdStrike Falcon
    "SentinelAgent", "SentinelHelperService",  # SentinelOne
    "SAVService", "Sophos Endpoint Defense Service", "Sophos MCS Agent",  # Sophos
    "ntrtscan", "TmCCSF", "tmlisten", "Ds_Agent",  # Trend Micro
    "SepMasterService",  # Symantec/Broadcom Endpoint Protection
    "masvc", "mfemms", "mfevtp",  # McAfee/Trellix
    "cyserver", "cyvera",  # Cortex XDR (Palo Alto Networks)
    "CbDefense", "carbonblack",  # VMware Carbon Black
    "EPSecurityService", "EPProtectedService",  # Bitdefender GravityZone
    "WRSVC",  # Webroot
    "ciscoamp",  # Cisco Secure Endpoint (AMP)
]


def _third_party_av_active() -> bool:
    data = run_ps_json(
        "Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct "
        "-ErrorAction SilentlyContinue | Where-Object { $_.displayName -notlike '*Defender*' } "
        "| Select-Object displayName"
    )
    if data:
        return True

    # OJO: "Get-Service -Name 'a','b','inexistente' -ErrorAction SilentlyContinue"
    # suprime el error de la salida, pero powershell.exe igual termina con
    # exit code 1 por el nombre no encontrado -- y run_ps_json descarta
    # cualquier salida cuando returncode != 0, perdiendo el match real junto
    # con el error (verificado en vivo). Por eso se enumeran TODOS los
    # servicios (nunca falla) y se filtra el nombre del lado de PowerShell,
    # en vez de pedirle a Get-Service una lista fija donde casi siempre
    # faltara alguno.
    service_list = ",".join(f"'{s}'" for s in _THIRD_PARTY_AV_SERVICES)
    fallback = run_ps_json(
        "Get-Service | Where-Object { $_.Status -eq 'Running' -and "
        f"$_.Name -in @({service_list}) }} | Select-Object -First 1 Name"
    )
    return bool(fallback)


def check_defender_realtime() -> CheckResult:
    data = run_ps_json("Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object RealTimeProtectionEnabled")
    if data is None:
        return CheckResult(
            check_id="defender_realtime",
            title="Proteccion en tiempo real de Windows Defender deshabilitada",
            category="Falta de actualizaciones y parches",
            severity=Severity.CRITICAL,
            vulnerable=False,
            determinable=False,
            detail="No se pudo consultar el estado de Windows Defender (puede no estar instalado o requerir privilegios).",
            recommendation="Verificar manualmente con: Get-MpComputerStatus",
            fixable=False,
        )

    enabled = bool(data.get("RealTimeProtectionEnabled"))
    if not enabled and _third_party_av_active():
        return CheckResult(
            check_id="defender_realtime",
            title="Proteccion en tiempo real de Windows Defender deshabilitada",
            category="Falta de actualizaciones y parches",
            severity=Severity.CRITICAL,
            vulnerable=False,
            detail="Defender esta inactivo, pero se detecto otro antivirus de terceros activo (comportamiento esperado).",
            recommendation="Verificar que el antivirus de terceros este actualizado y con proteccion en tiempo real activa.",
            fixable=False,
        )

    return CheckResult(
        check_id="defender_realtime",
        title="Proteccion en tiempo real de Windows Defender deshabilitada",
        category="Falta de actualizaciones y parches",
        severity=Severity.CRITICAL,
        vulnerable=not enabled,
        detail="RealTimeProtectionEnabled = False y no se detecto otro antivirus activo." if not enabled else "Proteccion en tiempo real activa.",
        recommendation="Activar la proteccion en tiempo real: es la primera linea de defensa contra malware/ransomware.",
        fixable=True,
    )


def fix_defender_realtime():
    proc = run_ps("Set-MpPreference -DisableRealtimeMonitoring $false")
    ok = proc.returncode == 0
    message = "Proteccion en tiempo real de Windows Defender activada." if ok else (proc.stderr or "").strip()[:300]
    undo = "Set-MpPreference -DisableRealtimeMonitoring $true  # NO recomendado: deja el equipo sin proteccion en tiempo real"
    return ok, message, undo
