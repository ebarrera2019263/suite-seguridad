"""WinRM (gestion remota de Windows): autenticacion basica y trafico sin
cifrar son riesgo de exposicion de credenciales."""
from __future__ import annotations

import winreg

from ..models import CheckResult, Severity
from ..ps import run_ps, run_ps_json
from ..registry_helpers import read_value, write_dword

_WINRM_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"


def _effective_wsman_flag(leaf: str) -> bool:
    """Lee la config EFECTIVA de WinRM via el proveedor WSMan (no la rama de
    GPO). Un admin que corre 'winrm set ...' o Set-Item WSMan:\\... escribe
    aca, no en Policies -- por eso hay que consultar ambas fuentes."""
    data = run_ps_json(
        f"(Get-Item -Path WSMan:\\localhost\\Service\\{leaf} -ErrorAction SilentlyContinue).Value"
    )
    if isinstance(data, bool):
        return data
    if isinstance(data, str):
        return data.strip().lower() == "true"
    return False


def check_winrm() -> CheckResult:
    ## Status debe castearse a [string]: el enum ServiceControllerStatus se
    ## serializa como entero (Running=4), asi que 'str(4) != "Running"' era
    ## siempre verdadero y el check cortaba antes de evaluar nada.
    service = run_ps_json(
        "Get-Service WinRM -ErrorAction SilentlyContinue "
        "| Select-Object @{Name='Status';Expression={[string]$_.Status}}"
    )
    if service is None or str(service.get("Status")) != "Running":
        return CheckResult(
            check_id="winrm_basic_auth",
            title="WinRM permite autenticacion basica / trafico sin cifrar",
            category="Gestion de dispositivos (MDM) y agentes",
            severity=Severity.HIGH,
            vulnerable=False,
            determinable=True,
            detail="El servicio WinRM no esta en ejecucion.",
            recommendation="No aplica mientras el servicio este detenido.",
            fixable=False,
        )

    ## Fuente 1: rama de Directiva de grupo (Policies). Fuente 2: config WSMan
    ## efectiva. Es vulnerable si CUALQUIERA de las dos habilita basic/unencrypted.
    allow_basic_gpo = read_value(winreg.HKEY_LOCAL_MACHINE, _WINRM_POLICY_PATH, "AllowBasic")
    allow_unenc_gpo = read_value(winreg.HKEY_LOCAL_MACHINE, _WINRM_POLICY_PATH, "AllowUnencryptedTraffic")
    basic_wsman = _effective_wsman_flag("Auth\\Basic")
    unenc_wsman = _effective_wsman_flag("AllowUnencrypted")

    basic_on = allow_basic_gpo == 1 or basic_wsman
    unenc_on = allow_unenc_gpo == 1 or unenc_wsman
    vulnerable = basic_on or unenc_on

    return CheckResult(
        check_id="winrm_basic_auth",
        title="WinRM permite autenticacion basica / trafico sin cifrar",
        category="Gestion de dispositivos (MDM) y agentes",
        severity=Severity.HIGH,
        vulnerable=vulnerable,
        detail=(
            f"Basic auth activa={basic_on} (GPO={allow_basic_gpo}, WSMan={basic_wsman}); "
            f"trafico sin cifrar activo={unenc_on} (GPO={allow_unenc_gpo}, WSMan={unenc_wsman})."
            if vulnerable else "WinRM no permite autenticacion basica ni trafico sin cifrar (GPO ni WSMan)."
        ),
        recommendation="Deshabilitar autenticacion basica y trafico sin cifrar en WinRM; usar Negotiate/Kerberos o Certificados sobre HTTPS.",
        fixable=True,
    )


def fix_winrm():
    ok1 = write_dword(winreg.HKEY_LOCAL_MACHINE, _WINRM_POLICY_PATH, "AllowBasic", 0)
    ok2 = write_dword(winreg.HKEY_LOCAL_MACHINE, _WINRM_POLICY_PATH, "AllowUnencryptedTraffic", 0)
    ok = ok1 and ok2
    message = "Autenticacion basica y trafico sin cifrar deshabilitados en WinRM." if ok else "No se pudo modificar el registro."
    undo = (
        f'Set-ItemProperty -Path "HKLM:\\{_WINRM_POLICY_PATH}" -Name AllowBasic -Value 1 -Type DWord; '
        f'Set-ItemProperty -Path "HKLM:\\{_WINRM_POLICY_PATH}" -Name AllowUnencryptedTraffic -Value 1 -Type DWord'
        "  # NO recomendado"
    )
    return ok, message, undo
