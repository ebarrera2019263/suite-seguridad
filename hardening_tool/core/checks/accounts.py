"""Verificaciones de cuentas locales, UAC y credenciales de autologon."""
from __future__ import annotations

import winreg

from ..models import CheckResult, Severity
from ..ps import run_ps, run_ps_json
from ..registry_helpers import delete_value, read_value, write_dword, write_string

_UAC_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_WINLOGON_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


# La cuenta de invitado integrada se identifica por su SID bien conocido
# (termina en "-501"), NUNCA por el nombre "Guest": en Windows instalado en
# espanol (y otros idiomas) la cuenta se llama "Invitado", y "Get-LocalUser
# -Name Guest" no matchea nada -- el check quedaba siempre "no determinable"
# y el fix siempre fallaba, sin que la cuenta real fuera nunca auditada.
_GUEST_LOOKUP_CMD = (
    "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } "
    "| Select-Object -First 1 Name, Enabled"
)


def check_guest_account() -> CheckResult:
    data = run_ps_json(_GUEST_LOOKUP_CMD)
    if data is None:
        return CheckResult(
            check_id="guest_account",
            title="Cuenta de invitado integrada (SID -501) habilitada",
            category="Riesgo de fuerza bruta / configuraciones por defecto",
            severity=Severity.MEDIUM,
            vulnerable=False,
            determinable=False,
            detail="No se pudo identificar la cuenta de invitado integrada (SID terminado en -501) en este equipo.",
            recommendation="Verificar manualmente con: Get-LocalUser | Where-Object { $_.SID -like '*-501' }",
            fixable=False,
        )

    name = data.get("Name") or "Invitado"
    enabled = bool(data.get("Enabled"))
    return CheckResult(
        check_id="guest_account",
        title="Cuenta de invitado integrada (SID -501) habilitada",
        category="Riesgo de fuerza bruta / configuraciones por defecto",
        severity=Severity.MEDIUM,
        vulnerable=enabled,
        detail=(
            f"La cuenta de invitado integrada ('{name}') esta habilitada."
            if enabled
            else f"La cuenta de invitado integrada ('{name}') esta deshabilitada."
        ),
        recommendation="Deshabilitar la cuenta de invitado: es una cuenta por defecto, sin contrasena fuerte propia, objetivo comun de fuerza bruta.",
        fixable=True,
    )


def fix_guest_account():
    data = run_ps_json(_GUEST_LOOKUP_CMD)
    name = (data or {}).get("Name")
    if not name:
        return (
            False,
            "No se pudo identificar el nombre de la cuenta de invitado integrada (SID -501) en este equipo.",
            None,
        )

    proc = run_ps(f'Disable-LocalUser -Name "{name}" -ErrorAction Stop')
    ok = proc.returncode == 0
    message = f"Cuenta de invitado ('{name}') deshabilitada." if ok else (proc.stderr or "").strip()[:300]
    undo = f'Enable-LocalUser -Name "{name}"  # NO recomendado: la cuenta de invitado es un vector de ataque comun'
    return ok, message, undo


def check_uac() -> CheckResult:
    value = read_value(winreg.HKEY_LOCAL_MACHINE, _UAC_PATH, "EnableLUA")
    disabled = value == 0
    return CheckResult(
        check_id="uac_disabled",
        title="Control de Cuentas de Usuario (UAC) deshabilitado",
        category="Riesgo de fuerza bruta / configuraciones por defecto",
        severity=Severity.HIGH,
        vulnerable=disabled,
        detail="EnableLUA = 0 (UAC deshabilitado)." if disabled else f"EnableLUA = {value if value is not None else '1 (por defecto)'}",
        recommendation="Mantener UAC activo: evita que procesos/malware obtengan privilegios de administrador sin confirmacion explicita.",
        fixable=True,
    )


def fix_uac():
    ok = write_dword(winreg.HKEY_LOCAL_MACHINE, _UAC_PATH, "EnableLUA", 1)
    message = "UAC activado (requiere reiniciar el equipo para completarse)." if ok else "No se pudo modificar el registro."
    undo = f'Set-ItemProperty -Path "HKLM:\\{_UAC_PATH}" -Name EnableLUA -Value 0 -Type DWord  # NO recomendado'
    return ok, message, undo


def check_autologon_password() -> CheckResult:
    auto_logon = read_value(winreg.HKEY_LOCAL_MACHINE, _WINLOGON_PATH, "AutoAdminLogon")
    default_password = read_value(winreg.HKEY_LOCAL_MACHINE, _WINLOGON_PATH, "DefaultPassword")
    ## Vulnerable si la contrasena en texto plano existe en el registro, sin
    ## importar el valor actual de AutoAdminLogon: es comun que quede
    ## huerfana (netplwiz no siempre la limpia al desactivar el autologon
    ## desde la UI), y en ese caso el secreto sigue expuesto en el registro
    ## aunque el autologon ya no este activo.
    vulnerable = bool(default_password)
    orphaned = vulnerable and str(auto_logon) != "1"
    return CheckResult(
        check_id="autologon_password",
        title="Contrasena de auto-inicio de sesion almacenada en texto plano",
        category="Riesgo de fuerza bruta / configuraciones por defecto",
        severity=Severity.CRITICAL,
        vulnerable=vulnerable,
        detail=(
            (
                "Se encontro una contrasena de autologon en el registro (valor oculto por "
                "seguridad, no se muestra ni se guarda en ningun reporte)"
                + (
                    ", aunque AutoAdminLogon esta actualmente desactivado (0) -- quedo huerfana "
                    "de una configuracion anterior y sigue expuesta igual."
                    if orphaned else " y AutoAdminLogon=1 (autologon activo)."
                )
            )
            if vulnerable
            else "No se encontraron credenciales de autologon en texto plano."
        ),
        recommendation="Eliminar el autologon con contrasena en texto plano; usar inicio de sesion normal o Credential Guard.",
        fixable=True,
    )


def fix_autologon_password():
    ok1 = delete_value(winreg.HKEY_LOCAL_MACHINE, _WINLOGON_PATH, "DefaultPassword")
    ok2 = write_string(winreg.HKEY_LOCAL_MACHINE, _WINLOGON_PATH, "AutoAdminLogon", "0")
    ok = ok1 and ok2
    message = "Contrasena de autologon eliminada del registro y autologon desactivado." if ok else "No se pudo modificar el registro."
    undo = (
        "# Por seguridad, esta herramienta NO guarda la contrasena original. "
        "Si necesita autologon, reconfigurelo manualmente con 'netplwiz' o "
        "'Sysinternals Autologon'."
    )
    return ok, message, undo
