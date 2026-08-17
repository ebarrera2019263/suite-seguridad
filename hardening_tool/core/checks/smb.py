"""Verificaciones de SMB local: protocolo SMBv1 y firma obligatoria."""
from __future__ import annotations

from ..models import CheckResult, Severity
from ..ps import run_ps, run_ps_json


def check_smbv1() -> CheckResult:
    ## IMPORTANTE: hay que castear State a [string] del lado PowerShell. El enum
    ## Microsoft.Dism.Commands.FeatureState se serializa a JSON como su valor
    ## ENTERO (Enabled=2), asi que la comparacion contra "Enabled" fallaba
    ## siempre y este check (SMBv1 = EternalBlue/WannaCry) nunca detectaba nada.
    data = run_ps_json(
        "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue "
        "| Select-Object @{Name='State';Expression={[string]$_.State}}"
    )
    ## Fallback adicional: en Windows sin la caracteristica opcional (Server core
    ## viejo) se consulta la config del servidor SMB directamente.
    server_cfg = run_ps_json("Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol")

    state = str(data.get("State")) if data else None
    server_smb1 = bool(server_cfg.get("EnableSMB1Protocol")) if server_cfg else None

    if state is None and server_smb1 is None:
        return CheckResult(
            check_id="smb_v1",
            title="Protocolo SMBv1 habilitado",
            category="Falta de actualizaciones y parches",
            severity=Severity.CRITICAL,
            vulnerable=False,
            determinable=False,
            detail="No se pudo determinar el estado de SMBv1 (requiere permisos de administrador o no aplica a este SO).",
            recommendation="Verificar manualmente con: Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            fixable=False,
        )

    enabled = state == "Enabled" or server_smb1 is True
    pending = state in ("DisablePending", "EnablePending")

    if pending:
        detail = f"SMBv1 quedo en estado '{state}': la caracteristica se deshabilito pero REQUIERE REINICIO para completarse; hasta reiniciar SMBv1 puede seguir negociable."
    elif enabled:
        detail = "SMBv1 esta habilitado en este equipo."
    else:
        detail = "SMBv1 no esta habilitado."

    return CheckResult(
        check_id="smb_v1",
        title="Protocolo SMBv1 habilitado",
        category="Falta de actualizaciones y parches",
        severity=Severity.CRITICAL,
        vulnerable=enabled or pending,
        detail=detail,
        recommendation=(
            "Deshabilitar SMBv1: es un protocolo obsoleto sin soporte, explotado "
            "por malware/ransomware conocido (ej. WannaCry via EternalBlue). "
            + ("Reinicie el equipo para completar la desactivacion." if pending else "")
        ),
        fixable=not pending,
    )


def fix_smbv1():
    ## Dos pasos: (1) Set-SmbServerConfiguration detiene la negociacion SMB1 del
    ## SERVIDOR en caliente (sin reinicio) -> cierra el hallazgo del scanner de
    ## inmediato; (2) Disable-WindowsOptionalFeature remueve la caracteristica
    ## (requiere reinicio para completarse).
    hot = run_ps("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force")
    proc = run_ps("Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart")
    ok = hot.returncode == 0 or proc.returncode == 0
    if ok:
        message = (
            "SMBv1 deshabilitado en el servidor SMB en caliente (deja de negociarse de inmediato) "
            "y caracteristica marcada para remocion (requiere reinicio para completarse del todo)."
        )
    else:
        message = (hot.stderr or proc.stderr or proc.stdout or "No se pudo deshabilitar SMBv1.").strip()[:400]
    undo = (
        "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force; "
        "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart  # NO recomendado: SMBv1 es inseguro"
    )
    return ok, message, undo


def check_smb_signing() -> CheckResult:
    data = run_ps_json("Get-SmbServerConfiguration | Select-Object RequireSecuritySignature")
    if data is None:
        return CheckResult(
            check_id="smb_signing",
            title="Firma SMB no obligatoria",
            category="Riesgo de fuerza bruta / configuraciones por defecto",
            severity=Severity.MEDIUM,
            vulnerable=False,
            determinable=False,
            detail="No se pudo determinar la configuracion de firma SMB.",
            recommendation="Verificar manualmente con: Get-SmbServerConfiguration",
            fixable=False,
        )

    required = bool(data.get("RequireSecuritySignature"))
    return CheckResult(
        check_id="smb_signing",
        title="Firma SMB no obligatoria",
        category="Riesgo de fuerza bruta / configuraciones por defecto",
        severity=Severity.MEDIUM,
        vulnerable=not required,
        detail="RequireSecuritySignature = False" if not required else "RequireSecuritySignature = True",
        recommendation="Exigir firma SMB para mitigar ataques de relay/MITM (SMB Relay) dentro de la red local.",
        fixable=True,
    )


def fix_smb_signing():
    proc = run_ps("Set-SmbServerConfiguration -RequireSecuritySignature $true -Force")
    ok = proc.returncode == 0
    message = (proc.stdout or proc.stderr or "").strip()[:400] or "Firma SMB requerida activada."
    undo = "Set-SmbServerConfiguration -RequireSecuritySignature $false -Force  # NO recomendado"
    return ok, message, undo
