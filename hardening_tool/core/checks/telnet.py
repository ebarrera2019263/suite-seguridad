"""Verificacion del servidor Telnet de Windows (texto plano, sin cifrar)."""
from __future__ import annotations

from ..models import CheckResult, Severity
from ..ps import run_ps, run_ps_json


def check_telnet_server() -> CheckResult:
    ## State debe castearse a [string] del lado PowerShell: el enum FeatureState
    ## se serializa como entero (Enabled=2) y la comparacion contra "Enabled"
    ## fallaba siempre (mismo bug que en smb.py).
    data = run_ps_json(
        "Get-WindowsOptionalFeature -Online -FeatureName TelnetServer -ErrorAction SilentlyContinue "
        "| Select-Object @{Name='State';Expression={[string]$_.State}}"
    )
    if data is None:
        return CheckResult(
            check_id="telnet_server",
            title="Servidor Telnet instalado",
            category="Conexiones remotas no autorizadas/expuestas",
            severity=Severity.CRITICAL,
            vulnerable=False,
            determinable=False,
            detail="No se pudo determinar si el servidor Telnet esta instalado.",
            recommendation="Verificar manualmente con: Get-WindowsOptionalFeature -Online -FeatureName TelnetServer",
            fixable=False,
        )

    enabled = str(data.get("State")) in ("Enabled", "EnablePending")
    return CheckResult(
        check_id="telnet_server",
        title="Servidor Telnet instalado",
        category="Conexiones remotas no autorizadas/expuestas",
        severity=Severity.CRITICAL,
        vulnerable=enabled,
        detail="El servidor Telnet esta instalado y habilitado." if enabled else "El servidor Telnet no esta habilitado.",
        recommendation=(
            "Deshabilitar el servidor Telnet: transmite credenciales y datos en texto "
            "plano, interceptables por cualquiera en la misma red (sniffing)."
        ),
        fixable=True,
    )


def fix_telnet_server():
    proc = run_ps("Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer -NoRestart")
    ok = proc.returncode == 0
    run_ps("Stop-Service TlntSvr -ErrorAction SilentlyContinue; Set-Service TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue")
    message = "Servidor Telnet deshabilitado." if ok else (proc.stderr or proc.stdout or "").strip()[:400]
    undo = "Enable-WindowsOptionalFeature -Online -FeatureName TelnetServer -NoRestart  # NO recomendado: Telnet es inseguro"
    return ok, message, undo
