"""Verificacion del Firewall de Windows (perfiles Domain/Private/Public)."""
from __future__ import annotations

from ..models import CheckResult, Severity
from ..ps import run_ps, run_ps_json

# Get-NetFirewallProfile expone DefaultInboundAction como un enum
# (NotConfigured=0/Allow=2/Block=4), pero ConvertTo-Json lo serializa como
# su valor ENTERO subyacente, no el nombre (verificado en vivo). Un perfil
# puede estar Enabled=True y aun asi permitir TODO el trafico entrante por
# defecto si DefaultInboundAction=Allow -- CIS Benchmark/Nessus lo marcan
# como firewall "activo pero abierto de par en par", y antes este check no
# lo detectaba (solo miraba Enabled).
_DEFAULT_INBOUND_ALLOW = 2


def check_firewall() -> CheckResult:
    data = run_ps_json("Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction")
    if data is None:
        return CheckResult(
            check_id="firewall_profiles",
            title="Firewall de Windows deshabilitado o permitiendo entrantes por defecto",
            category="Gestion de dispositivos (MDM) y agentes",
            severity=Severity.HIGH,
            vulnerable=False,
            determinable=False,
            detail="No se pudo consultar el estado del firewall.",
            recommendation="Verificar manualmente con: Get-NetFirewallProfile",
            fixable=False,
        )

    profiles = data if isinstance(data, list) else [data]
    disabled = [p.get("Name") for p in profiles if not p.get("Enabled")]
    allow_inbound = [
        p.get("Name") for p in profiles
        if p.get("Enabled") and p.get("DefaultInboundAction") == _DEFAULT_INBOUND_ALLOW
    ]
    vulnerable = bool(disabled) or bool(allow_inbound)

    detail_parts = []
    if disabled:
        detail_parts.append(f"Perfiles deshabilitados: {', '.join(disabled)}.")
    if allow_inbound:
        detail_parts.append(
            f"Perfiles 'activos' pero con DefaultInboundAction=Allow (permiten entrante por defecto): {', '.join(allow_inbound)}."
        )
    detail = " ".join(detail_parts) if detail_parts else "Todos los perfiles de firewall estan activos y bloqueando entrante por defecto."

    return CheckResult(
        check_id="firewall_profiles",
        title="Firewall de Windows deshabilitado o permitiendo entrantes por defecto",
        category="Gestion de dispositivos (MDM) y agentes",
        severity=Severity.HIGH,
        vulnerable=vulnerable,
        detail=detail,
        recommendation="Mantener el Firewall de Windows activo en los tres perfiles (Dominio, Privado, Publico) con DefaultInboundAction en Block.",
        fixable=True,
    )


def fix_firewall():
    proc = run_ps("Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block")
    ok = proc.returncode == 0
    message = (
        "Firewall activado en todos los perfiles, con bloqueo de entrante por defecto." if ok
        else (proc.stderr or proc.stdout or "No se pudo aplicar el cambio.").strip()[:400]
    )
    undo = "Set-NetFirewallProfile -All -Enabled False -DefaultInboundAction NotConfigured  # NO recomendado: deja el equipo sin firewall"
    return ok, message, undo


# Puertos entrantes de acceso remoto de terceros / texto plano que conviene
# bloquear en un host que corre SOLO el hardening local (sin GPO de dominio).
# Cubre el mismo set que la regla SEC-10 del GPO. NO incluye RDP (3389): esa
# es una decision de negocio que se maneja aparte (firewall con scoping).
_RAT_BLOCK_RULE = "Hardening-Bloquear-Acceso-Remoto-No-Autorizado"
_RAT_BLOCK_PORTS = "23,5900,5901,5938,7070,6568"


def check_rat_ports_blocked() -> CheckResult:
    existing = run_ps_json(
        f"Get-NetFirewallRule -DisplayName '{_RAT_BLOCK_RULE}' -ErrorAction SilentlyContinue "
        "| Select-Object -First 1 @{Name='Enabled';Expression={[string]$_.Enabled}}"
    )
    already = existing is not None
    return CheckResult(
        check_id="rat_ports_blocked",
        title="Puertos de acceso remoto de terceros no bloqueados por firewall (Telnet/VNC/TeamViewer/AnyDesk)",
        category="Conexiones remotas no autorizadas/expuestas",
        severity=Severity.MEDIUM,
        vulnerable=not already,
        detail=(
            "Ya existe una regla de firewall que bloquea Telnet/VNC/TeamViewer/AnyDesk entrantes."
            if already else
            f"No hay regla de firewall que bloquee entrantes los puertos {_RAT_BLOCK_PORTS} "
            "(Telnet/VNC/TeamViewer/AnyDesk). En un host no unido al dominio (sin el GPO SEC-10), "
            "un scanner los ve abiertos si algun servicio los usa."
        ),
        recommendation=(
            "Crear una regla de firewall entrante Block para esos puertos. Para control real del RAT "
            "(que ademas sale por 443 hacia relays) complementar con AppLocker/SRP."
        ),
        fixable=not already,
    )


def fix_rat_ports_blocked():
    proc = run_ps(
        f"New-NetFirewallRule -DisplayName '{_RAT_BLOCK_RULE}' -Direction Inbound -Action Block "
        f"-Protocol TCP -LocalPort {_RAT_BLOCK_PORTS} -Profile Any"
    )
    ok = proc.returncode == 0
    message = (
        f"Regla de firewall creada: bloquea entrantes {_RAT_BLOCK_PORTS} (Telnet/VNC/TeamViewer/AnyDesk)."
        if ok else (proc.stderr or proc.stdout or "No se pudo crear la regla.").strip()[:400]
    )
    undo = f"Remove-NetFirewallRule -DisplayName '{_RAT_BLOCK_RULE}'  # revierte el bloqueo de esos puertos"
    return ok, message, undo
