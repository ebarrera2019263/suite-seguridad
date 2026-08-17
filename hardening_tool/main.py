#!/usr/bin/env python
"""
IP Hardening Tool (local)
==========================
Herramienta de endurecimiento (hardening) LOCAL: audita la configuracion
de seguridad del equipo Windows en el que se ejecuta y, con confirmacion
explicita del usuario para cada cambio, corrige lo que encuentra mal
configurado (SMBv1, firma SMB, NLA de RDP, Firewall, protocolos/cifrados
TLS obsoletos, servidor Telnet, algoritmos SSH debiles, cuenta Guest, UAC,
credenciales de autologon, LLMNR/NetBIOS, WinRM inseguro, Windows
Defender). Tambien reporta (sin corregir automaticamente) actualizaciones
pendientes y software de acceso remoto de terceros instalado.

LIMITE DE ALCANCE (por diseno): esta herramienta SOLO puede leer y
modificar la configuracion del equipo local en el que se ejecuta. No
acepta direcciones IP, nombres de host remotos, ni tiene ninguna
funcionalidad de red hacia otras maquinas.

USO ETICO OBLIGATORIO: ejecute esta herramienta unicamente en equipos de
su propiedad o de los que sea administrador autorizado. Modificar
configuracion de seguridad de un sistema sin autorizacion puede ser
ilegal, y algunos cambios (firewall, RDP, WinRM) pueden afectar el acceso
remoto al propio equipo si no se revisan con cuidado.
"""
from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from rich.console import Console

from core import admin, restore
from core.checks import (
    accounts,
    defender,
    firewall,
    network_exposure,
    rdp,
    remote_tools,
    smb,
    ssh,
    telnet,
    tls,
    updates,
    winrm,
)
from core.models import CheckResult, Severity
from core.report import export_html, export_json, print_console_summary

BANNER = r"""
IP HARDENING TOOL (local)
Diagnostico y correccion de configuracion de seguridad del equipo local
"""

# Cada entrada: (funcion_de_verificacion, funcion_de_correccion_o_None)
CHECK_REGISTRY: List[Tuple[Callable[[], CheckResult], Optional[Callable]]] = [
    (smb.check_smbv1, smb.fix_smbv1),
    (smb.check_smb_signing, smb.fix_smb_signing),
    (rdp.check_rdp_nla, rdp.fix_rdp_nla),
    (rdp.check_rdp_enabled, None),
    (firewall.check_firewall, firewall.fix_firewall),
    (firewall.check_rat_ports_blocked, firewall.fix_rat_ports_blocked),
    (tls.check_obsolete_tls_protocols, tls.fix_obsolete_tls_protocols),
    (tls.check_weak_cipher_suites, tls.fix_weak_cipher_suites),
    (telnet.check_telnet_server, telnet.fix_telnet_server),
    (ssh.check_ssh_weak_algorithms, ssh.fix_ssh_weak_algorithms),
    (accounts.check_guest_account, accounts.fix_guest_account),
    (accounts.check_uac, accounts.fix_uac),
    (accounts.check_autologon_password, accounts.fix_autologon_password),
    (network_exposure.check_llmnr, network_exposure.fix_llmnr),
    (network_exposure.check_netbios, network_exposure.fix_netbios),
    (winrm.check_winrm, winrm.fix_winrm),
    (defender.check_defender_realtime, defender.fix_defender_realtime),
    (updates.check_pending_updates, None),
    (remote_tools.check_remote_access_software, None),
]

# Checks cuya correccion puede afectar sesiones remotas activas; si se
# detecta una sesion RDP, se pide una confirmacion reforzada adicional.
_HIGH_IMPACT_IDS = {"firewall_profiles", "rdp_nla", "winrm_basic_auth"}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Diagnostico y correccion de configuracion de seguridad del equipo LOCAL (sin alcance de red).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=BANNER,
    )
    parser.add_argument("--dry-run", action="store_true", help="Solo diagnostica y genera reporte; no ofrece aplicar ninguna correccion.")
    parser.add_argument("--yes", action="store_true", help="Omite la confirmacion etica interactiva inicial (las correcciones individuales se siguen confirmando una por una salvo --dry-run).")
    parser.add_argument("--skip-restore-point", action="store_true", help="No intentar crear un punto de restauracion antes de aplicar correcciones.")
    parser.add_argument("--no-elevate", action="store_true", help="No intentar relanzar el proceso como Administrador automaticamente.")
    parser.add_argument("--output-dir", default="reportes_hardening", help="Carpeta de salida para JSON/HTML/script de reversion (default: reportes_hardening)")
    parser.add_argument("--no-pause", action="store_true", help="No esperar Enter al finalizar (util para scripts/CI)")
    return parser


def _should_pause(args: argparse.Namespace) -> bool:
    if args.no_pause:
        return False
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False


def _pause(console: Console) -> None:
    try:
        console.input("\nPresione Enter para salir...")
    except Exception:
        pass


def confirm_authorization(console: Console, skip_prompt: bool) -> bool:
    if skip_prompt:
        return True
    console.print(
        "\n[bold yellow]AVISO LEGAL Y ETICO[/bold yellow]\n"
        "Esta herramienta MODIFICA la configuracion de seguridad de ESTE equipo "
        "(el que la esta ejecutando). No tiene ninguna capacidad de red hacia "
        "otras maquinas. Usela solo en equipos propios o con autorizacion "
        "explicita como administrador.\n"
    )
    answer = console.input("¿Confirma que esta autorizado para modificar la configuracion de este equipo? [s/N]: ")
    return answer.strip().lower() in ("s", "si", "y", "yes")


def run_checks(console: Console) -> List[CheckResult]:
    results: List[CheckResult] = []
    with console.status("Ejecutando verificaciones locales..."):
        for check_fn, _ in CHECK_REGISTRY:
            try:
                results.append(check_fn())
            except Exception as exc:
                results.append(
                    CheckResult(
                        check_id=getattr(check_fn, "__name__", "desconocido"),
                        title=f"Error al ejecutar verificacion {check_fn.__name__}",
                        category="Error interno",
                        severity=Severity.INFO,
                        vulnerable=False,
                        determinable=False,
                        detail=str(exc),
                        recommendation="Reintentar manualmente la verificacion correspondiente.",
                        fixable=False,
                    )
                )
    return results


def apply_fixes_interactively(console: Console, args: argparse.Namespace, results: List[CheckResult]) -> List[Tuple[str, str]]:
    """Recorre los hallazgos corregibles, pide confirmacion uno por uno y
    aplica la correccion si el usuario acepta. Devuelve la lista de
    (titulo, comando_de_reversion) de lo efectivamente aplicado."""
    undo_entries: List[Tuple[str, str]] = []

    fixable_findings = [
        (result, fix_fn)
        for result, (_, fix_fn) in zip(results, CHECK_REGISTRY)
        if result.vulnerable and not result.manual_only and result.fixable and fix_fn is not None
    ]
    fixable_findings.sort(key=lambda pair: pair[0].severity.rank, reverse=True)

    if not fixable_findings:
        console.print("[green]No hay correcciones automaticas pendientes para confirmar.[/green]")
        return undo_entries

    remote = admin.is_remote_session()
    console.print(f"\n[bold]{len(fixable_findings)}[/bold] hallazgo(s) con correccion automatica disponible.\n")

    for result, fix_fn in fixable_findings:
        console.print(f"[{result.severity.color}]{result.severity.value}[/{result.severity.color}] — [bold]{result.title}[/bold]")
        console.print(f"  Detalle: {result.detail}")
        console.print(f"  Recomendacion: {result.recommendation}")

        if remote and result.check_id in _HIGH_IMPACT_IDS:
            console.print(
                "  [bold red]Advertencia:[/bold red] esta sesion parece ser remota (RDP). "
                "Este cambio (firewall/RDP/WinRM) podria afectar el acceso remoto actual."
            )
            confirm_word = console.input("  Escriba EXACTAMENTE 'confirmo' para aplicar este cambio, o presione Enter para omitir: ")
            apply_it = confirm_word.strip().lower() == "confirmo"
        else:
            answer = console.input("  ¿Aplicar esta correccion ahora? [s/N]: ")
            apply_it = answer.strip().lower() in ("s", "si", "y", "yes")

        if not apply_it:
            console.print("  [dim]Omitido.[/dim]\n")
            continue

        try:
            ok, message, undo_cmd = fix_fn()
        except Exception as exc:
            ok, message, undo_cmd = False, f"Excepcion al aplicar la correccion: {exc}", "# no aplicable"

        result.fix_applied = ok
        result.fix_message = message
        result.undo_hint = undo_cmd
        if ok:
            console.print(f"  [green]Aplicada:[/green] {message}\n")
            undo_entries.append((result.title, undo_cmd))
        else:
            console.print(f"  [red]No se pudo aplicar:[/red] {message}\n")
            ## Un fix_* que hace varios pasos puede fallar en general (ok=False)
            ## aunque alguno de sus pasos SI haya modificado el sistema
            ## realmente (ver p.ej. fix_obsolete_tls_protocols, fix_winrm,
            ## fix_autologon_password). Se registra igual el undo -- salvo el
            ## caso explicito de "no se aplico nada" -- para no perder la
            ## posibilidad de revertir un cambio parcial real.
            if undo_cmd and undo_cmd not in ("# no aplicable", "# nada que deshacer"):
                undo_entries.append((f"{result.title} (aplicacion PARCIAL o fallida — revisar)", undo_cmd))

    return undo_entries


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    console = Console()
    console.print(BANNER, style="bold cyan")

    if platform.system().lower() != "windows":
        console.print("[red]Esta herramienta solo es compatible con Windows.[/red]")
        return 1

    if not admin.is_admin():
        console.print(
            "[yellow]Se requieren privilegios de Administrador para diagnosticar y "
            "corregir la configuracion de este equipo.[/yellow]"
        )
        if args.no_elevate or not _should_pause(args):
            console.print("[red]Ejecute esta herramienta como Administrador (clic derecho > 'Ejecutar como administrador').[/red]")
            return 1
        answer = console.input("¿Reiniciar ahora como Administrador (se pedira confirmacion de Windows/UAC)? [S/n]: ")
        if answer.strip().lower() in ("", "s", "si", "y", "yes"):
            if admin.relaunch_as_admin():
                console.print("[cyan]Reiniciando como Administrador...[/cyan]")
                return 0
            console.print("[red]No se pudo relanzar como Administrador. Ejecute manualmente el .exe como Administrador.[/red]")
            _pause(console)
            return 1
        console.print("[red]No se puede continuar sin privilegios de Administrador.[/red]")
        _pause(console)
        return 1

    if admin.is_remote_session():
        console.print(
            "[yellow]Aviso:[/yellow] esta sesion parece haber llegado por Escritorio "
            "Remoto (RDP). Tenga cuidado con los cambios de Firewall/RDP/WinRM: podrian "
            "cortar esta misma sesion. Asegurese de tener otra forma de acceso "
            "(consola local, iDRAC/iLO, etc.) antes de aplicarlos.\n"
        )

    if not confirm_authorization(console, args.yes):
        console.print("[red]Operacion cancelada: autorizacion no confirmada.[/red]")
        if _should_pause(args):
            _pause(console)
        return 1

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.dry_run and not args.skip_restore_point:
        create_rp = console.input("¿Crear un punto de restauracion de Windows antes de continuar? [S/n]: ")
        if create_rp.strip().lower() in ("", "s", "si", "y", "yes"):
            ok, message = restore.create_restore_point()
            color = "green" if ok else "yellow"
            console.print(f"[{color}]{message}[/{color}]\n")

    results = run_checks(console)
    print_console_summary(results, console)

    undo_entries: List[Tuple[str, str]] = []
    if args.dry_run:
        console.print("[cyan]Modo --dry-run: no se ofrecio aplicar ninguna correccion.[/cyan]")
    else:
        undo_entries = apply_fixes_interactively(console, args, results)

    manual_findings = [r for r in results if r.vulnerable and r.manual_only]
    if manual_findings:
        console.print("\n[bold]Hallazgos que requieren revision manual (no se corrigen automaticamente):[/bold]")
        for r in manual_findings:
            console.print(f"  - [{r.severity.color}]{r.severity.value}[/{r.severity.color}] {r.title}: {r.recommendation}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = output_dir / f"diagnostico_{timestamp}.json"
    html_path = output_dir / f"diagnostico_{timestamp}.html"
    export_json(results, str(json_path))
    export_html(results, str(html_path))
    console.print(f"\n[green]Reporte JSON:[/green] {json_path}")
    console.print(f"[green]Reporte HTML:[/green] {html_path}")

    if undo_entries:
        undo_path = restore.write_undo_script(output_dir, undo_entries)
        console.print(f"[green]Script de reversion:[/green] {undo_path}")

    if _should_pause(args):
        _pause(console)

    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except SystemExit as exc:
        is_error = exc.code not in (0, None)
        if is_error and "--no-pause" not in sys.argv and sys.stdin is not None and sys.stdin.isatty():
            try:
                Console().input("\nPresione Enter para salir...")
            except Exception:
                pass
        raise exc
    except Exception as exc:  # pragma: no cover
        console = Console()
        console.print(f"\n[bold red]Error inesperado:[/bold red] {exc}")
        if "--no-pause" not in sys.argv and sys.stdin is not None and sys.stdin.isatty():
            try:
                console.input("\nPresione Enter para salir...")
            except Exception:
                pass
        sys.exit(1)
    else:
        sys.exit(exit_code)
