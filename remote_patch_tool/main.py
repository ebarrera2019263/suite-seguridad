#!/usr/bin/env python
"""
Remote Patch Tool
===================
Herramienta puntual: se le indica UNA direccion IP y aplica, de forma
remota via WinRM (Invoke-Command), dos correcciones especificas:

  1. Bloquear RDP (regla de firewall, TCP 3389 entrante). No desinstala
     ni deshabilita el servicio, solo bloquea el puerto -- reversible con
     --undo. WinRM (5985/5986) se deja intacto a proposito para que esta
     misma herramienta pueda seguir alcanzando el equipo despues.
  2. Forzar TLS mas seguro: deshabilita explicitamente SSLv2/SSLv3/
     TLS1.0/TLS1.1 y las suites de cifrado debiles (RC4/DES/3DES/MD5/
     EXPORT/NULL).

REQUISITOS: el equipo objetivo debe tener WinRM habilitado y accesible
(GPO/`Enable-PSRemoting` habitual en entornos de dominio), y quien ejecuta
esta herramienta debe tener permisos de administrador en ese equipo
(de la sesion actual, o credenciales alternativas que se piden al vuelo).

USO EXCLUSIVO AUTORIZADO: modifica configuracion de seguridad de un
equipo que NO es el que ejecuta la herramienta. Uselo solo contra equipos
de su organizacion, con autorizacion, y verifique primero que bloquear
RDP no es la unica via de acceso remoto a ese equipo.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console

from core import local_ip, remote_ps

BANNER = r"""
REMOTE PATCH TOOL
Bloqueo remoto de RDP + endurecimiento remoto de TLS -- una IP a la vez
"""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bloquea RDP y endurece TLS de forma remota (WinRM) en UNA maquina indicada por IP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=BANNER,
    )
    parser.add_argument("--ip", default="", help="IP de la maquina objetivo (si se omite, se pregunta).")
    parser.add_argument("--undo", action="store_true", help="En vez de aplicar, revierte block_rdp y harden_tls en la IP indicada.")
    parser.add_argument("--yes", action="store_true", help="Omite la confirmacion etica inicial (las acciones individuales se siguen confirmando salvo que tambien use --skip-confirms).")
    parser.add_argument("--skip-confirms", action="store_true", help="No pedir confirmacion por cada accion (usar solo en automatizacion ya autorizada).")
    parser.add_argument("--output-dir", default="reportes_remotos", help="Carpeta de salida para el reporte (default: reportes_remotos)")
    parser.add_argument("--no-pause", action="store_true", help="No esperar Enter al finalizar")
    return parser


def _should_pause(args) -> bool:
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


def _prompt_ip(console: Console) -> str:
    while True:
        raw = console.input("IP de la maquina objetivo (remota, NO esta maquina): ").strip()
        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            console.print("[red]No es una IP valida.[/red]")


def confirm_authorization(console: Console, skip_prompt: bool) -> bool:
    if skip_prompt:
        return True
    console.print(
        "\n[bold white on red] AVISO LEGAL Y ETICO [/bold white on red]\n"
        "Esta herramienta modifica de forma REMOTA la configuracion de un equipo "
        "que no es el suyo (firewall + registro TLS). Use esta herramienta solo "
        "contra equipos de su organizacion, con autorizacion, y confirme que "
        "bloquear RDP no es la unica via de acceso remoto a ese equipo.\n"
    )
    answer = console.input("Escriba EXACTAMENTE 'confirmo autorizacion' para continuar: ")
    return answer.strip().lower() == "confirmo autorizacion"


def confirm_action(console: Console, prompt: str, skip: bool) -> bool:
    if skip:
        return True
    answer = console.input(f"{prompt} [s/N]: ")
    return answer.strip().lower() in ("s", "si", "y", "yes")


def _revalidate_connectivity(console: Console, results: dict, action_key: str, ip: str, username, password) -> None:
    """Vuelve a probar WinRM inmediatamente despues de aplicar un cambio: es
    la unica forma con la que esta herramienta puede confirmar, en el
    momento, que el cambio no corto el propio canal de gestion hacia el
    equipo -- antes no se volvia a probar nada despues de aplicar, y un
    corte de conectividad (p.ej. por una politica que reaplica firewall al
    reiniciar, o un WinRM-HTTPS que dejo de negociar tras el cambio de
    SCHANNEL) recien se notaba la proxima vez que hiciera falta entrar.
    Esto NO es un rollback automatico (no hay auto-reversion programada en
    el equipo remoto si la conectividad se pierde de verdad), solo deteccion
    inmediata."""
    console.print("[dim]Revalidando conectividad WinRM tras el cambio...[/dim]")
    ok, msg, data = remote_ps.test_connectivity(ip, username, password)
    results[f"{action_key}_post_check"] = {"ok": ok, "mensaje": msg, "detalle": data}
    if ok:
        console.print("[green]Conectividad WinRM confirmada despues del cambio.[/green]\n")
    else:
        console.print(
            f"[bold white on red] ALERTA: no se pudo confirmar conectividad WinRM despues de aplicar el cambio ({msg}). [/bold white on red]\n"
            "El cambio pudo haberse aplicado igual (revise el reporte), pero esta herramienta ya no puede "
            "verificarlo ni revertirlo automaticamente desde aca. Intente reconectar por otra via "
            "(consola local, iDRAC/iLO, otro admin) antes de asumir que el equipo esta bien.\n"
        )


def run_apply(console: Console, args: argparse.Namespace, ip: str, username, password) -> dict:
    results = {}

    if confirm_action(console, "¿Bloquear RDP (TCP 3389 entrante) en este equipo?", args.skip_confirms):
        ok, msg, data = remote_ps.block_rdp(ip, username, password)
        results["block_rdp"] = {"ok": ok, "mensaje": msg, "detalle": data}
        if ok:
            console.print(f"[green]RDP bloqueado.[/green] {data.get('Detail') if data else ''}")
            _revalidate_connectivity(console, results, "block_rdp", ip, username, password)
        else:
            console.print(f"[red]No se pudo bloquear RDP:[/red] {msg}")
    else:
        console.print("[dim]Bloqueo de RDP omitido.[/dim]")

    if confirm_action(console, "¿Forzar TLS mas seguro (deshabilitar SSLv2/SSLv3/TLS1.0/1.1 y cifrados debiles)?", args.skip_confirms):
        ok, msg, data = remote_ps.harden_tls(ip, username, password)
        results["harden_tls"] = {"ok": ok, "mensaje": msg, "detalle": data}
        if ok:
            console.print(f"[green]TLS endurecido.[/green] {data.get('Detail') if data else ''}")
            console.print("[yellow]Puede requerir reiniciar el equipo remoto para completarse del todo.[/yellow]")
            if data and data.get("CipherSuiteCmdletAvailable") is False:
                console.print(
                    "[dim]Nota:[/dim] este equipo remoto no soporta Get-TlsCipherSuite (Windows < 2016); "
                    "los cifrados debiles se cerraron por registro (fallback), no por nombre de suite."
                )
            _revalidate_connectivity(console, results, "harden_tls", ip, username, password)
        else:
            console.print(f"[red]No se pudo endurecer TLS:[/red] {msg}")
    else:
        console.print("[dim]Endurecimiento de TLS omitido.[/dim]")

    return results


def run_undo(console: Console, args: argparse.Namespace, ip: str, username, password) -> dict:
    results = {}
    if confirm_action(console, "¿Revertir el bloqueo de RDP en este equipo?", args.skip_confirms):
        ok, msg, data = remote_ps.undo_block_rdp(ip, username, password)
        results["undo_block_rdp"] = {"ok": ok, "mensaje": msg, "detalle": data}
        console.print(f"[green]OK:[/green] {data.get('Detail')}" if ok else f"[red]Fallo:[/red] {msg}")

    if confirm_action(console, "¿Revertir el endurecimiento de TLS en este equipo?", args.skip_confirms):
        ok, msg, data = remote_ps.undo_harden_tls(ip, username, password)
        results["undo_harden_tls"] = {"ok": ok, "mensaje": msg, "detalle": data}
        console.print(f"[green]OK:[/green] {data.get('Detail')}" if ok else f"[red]Fallo:[/red] {msg}")

    return results


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    console = Console()
    console.print(BANNER, style="bold red")

    ip = args.ip.strip() if args.ip else ""
    if not ip:
        if not _should_pause(args):
            console.print("[red]Falta --ip.[/red]")
            return 1
        ip = _prompt_ip(console)
    else:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            console.print(f"[red]--ip invalida: {ip}[/red]")
            return 1

    is_local, enum_reliable = local_ip.is_local_target(ip)
    if is_local:
        console.print(
            f"[bold white on red] {ip} parece ser ESTA MISMA maquina. [/bold white on red]\n"
            "No se puede continuar: bloquearse el propio RDP de forma remota puede dejarlo "
            "sin acceso. Ejecute esta herramienta desde OTRO equipo para modificar este."
        )
        if _should_pause(args):
            _pause(console)
        return 1
    if not enum_reliable:
        # Fallar CERRADO: si ningun metodo de deteccion de IP local funciono
        # (sin salida de red, o PowerShell no disponible/restringido), antes
        # se asumia silenciosamente que el objetivo no era esta maquina y se
        # continuaba igual -- exactamente el escenario que esta guarda existe
        # para prevenir.
        console.print(
            f"[bold white on red] No se pudo verificar de forma confiable si {ip} es esta misma maquina. [/bold white on red]\n"
            "Ningun metodo de deteccion de IP local funciono en este equipo (sin salida de "
            "red, o PowerShell no disponible/restringido). Por seguridad, esta herramienta "
            "no continua sin poder descartar que el objetivo sea este mismo equipo.\n"
            "Verifique la conectividad de red de ESTE equipo y reintente."
        )
        if _should_pause(args):
            _pause(console)
        return 1

    if not confirm_authorization(console, args.yes):
        console.print("[red]Operacion cancelada: autorizacion no confirmada.[/red]")
        if _should_pause(args):
            _pause(console)
        return 1

    username = None
    password = None
    if _should_pause(args):
        use_alt = console.input("¿Usar credenciales distintas a la sesion actual? [s/N]: ")
        if use_alt.strip().lower() in ("s", "si", "y", "yes"):
            username = console.input("Usuario (ej. DOMINIO\\usuario): ").strip()
            password = getpass.getpass("Contrasena: ")

    console.print(f"\n[bold]Probando conectividad WinRM con {ip}...[/bold]")
    ok, msg, data = remote_ps.test_connectivity(ip, username, password)
    if not ok:
        console.print(f"[red]No se pudo conectar: {msg}[/red]")
        console.print("[yellow]Verifique que WinRM este habilitado en el equipo objetivo (Enable-PSRemoting) y que el firewall permita el puerto 5985/5986.[/yellow]")
        if _should_pause(args):
            _pause(console)
        return 1
    console.print(f"[green]Conectado.[/green] Host remoto: {data.get('Hostname')}, usuario efectivo: {data.get('EffectiveUser')}\n")

    if args.undo:
        results = run_undo(console, args, ip, username, password)
    else:
        results = run_apply(console, args, ip, username, password)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"parche_remoto_{ip.replace('.', '-')}_{timestamp}.json"
    import json
    report_path.write_text(
        json.dumps({"ip": ip, "fecha": datetime.now().isoformat(timespec="seconds"), "modo": "undo" if args.undo else "apply", "resultados": results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    console.print(f"\n[green]Reporte:[/green] {report_path}")
    if not args.undo:
        console.print(
            f"[dim]Para revertir estos cambios en {ip}: vuelva a ejecutar esta herramienta con --ip {ip} --undo[/dim]"
        )

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
    except Exception as exc:
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
