#!/usr/bin/env python
"""
Credential Audit Tool
=======================
Herramienta para VALIDAR (no para atacar) si la politica de contrasenas
de la organizacion resistiria intentos de adivinacion basicos. Prueba una
lista curada y pequena de contrasenas debiles/comunes contra CUENTAS
LOCALES (no de dominio) de los equipos indicados, via SMB ('net use') y
WinRM. Si encuentra una contrasena valida, evalua su fortaleza y, con esa
misma credencial, intenta obtener el sistema operativo exacto y las
contrasenas WiFi ya guardadas en ese equipo.

USO EXCLUSIVO AUTORIZADO: esta herramienta realiza intentos de
autenticacion REALES contra los equipos indicados. Eso PUEDE bloquear
cuentas segun la politica configurada (de hecho, un bloqueo durante la
prueba es una senal POSITIVA: significa que la politica esta funcionando).
Use esta herramienta unicamente contra equipos designados explicitamente
para esta prueba (por ejemplo, maquinas dejadas a proposito con
vulnerabilidades para validar la remediacion), nunca contra la poblacion
general de usuarios de la organizacion sin coordinacion previa con IT.

Por diseno, solo prueba cuentas LOCALES ('\\\\IP\\usuario'), nunca cuentas
de dominio: asi, si se bloquea una cuenta, el impacto queda limitado a esa
maquina puntual y no afecta el acceso de nadie mas en la organizacion.
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from core import inventory, smb_cred, winrm_cred
from core.models import CredentialAttemptResult, HostCredentialReport, WifiFinding
from core.report import export_html, export_json, print_console_report
from core.strength import evaluate_password
from core.wordlist import load_usernames, load_wordlist

BANNER = r"""
CREDENTIAL AUDIT TOOL
Validacion REAL de politica de contrasenas -- cuentas locales unicamente
"""

_SCOPE_WARNING_THRESHOLD = 5


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Valida la fortaleza real de contrasenas locales y WiFi contra equipos designados para prueba.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=BANNER,
    )
    src = parser.add_mutually_exclusive_group(required=False)
    src.add_argument("--targets", help="IPs separadas por coma, o un rango CIDR (usar con extremo cuidado).")
    src.add_argument("--file", help="Archivo de texto con una IP por linea.")
    parser.add_argument("--users", default="", help="Usuarios locales a probar, separados por coma (siempre se incluye Administrator).")
    parser.add_argument("--users-file", default="", help="Archivo con un usuario local por linea.")
    parser.add_argument("--wordlist", default="", help="Archivo de contrasenas propio (si no se indica, usa la lista curada incorporada).")
    parser.add_argument("--delay", type=float, default=2.0, help="Segundos de espera entre intentos sobre la MISMA cuenta (default: 2.0)")
    parser.add_argument("--max-attempts", type=int, default=0, help="Maximo de contrasenas a probar por cuenta (0 = usar toda la lista)")
    parser.add_argument("--threads", type=int, default=4, help="Equipos analizados en paralelo (default: 4; los intentos DENTRO de una cuenta son siempre secuenciales)")
    parser.add_argument("--output-dir", default="reportes_credenciales", help="Carpeta de salida (default: reportes_credenciales)")
    parser.add_argument("--yes", action="store_true", help="Omite la confirmacion etica interactiva (recomendado solo en pipelines ya autorizados)")
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


def expand_targets(raw: List[str]) -> List[str]:
    ips: List[str] = []
    for token in raw:
        token = token.strip()
        if not token:
            continue
        try:
            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                ips.extend(str(ip) for ip in network.hosts())
            else:
                ipaddress.ip_address(token)
                ips.append(token)
        except ValueError:
            print(f"[!] Objetivo invalido ignorado: {token}", file=sys.stderr)
    seen, deduped = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    return deduped


def run_interactive_wizard(console: Console, args: argparse.Namespace) -> bool:
    console.print("[cyan]Modo interactivo (sin argumentos).[/cyan]\n")
    targets = console.input("IPs de las maquinas de PRUEBA designadas (separadas por coma): ").strip()
    if not targets:
        console.print("[red]No se ingreso ningun objetivo. Cancelando.[/red]")
        return False
    args.targets = targets

    users = console.input("Usuarios locales a probar, separados por coma [Administrator]: ").strip()
    args.users = users

    return True


def _is_interactive() -> bool:
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False


def confirm_authorization(console: Console, skip_prompt: bool) -> bool:
    if skip_prompt:
        return True
    if not _is_interactive():
        console.print(
            "[red]Se requiere confirmacion de autorizacion y no hay una consola interactiva "
            "disponible. Vuelva a ejecutar con --yes si ya esta autorizado (p.ej. en un pipeline).[/red]"
        )
        return False
    console.print(
        "\n[bold white on red] AVISO LEGAL Y ETICO [/bold white on red]\n"
        "[bold yellow]Esta herramienta realiza intentos de inicio de sesion REALES.[/bold yellow]\n"
        "Puede bloquear cuentas locales de los equipos indicados si la politica de "
        "bloqueo esta activa (eso es una senal POSITIVA, no un error). Use esta "
        "herramienta UNICAMENTE contra equipos explicitamente designados para esta "
        "prueba, con autorizacion, y nunca contra la poblacion general de usuarios.\n"
    )
    try:
        answer = console.input("Escriba EXACTAMENTE 'confirmo autorizacion' para continuar: ")
    except EOFError:
        return False
    return answer.strip().lower() == "confirmo autorizacion"


def confirm_scope(console: Console, target_count: int, skip_prompt: bool) -> bool:
    if target_count <= _SCOPE_WARNING_THRESHOLD or skip_prompt:
        return True
    if not _is_interactive():
        console.print(
            f"[red]{target_count} equipos resueltos supera el umbral de confirmacion y no hay "
            "consola interactiva disponible. Use --yes solo si ya reviso el alcance.[/red]"
        )
        return False
    console.print(
        f"\n[bold white on red] {target_count} equipos resueltos como objetivo. [/bold white on red]\n"
        "Esto supera el umbral de alcance chico esperado para una prueba puntual de "
        "'maquinas dejadas a proposito con vulnerabilidades'. Verifique que no se le "
        "haya colado un rango CIDR mas amplio de lo previsto.\n"
    )
    try:
        answer = console.input(f"Escriba el numero exacto de equipos ({target_count}) para confirmar que es correcto: ")
    except EOFError:
        return False
    return answer.strip() == str(target_count)


def crack_host(ip: str, usernames: List[str], wordlist: List[str], delay_s: float, max_attempts: int) -> HostCredentialReport:
    report = HostCredentialReport(ip=ip)
    inv = inventory.gather_inventory(ip)
    report.alive = inv["alive"]
    report.mac = inv["mac"]
    report.hostname = inv["hostname"]
    report.os_guess = inv["os_guess"]

    if not report.alive:
        return report

    limit = max_attempts if max_attempts > 0 else None
    got_working_cred = None  # (username, password) para la cosecha post-crack

    for username in usernames:
        outcome, password, attempts = smb_cred.crack_smb_account(ip, username, wordlist, delay_s, limit)
        protocol = "SMB"

        ## Se reintenta por WinRM salvo que SMB ya haya dado un resultado propio
        ## concluyente (cuenta encontrada/bloqueada/deshabilitada). Antes solo
        ## se reintentaba en 'not_found': si el 445 estaba cerrado (SMB da
        ## 'unreachable') o el equipo fuerza ACCESS_DENIED para todo (SMB da
        ## 'denied'), la cuenta quedaba sin verificar aunque WinRM si respondiera.
        if outcome in ("not_found", "unreachable", "denied"):
            outcome2, password2, attempts2 = winrm_cred.crack_winrm_account(ip, username, wordlist, delay_s, limit)
            if outcome2 != "unreachable":
                outcome, password, attempts, protocol = outcome2, password2, attempts + attempts2, "WinRM"

        result = CredentialAttemptResult(username=username, outcome=outcome, password=password, attempts_made=attempts, protocol=protocol)
        if outcome == "cracked":
            ## from_known_weak_list=True: se adivino de la wordlist, es critica
            ## por definicion (la composicion sola diria 'Media' para algo como
            ## 'Verano2026!', lo que contradiria el hecho de haberla crackeado).
            label, notes = evaluate_password(password, username, from_known_weak_list=True)
            result.strength_label = label
            result.strength_notes = notes
            if got_working_cred is None:
                got_working_cred = (username, password)
        report.attempts.append(result)

    if got_working_cred:
        username, password = got_working_cred
        harvested = winrm_cred.harvest_via_winrm(ip, username, password)
        if not harvested:
            harvested = winrm_cred.get_os_via_cim(ip, username, password)

        if harvested:
            if harvested.get("Hostname"):
                report.hostname = report.hostname or harvested.get("Hostname")
            if harvested.get("OSCaption"):
                report.os_exact = f"{harvested.get('OSCaption')} ({harvested.get('OSVersion', '')})".strip()
            for wp in harvested.get("WifiProfiles", []) or []:
                ssid = wp.get("SSID")
                pwd = wp.get("Password")
                if not ssid:
                    continue
                if pwd:
                    label, notes = evaluate_password(pwd, "")
                else:
                    label, notes = "Info", "Perfil sin contrasena guardada u oculta (requiere privilegios)."
                report.wifi_findings.append(WifiFinding(ssid=ssid, password=pwd, strength_label=label, strength_notes=notes))
        else:
            report.errors.append("No se pudo cosechar SO exacto / perfiles WiFi (WinRM y WMI/DCOM no disponibles o sin permisos).")

    return report


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    console = Console()
    console.print(BANNER, style="bold red")

    if not args.targets and not args.file:
        if not _should_pause(args):
            console.print("[red]Faltan objetivos. Use --targets o --file.[/red]")
            return 1
        if not run_interactive_wizard(console, args):
            _pause(console)
            return 1

    if not confirm_authorization(console, args.yes):
        console.print("[red]Operacion cancelada: autorizacion no confirmada.[/red]")
        if _should_pause(args):
            _pause(console)
        return 1

    raw_targets = Path(args.file).read_text(encoding="utf-8").splitlines() if args.file else args.targets.split(",")
    targets = expand_targets(raw_targets)
    if not targets:
        console.print("[red]No se resolvieron objetivos validos.[/red]")
        return 1

    if not confirm_scope(console, len(targets), args.yes):
        console.print("[red]Alcance no confirmado. Cancelando.[/red]")
        if _should_pause(args):
            _pause(console)
        return 1

    usernames = load_usernames(args.users, args.users_file or None)
    wordlist = load_wordlist(args.wordlist or None)
    max_attempts = args.max_attempts if args.max_attempts > 0 else 0

    console.print(
        f"\n[bold]{len(targets)}[/bold] equipo(s), [bold]{len(usernames)}[/bold] usuario(s) por equipo, "
        f"[bold]{len(wordlist)}[/bold] contrasena(s) por usuario, delay [bold]{args.delay}s[/bold] entre intentos.\n"
    )

    reports: List[HostCredentialReport] = []
    with Progress(
        TextColumn("[progress.description]{task.description}"), BarColumn(),
        TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(), console=console,
    ) as progress:
        task_id = progress.add_task("Validando credenciales...", total=len(targets))
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
            futures = {
                executor.submit(crack_host, ip, usernames, wordlist, args.delay, max_attempts): ip
                for ip in targets
            }
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    reports.append(future.result())
                except Exception as exc:
                    console.print(f"[red]Error en {ip}: {exc}[/red]")
                    reports.append(HostCredentialReport(ip=ip, errors=[str(exc)]))
                progress.advance(task_id)

    reports.sort(key=lambda r: tuple(int(p) for p in r.ip.split(".")) if r.ip.count(".") == 3 else (0,))
    print_console_report(reports, console)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = output_dir / f"credenciales_{timestamp}.json"
    html_path = output_dir / f"credenciales_{timestamp}.html"
    export_json(reports, str(json_path))
    export_html(reports, str(html_path))
    console.print(f"[green]Reporte JSON:[/green] {json_path}")
    console.print(f"[green]Reporte HTML:[/green] {html_path}")
    console.print("[bold yellow]Recuerde: si se encontraron contrasenas debiles, rotelas de inmediato y proteja este reporte.[/bold yellow]")

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
