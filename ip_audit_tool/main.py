#!/usr/bin/env python
"""
IP Security Audit Tool
=======================
Herramienta de auditoria de seguridad para redes internas: descubre hosts,
levanta inventario (IP/MAC/hostname/SO), identifica servicios y puertos
expuestos, y correlaciona hallazgos con una base local de configuraciones
riesgosas y versiones vulnerables conocidas.

USO ETICO OBLIGATORIO: ejecute esta herramienta unicamente sobre redes y
equipos de su propiedad o para los que cuente con autorizacion explicita
por escrito. El uso no autorizado contra sistemas de terceros puede ser
ilegal en su jurisdiccion.

Ejemplos:
    python main.py --targets 192.168.1.0/24
    python main.py --targets 10.0.0.5,10.0.0.6,10.0.0.10
    python main.py --file ips.txt --output-dir reportes --threads 30
"""
from __future__ import annotations

import argparse
import ctypes
import ipaddress
import platform
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

# El core de auditoria de IP es un paquete COMPARTIDO en la raiz del repo
# (ip_audit_core/), consumido tanto por este CLI como por la GUI (suite_gui),
# para no mantener dos copias que se desincronizan. Al ejecutar desde el
# codigo fuente hay que anadir la raiz del repo al path; ya empaquetado con
# PyInstaller el paquete viaja en el bundle y esta insercion es inocua.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ip_audit_core.host_analyzer import analyze_host
from ip_audit_core.models import HostResult
from ip_audit_core.report import export_html, export_json, export_pdf, print_console_report
from ip_audit_core.vuln_db import DEFAULT_PORT_LIST

BANNER = r"""
IP SECURITY AUDIT TOOL
Auditoria de seguridad de red - Uso exclusivo autorizado
"""


def is_windows_admin() -> bool:
    if platform.system().lower() != "windows":
        return True  # asumimos permisos suficientes en *nix; se valida con os.geteuid si hace falta
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def expand_targets(raw_targets: List[str]) -> List[str]:
    ips: List[str] = []
    for token in raw_targets:
        token = token.strip()
        if not token:
            continue
        try:
            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                ips.extend(str(ip) for ip in network.hosts())
            elif "-" in token and token.count(".") == 3:
                # Rango tipo 192.168.1.10-20 (ultimo octeto)
                base, end = token.rsplit("-", 1)
                base_ip = ipaddress.ip_address(base)
                prefix = ".".join(base.split(".")[:3])
                start_octet = int(base.split(".")[-1])
                end_octet = int(end)
                if start_octet > end_octet:
                    print(f"[!] Rango invertido ignorado: {token}", file=sys.stderr)
                    continue
                for octet in range(start_octet, end_octet + 1):
                    ips.append(f"{prefix}.{octet}")
            else:
                ipaddress.ip_address(token)
                ips.append(token)
        except ValueError:
            print(f"[!] Objetivo invalido ignorado: {token}", file=sys.stderr)
    # dedupe preservando orden
    seen = set()
    deduped = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    return deduped


def load_targets_from_file(path: str) -> List[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    tokens = [line.split("#", 1)[0].strip() for line in lines]
    return [t for t in tokens if t]


def parse_ports(ports_arg: str) -> List[int]:
    if not ports_arg:
        return DEFAULT_PORT_LIST
    result = []
    for part in ports_arg.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if start > end:
                    print(f"[!] Rango de puertos invertido ignorado: {part}", file=sys.stderr)
                    continue
                result.extend(range(start, end + 1))
            else:
                result.append(int(part))
        except ValueError:
            print(f"[!] Puerto/rango invalido ignorado: {part}", file=sys.stderr)
    if not result:
        print("[!] --ports no dejo ningun puerto valido; usando la lista por defecto.", file=sys.stderr)
        return DEFAULT_PORT_LIST
    return sorted(set(result))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Auditoria de seguridad para redes internas (IP/MAC/hostname/SO, puertos, TLS, SSH, exposicion).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=BANNER,
    )
    src = parser.add_mutually_exclusive_group(required=False)
    src.add_argument("--targets", help="IPs, CIDR o rangos separados por coma. Ej: 192.168.1.0/24,10.0.0.5")
    src.add_argument("--file", help="Archivo de texto con una IP/CIDR/rango por linea (ips.txt)")
    parser.add_argument(
        "dropped_file",
        nargs="?",
        default=None,
        help=argparse.SUPPRESS,  # permite arrastrar un ips.txt sobre el .exe
    )

    parser.add_argument("--ports", default="", help="Lista/rango de puertos personalizados (ej: 22,80,443,1000-1010). Por defecto usa un set curado.")
    parser.add_argument("--threads", type=int, default=20, help="Numero de hosts analizados en paralelo (default: 20)")
    parser.add_argument("--port-timeout", type=float, default=0.9, help="Timeout por puerto en segundos (default: 0.9)")
    parser.add_argument("--output-dir", default="reportes", help="Carpeta de salida para JSON/HTML (default: reportes)")
    parser.add_argument("--formats", default="json,html,pdf", help="Formatos de exportacion separados por coma (json,html,pdf)")
    parser.add_argument("--skip-mac", action="store_true", help="Omite la resolucion de MAC (evita requerir privilegios elevados)")
    parser.add_argument("--no-console-table", action="store_true", help="No imprimir las tablas detalladas en consola")
    parser.add_argument("--yes", action="store_true", help="Omite la confirmacion etica interactiva")
    parser.add_argument("--no-pause", action="store_true", help="No esperar Enter al finalizar (util para scripts/CI)")
    # Chequeos activos adicionales (opt-in). Estan DESACTIVADOS por defecto para
    # conservar el comportamiento historico del CLI y porque son mas intrusivos:
    # requieren autorizacion explicita sobre la aplicacion/servicio objetivo.
    parser.add_argument("--web-sqli", action="store_true", help="Activa el sondeo NO destructivo de inyeccion SQL (error-based) sobre puertos web abiertos.")
    parser.add_argument("--ddos-exposure", action="store_true", help="Comprueba exposicion a DDoS por amplificacion (envia 1 paquete UDP por servicio; no inunda).")
    parser.add_argument("--connectivity", action="store_true", help="Ejecuta una prueba de conectividad blackbox (ICMP/TCP/UDP acotada) como hallazgo informativo.")
    return parser


def run_interactive_wizard(console: Console, args: argparse.Namespace) -> bool:
    """Se activa cuando el .exe se abre con doble clic (sin argumentos).
    Pregunta lo minimo indispensable en la propia consola. Devuelve False
    si el usuario cancela."""
    console.print(
        "[cyan]No se recibieron argumentos: iniciando modo interactivo.[/cyan]\n"
        "(Tambien puede usar esta herramienta desde una terminal con "
        "argumentos, ej: IPSecurityAuditTool.exe --targets 192.168.1.0/24 "
        "--help)\n"
    )
    targets = console.input(
        "Ingrese IP(s), rango CIDR o rango (ej: 192.168.1.0/24 o "
        "192.168.1.10,192.168.1.20): "
    ).strip()
    if not targets:
        console.print("[red]No se ingreso ningun objetivo. Cancelando.[/red]")
        return False
    args.targets = targets

    skip_mac_answer = console.input("¿Omitir resolucion de MAC (no requiere ser Administrador)? [s/N]: ")
    args.skip_mac = skip_mac_answer.strip().lower() in ("s", "si", "y", "yes")

    out_dir = console.input(f"Carpeta de salida para reportes [{args.output_dir}]: ").strip()
    if out_dir:
        args.output_dir = out_dir

    return True


def confirm_authorization(skip_prompt: bool) -> bool:
    if skip_prompt:
        return True
    console = Console()
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        interactive = False
    if not interactive:
        console.print(
            "[red]Se requiere confirmacion de autorizacion y no hay una consola interactiva "
            "disponible. Vuelva a ejecutar con --yes si ya esta autorizado (p.ej. en un pipeline).[/red]"
        )
        return False
    console.print(
        "\n[bold yellow]AVISO LEGAL Y ETICO[/bold yellow]\n"
        "Esta herramienta debe usarse UNICAMENTE sobre redes/equipos propios "
        "o con autorizacion explicita por escrito. El uso no autorizado "
        "puede constituir un delito.\n"
    )
    try:
        answer = console.input("¿Confirma que cuenta con autorizacion para escanear estos objetivos? [s/N]: ")
    except EOFError:
        return False
    return answer.strip().lower() in ("s", "si", "y", "yes")


def _should_pause(args: argparse.Namespace) -> bool:
    """Evita que la ventana del .exe se cierre de golpe al abrirlo con doble
    clic (o al fallar). Solo pausa si hay una consola interactiva real."""
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


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    console = Console()
    console.print(BANNER, style="bold cyan")

    # Soporta arrastrar un ips.txt sobre el .exe (llega como argumento posicional).
    if args.dropped_file and not args.targets and not args.file:
        args.file = args.dropped_file

    if not args.targets and not args.file:
        if not _should_pause(args):
            console.print(
                "[red]Faltan objetivos. Use --targets o --file (--help para ver todas las opciones).[/red]"
            )
            return 1
        if not run_interactive_wizard(console, args):
            _pause(console)
            return 1

    if not confirm_authorization(args.yes):
        console.print("[red]Operacion cancelada: autorizacion no confirmada.[/red]")
        if _should_pause(args):
            _pause(console)
        return 1

    if not args.skip_mac and not is_windows_admin():
        console.print(
            "[yellow]Aviso:[/yellow] no se detectaron privilegios de administrador. "
            "La resolucion de direcciones MAC puede fallar o ser incompleta. "
            "Ejecute como administrador o use --skip-mac para omitir este aviso."
        )

    raw_targets = load_targets_from_file(args.file) if args.file else args.targets.split(",")
    targets = expand_targets(raw_targets)
    if not targets:
        console.print("[red]No se resolvieron objetivos validos.[/red]")
        return 1

    ports = parse_ports(args.ports)

    ## Cada host analizado abre a su vez su propio pool de hilos para el
    ## escaneo de puertos (ver scanner.scan_ports): con --threads alto y
    ## muchos puertos, el numero de hilos concurrentes en el pico es
    ## args.threads * min(100, len(ports)), pudiendo agotar recursos del
    ## sistema. Se limita a un techo razonable en vez de confiar en que el
    ## usuario nunca pase un valor extremo.
    max_sensible_threads = 64
    if args.threads > max_sensible_threads:
        console.print(
            f"[yellow]--threads {args.threads} es muy alto (cada host abre ademas su propio "
            f"pool de hasta {min(100, len(ports))} hilos para puertos); se limita a "
            f"{max_sensible_threads} para evitar agotar recursos.[/yellow]"
        )
        args.threads = max_sensible_threads

    console.print(f"[bold]{len(targets)}[/bold] objetivos a analizar, [bold]{len(ports)}[/bold] puertos por host, [bold]{args.threads}[/bold] hilos.\n")

    results: List[HostResult] = []
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Analizando hosts...", total=len(targets))
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
            futures = {
                executor.submit(
                    analyze_host,
                    ip,
                    ports,
                    args.port_timeout,
                    2.0,
                    3.0,
                    4.0,
                    args.skip_mac,
                    args.web_sqli,
                    args.ddos_exposure,
                    args.connectivity,
                ): ip
                for ip in targets
            }
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    console.print(f"[red]Error analizando {ip}: {exc}[/red]")
                    results.append(HostResult(ip=ip, errors=[str(exc)]))
                progress.advance(task_id)

    results.sort(key=lambda r: tuple(int(p) for p in r.ip.split(".")) if r.ip.count(".") == 3 else (0,))

    if not args.no_console_table:
        print_console_report(results, console=console)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    formats = {f.strip().lower() for f in args.formats.split(",") if f.strip()}

    if "json" in formats:
        json_path = output_dir / f"reporte_{timestamp}.json"
        export_json(results, str(json_path))
        console.print(f"[green]Reporte JSON:[/green] {json_path}")

    if "html" in formats:
        html_path = output_dir / f"reporte_{timestamp}.html"
        export_html(results, str(html_path))
        console.print(f"[green]Reporte HTML:[/green] {html_path}")

    if "pdf" in formats:
        pdf_path = output_dir / f"reporte_{timestamp}.pdf"
        export_pdf(results, str(pdf_path))
        console.print(f"[green]Reporte PDF:[/green] {pdf_path}")

    if _should_pause(args):
        _pause(console)

    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except SystemExit as exc:
        # argparse llama sys.exit() en errores de parseo (p.ej. flag invalida)
        # o al mostrar --help (code 0). Solo pausamos en errores reales, para
        # que el usuario vea el mensaje si vino de un doble clic.
        is_error = exc.code not in (0, None)
        if is_error and "--no-pause" not in sys.argv and sys.stdin is not None and sys.stdin.isatty():
            try:
                Console().input("\nPresione Enter para salir...")
            except Exception:
                pass
        raise exc
    except Exception as exc:  # pragma: no cover - ultima red de seguridad
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
