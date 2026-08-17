"""Reportes: consola (rich), JSON y HTML. Contienen credenciales en texto
plano cuando se encuentran -- es el objetivo explicito de esta
herramienta (validar politica de contrasenas), pero por eso cada reporte
lleva un aviso de manejo seguro bien visible."""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table

from .models import HostCredentialReport

_OUTCOME_COLOR = {
    "cracked": "bold white on red",
    "locked": "bold yellow",
    "denied": "cyan",
    "not_found": "green",
    "unreachable": "dim",
    "error": "dim",
}


def print_console_report(hosts: List[HostCredentialReport], console: Console) -> None:
    table = Table(title="Resultado de validacion de credenciales")
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("SO")
    table.add_column("Usuario")
    table.add_column("Resultado")
    table.add_column("Contrasena")
    table.add_column("Intentos")
    table.add_column("Protocolo")

    for h in hosts:
        if not h.alive:
            table.add_row(h.ip, "-", "-", "-", "[dim]sin respuesta[/dim]", "-", "-", "-")
            continue
        if not h.attempts:
            table.add_row(h.ip, h.hostname or "-", h.os_exact or h.os_guess or "-", "-", "[dim]sin intentos[/dim]", "-", "-", "-")
            continue
        for a in h.attempts:
            color = _OUTCOME_COLOR.get(a.outcome, "white")
            pass_display = a.password if a.outcome == "cracked" else "-"
            table.add_row(
                h.ip, h.hostname or "-", h.os_exact or h.os_guess or "-",
                a.username, f"[{color}]{a.outcome}[/{color}]",
                pass_display, str(a.attempts_made), a.protocol or "-",
            )

    console.print(table)

    cracked = sum(1 for h in hosts for a in h.attempts if a.outcome == "cracked")
    locked = sum(1 for h in hosts for a in h.attempts if a.outcome == "locked")
    console.print(
        f"\n[bold]Resumen:[/bold] {cracked} credencial(es) debil(es) encontrada(s), "
        f"{locked} cuenta(s) bloqueada(s) por la politica durante la prueba.\n"
    )
    if cracked:
        console.print("[bold red]El reporte generado contiene contrasenas en texto plano. Manejelo como secreto y rotelas de inmediato.[/bold red]\n")


def export_json(hosts: List[HostCredentialReport], output_path: str) -> None:
    payload = {
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "aviso": "Este reporte puede contener contrasenas en texto plano. Manejar como secreto.",
        "resumen": {
            "hosts_analizados": len(hosts),
            "credenciales_debiles_encontradas": sum(1 for h in hosts for a in h.attempts if a.outcome == "cracked"),
            "cuentas_bloqueadas_durante_la_prueba": sum(1 for h in hosts for a in h.attempts if a.outcome == "locked"),
        },
        "resultados": [h.to_dict() for h in hosts],
    }
    Path(output_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def export_html(hosts: List[HostCredentialReport], output_path: str) -> None:
    cracked_total = sum(1 for h in hosts for a in h.attempts if a.outcome == "cracked")
    locked_total = sum(1 for h in hosts for a in h.attempts if a.outcome == "locked")

    rows = []
    for h in hosts:
        if not h.alive:
            continue
        for a in h.attempts:
            pass_display = _esc(a.password) if a.outcome == "cracked" else "-"
            row_color = "#7f1d1d" if a.outcome == "cracked" else ("#b45309" if a.outcome == "locked" else "#111827")
            rows.append(
                f"<tr style='background:{row_color}'>"
                f"<td>{_esc(h.ip)}</td><td>{_esc(h.hostname or '-')}</td>"
                f"<td>{_esc(h.os_exact or h.os_guess or '-')}</td>"
                f"<td>{_esc(a.username)}</td><td>{_esc(a.outcome)}</td>"
                f"<td><b>{pass_display}</b></td>"
                f"<td>{_esc(a.strength_label or '-')}</td><td>{_esc(a.strength_notes or '-')}</td>"
                f"<td>{a.attempts_made}</td><td>{_esc(a.protocol or '-')}</td>"
                "</tr>"
            )
        for w in h.wifi_findings:
            rows.append(
                "<tr style='background:#7f1d1d'>"
                f"<td>{_esc(h.ip)}</td><td>{_esc(h.hostname or '-')}</td><td>WiFi</td>"
                f"<td>SSID: {_esc(w.ssid)}</td><td>perfil guardado</td>"
                f"<td><b>{_esc(w.password or '-')}</b></td>"
                f"<td>{_esc(w.strength_label)}</td><td>{_esc(w.strength_notes)}</td>"
                "<td>-</td><td>WiFi (remoto)</td>"
                "</tr>"
            )

    css = """
    body{font-family:Segoe UI,Arial,sans-serif;background:#0b1220;color:#e5e7eb;margin:0;padding:24px;}
    h1{color:#f9fafb;} .warn{background:#7f1d1d;color:#fff;padding:12px 16px;border-radius:8px;font-weight:600;margin:12px 0;}
    table{border-collapse:collapse;width:100%;margin-top:12px;background:#111827;}
    th,td{border:1px solid #374151;padding:8px 10px;font-size:13px;text-align:left;vertical-align:top;}
    th{background:#1f2937;color:#f9fafb;}
    .summary-grid{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0;}
    .stat{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:12px 18px;min-width:160px;}
    .stat b{display:block;font-size:22px;}
    footer{color:#6b7280;margin-top:32px;font-size:12px;}
    """

    document = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Validacion de Credenciales</title>
<style>{css}</style></head>
<body>
<h1>Validacion de Politica de Contrasenas</h1>
<div class="warn">ADVERTENCIA: este documento contiene contrasenas reales en texto plano. Almacenelo cifrado, compartalo solo con quien deba verlo, y rote de inmediato cualquier contrasena listada aqui.</div>
<div class="summary-grid">
  <div class="stat"><span>Equipos analizados</span><b>{len(hosts)}</b></div>
  <div class="stat"><span>Credenciales debiles</span><b style="color:#ef4444">{cracked_total}</b></div>
  <div class="stat"><span>Cuentas bloqueadas (politica funciono)</span><b style="color:#f59e0b">{locked_total}</b></div>
</div>
<table>
<thead><tr><th>IP</th><th>Hostname</th><th>SO</th><th>Usuario/SSID</th><th>Resultado</th><th>Contrasena</th><th>Fortaleza</th><th>Notas</th><th>Intentos</th><th>Protocolo</th></tr></thead>
<tbody>{"".join(rows) if rows else "<tr><td colspan='10'>Sin hallazgos.</td></tr>"}</tbody>
</table>
<footer>Generado por Credential Audit Tool. Uso exclusivo sobre equipos designados para pruebas, con autorizacion explicita.</footer>
</body></html>"""

    Path(output_path).write_text(document, encoding="utf-8")
