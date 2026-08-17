"""Reportes: consola (rich), JSON y HTML para el equipo local analizado."""
from __future__ import annotations

import html
import json
import socket
from datetime import datetime
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table

from .models import CheckResult, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def print_console_summary(results: List[CheckResult], console: Console) -> None:
    table = Table(title=f"Diagnostico local — {socket.gethostname()}")
    table.add_column("Severidad")
    table.add_column("Categoria")
    table.add_column("Hallazgo")
    table.add_column("Estado")
    table.add_column("Correccion")

    ordered = sorted(results, key=lambda r: (not r.vulnerable, -r.severity.rank))
    for r in ordered:
        if r.vulnerable:
            estado = f"[{r.severity.color}]VULNERABLE[/{r.severity.color}]"
        elif not r.determinable:
            estado = "[dim]No verificable[/dim]"
        else:
            estado = "[green]OK[/green]"

        if not r.vulnerable:
            correccion = "-"
        elif r.manual_only:
            correccion = "[yellow]Manual[/yellow]"
        elif r.fix_applied is True:
            correccion = "[green]Aplicada[/green]"
        elif r.fix_applied is False:
            correccion = "[red]Fallo[/red]"
        else:
            correccion = "[dim]Omitida[/dim]"

        table.add_row(r.severity.value, r.category, r.title, estado, correccion)

    console.print(table)

    vulnerable_count = sum(1 for r in results if r.vulnerable)
    fixed_count = sum(1 for r in results if r.fix_applied is True)
    console.print(
        f"\n[bold]Resumen:[/bold] {len(results)} verificaciones, "
        f"{vulnerable_count} hallazgos, {fixed_count} corregidos en esta sesion.\n"
    )


def export_json(results: List[CheckResult], output_path: str) -> None:
    payload = {
        "equipo": socket.gethostname(),
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "resumen": {
            "total_verificaciones": len(results),
            "hallazgos": sum(1 for r in results if r.vulnerable),
            "corregidos_en_esta_sesion": sum(1 for r in results if r.fix_applied is True),
        },
        "resultados": [r.to_dict() for r in results],
    }
    Path(output_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def export_html(results: List[CheckResult], output_path: str) -> None:
    hostname = socket.gethostname()
    vulnerable = [r for r in results if r.vulnerable]
    fixed = sum(1 for r in results if r.fix_applied is True)
    sev_totals = {s: 0 for s in SEVERITY_ORDER}
    for r in vulnerable:
        sev_totals[r.severity] += 1

    rows = []
    ordered = sorted(results, key=lambda r: (not r.vulnerable, -r.severity.rank))
    for r in ordered:
        color = r.severity.hex if r.vulnerable else "#374151"
        estado = "VULNERABLE" if r.vulnerable else ("No verificable" if not r.determinable else "OK")
        if not r.vulnerable:
            correccion = "-"
        elif r.manual_only:
            correccion = "Manual"
        elif r.fix_applied is True:
            correccion = "Aplicada"
        elif r.fix_applied is False:
            correccion = "Fallo"
        else:
            correccion = "Omitida"

        rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{color}'>{_esc(r.severity.value)}</span></td>"
            f"<td>{_esc(r.category)}</td>"
            f"<td>{_esc(r.title)}</td>"
            f"<td>{_esc(estado)}</td>"
            f"<td>{_esc(correccion)}</td>"
            f"<td>{_esc(r.detail)}</td>"
            f"<td>{_esc(r.recommendation)}</td>"
            f"<td>{_esc(r.fix_message or '-')}</td>"
            "</tr>"
        )

    css = """
    body{font-family:Segoe UI,Arial,sans-serif;background:#0b1220;color:#e5e7eb;margin:0;padding:24px;}
    h1{color:#f9fafb;} h2{color:#f3f4f6;margin-top:32px;}
    .subtitle{color:#9ca3af;margin-top:-8px;}
    table{border-collapse:collapse;width:100%;margin-top:12px;background:#111827;}
    th,td{border:1px solid #374151;padding:8px 10px;font-size:13px;text-align:left;vertical-align:top;}
    th{background:#1f2937;color:#f9fafb;}
    tr:nth-child(even){background:#151f2e;}
    .badge{color:white;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap;}
    .summary-grid{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0;}
    .stat{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:12px 18px;min-width:140px;}
    .stat b{display:block;font-size:22px;}
    footer{color:#6b7280;margin-top:32px;font-size:12px;}
    """

    stats_html = "".join(
        f"<div class='stat'><span>{_esc(s.value)}</span><b style='color:{s.hex}'>{sev_totals[s]}</b></div>"
        for s in SEVERITY_ORDER
    )

    document = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Diagnostico de Endurecimiento Local</title>
<style>{css}</style></head>
<body>
<h1>Diagnostico de Endurecimiento Local</h1>
<p class="subtitle">Equipo: {_esc(hostname)} | Verificaciones: {len(results)} | Hallazgos: {len(vulnerable)} | Corregidos en esta sesion: {fixed}</p>
<div class="summary-grid">{stats_html}</div>

<h2>Detalle de verificaciones</h2>
<table>
<thead><tr><th>Severidad</th><th>Categoria</th><th>Verificacion</th><th>Estado</th><th>Correccion</th><th>Detalle</th><th>Recomendacion</th><th>Resultado de la correccion</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>

<footer>Generado por IP Hardening Tool. Herramienta de uso local exclusivo: solo audita y corrige el equipo en el que se ejecuta.</footer>
</body></html>"""

    Path(output_path).write_text(document, encoding="utf-8")
