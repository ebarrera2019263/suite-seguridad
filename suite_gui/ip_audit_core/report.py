"""Generacion de reportes: consola (rich), JSON, HTML y PDF."""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from .models import HostResult, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_MESES_ES = {
    1: "enero", 2: "febrero", 3: "marzo", 4: "abril", 5: "mayo", 6: "junio",
    7: "julio", 8: "agosto", 9: "septiembre", 10: "octubre", 11: "noviembre", 12: "diciembre",
}


def _fecha_larga_es(moment: Optional[datetime] = None) -> str:
    moment = moment or datetime.now()
    return f"{moment.day} de {_MESES_ES[moment.month]} de {moment.year}"


def print_console_report(results: List[HostResult], console: Console = None) -> None:
    console = console or Console()

    summary = Table(title="Inventario de Activos", show_lines=False)
    summary.add_column("IP", style="bold")
    summary.add_column("Estado")
    summary.add_column("Hostname")
    summary.add_column("MAC")
    summary.add_column("SO estimado")
    summary.add_column("Tipo")
    summary.add_column("Puertos abiertos")
    summary.add_column("Vulns")

    for r in results:
        estado = "[green]Activo[/green]" if r.alive else "[dim]Sin respuesta[/dim]"
        vulns_txt = str(len(r.vulnerabilities)) if r.alive else "-"
        summary.add_row(
            r.ip,
            estado,
            r.hostname or r.netbios_name or "-",
            r.mac or "-",
            r.os_guess or "-",
            r.device_type,
            ", ".join(str(p) for p in r.open_ports) or "-",
            vulns_txt,
        )
    console.print(summary)

    for r in results:
        if not r.alive or not r.vulnerabilities:
            continue
        vt = Table(title=f"Hallazgos en {r.ip} ({r.hostname or r.netbios_name or 'sin nombre'})")
        vt.add_column("Severidad")
        vt.add_column("Categoria")
        vt.add_column("Puerto")
        vt.add_column("Titulo")
        vt.add_column("CVE(s)")

        ordered = sorted(r.vulnerabilities, key=lambda v: v.severity.rank, reverse=True)
        for v in ordered:
            vt.add_row(
                f"[{v.severity.color}]{v.severity.value}[/{v.severity.color}]",
                v.category,
                str(v.port) if v.port else "-",
                v.title,
                ", ".join(v.cve_refs) or "-",
            )
        console.print(vt)

    total_vulns = sum(len(r.vulnerabilities) for r in results)
    hosts_alive = sum(1 for r in results if r.alive)
    console.print(
        f"\n[bold]Resumen:[/bold] {hosts_alive}/{len(results)} hosts activos, "
        f"{total_vulns} hallazgos totales.\n"
    )


def export_json(results: List[HostResult], output_path: str) -> None:
    payload = {
        "resultados": [r.to_dict() for r in results],
        "resumen": {
            "total_hosts": len(results),
            "hosts_activos": sum(1 for r in results if r.alive),
            "total_vulnerabilidades": sum(len(r.vulnerabilities) for r in results),
        },
    }
    Path(output_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


_SEVERITY_HEX = {
    Severity.CRITICAL: "#7f1d1d",
    Severity.HIGH: "#b91c1c",
    Severity.MEDIUM: "#b45309",
    Severity.LOW: "#0e7490",
    Severity.INFO: "#4b5563",
}


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def export_html(results: List[HostResult], output_path: str, title: str = "Reporte de Auditoria de Seguridad") -> None:
    hosts_alive = sum(1 for r in results if r.alive)
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    sev_totals = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for v in r.vulnerabilities:
            sev_totals[v.severity] += 1

    rows_summary = []
    for r in results:
        estado = "Activo" if r.alive else "Sin respuesta"
        rows_summary.append(
            f"<tr><td>{_esc(r.ip)}</td><td>{_esc(estado)}</td><td>{_esc(r.hostname or r.netbios_name or '-')}</td>"
            f"<td>{_esc(r.mac or '-')}</td><td>{_esc(r.os_guess or '-')}</td><td>{_esc(r.device_type)}</td>"
            f"<td>{_esc(', '.join(str(p) for p in r.open_ports) or '-')}</td>"
            f"<td>{len(r.vulnerabilities) if r.alive else '-'}</td></tr>"
        )

    host_sections = []
    for r in results:
        if not r.alive:
            continue
        vuln_rows = []
        ordered = sorted(r.vulnerabilities, key=lambda v: v.severity.rank, reverse=True)
        for v in ordered:
            color = _SEVERITY_HEX[v.severity]
            vuln_rows.append(
                "<tr>"
                f"<td><span class='badge' style='background:{color}'>{_esc(v.severity.value)}</span></td>"
                f"<td>{_esc(v.category)}</td>"
                f"<td>{_esc(v.port) if v.port else '-'}</td>"
                f"<td>{_esc(v.title)}</td>"
                f"<td>{_esc(v.description)}</td>"
                f"<td>{_esc(v.evidence or '-')}</td>"
                f"<td>{_esc(', '.join(v.cve_refs) or '-')}</td>"
                f"<td>{_esc(v.recommendation)}</td>"
                "</tr>"
            )
        services_rows = "".join(
            f"<li><b>{p}</b> ({_esc(s.name)}): {_esc((s.banner or '')[:180])}</li>"
            for p, s in sorted(r.services.items())
        )
        if not vuln_rows:
            vuln_table = "<p class='muted'>Sin hallazgos para este host.</p>"
        else:
            vuln_table = (
                "<table class='vulns'><thead><tr><th>Severidad</th><th>Categoria</th>"
                "<th>Puerto</th><th>Hallazgo</th><th>Descripcion</th><th>Evidencia</th>"
                "<th>CVE</th><th>Recomendacion</th></tr></thead><tbody>"
                + "".join(vuln_rows)
                + "</tbody></table>"
            )
        host_sections.append(
            f"<section class='host-card'>"
            f"<h3>{_esc(r.ip)} &mdash; {_esc(r.hostname or r.netbios_name or 'sin nombre')}</h3>"
            f"<p class='meta'>MAC: {_esc(r.mac or '-')} | SO estimado: {_esc(r.os_guess or '-')} | "
            f"Tipo: {_esc(r.device_type)} | Duracion: {r.scan_duration_s:.2f}s</p>"
            f"<p class='meta'>Servicios: <ul>{services_rows or '<li>Ninguno</li>'}</ul></p>"
            f"{vuln_table}"
            f"</section>"
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
    .host-card{background:#0f172a;border:1px solid #1f2937;border-radius:10px;padding:16px;margin-top:18px;}
    .meta{color:#9ca3af;font-size:13px;}
    .muted{color:#6b7280;}
    .summary-grid{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0;}
    .stat{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:12px 18px;min-width:140px;}
    .stat b{display:block;font-size:22px;}
    footer{color:#6b7280;margin-top:32px;font-size:12px;}
    """

    stats_html = "".join(
        f"<div class='stat'><span>{_esc(s.value)}</span><b style='color:{_SEVERITY_HEX[s]}'>{sev_totals[s]}</b></div>"
        for s in SEVERITY_ORDER
    )

    document = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>{_esc(title)}</title>
<style>{css}</style></head>
<body>
<h1>{_esc(title)}</h1>
<p class="subtitle">Hosts analizados: {len(results)} | Activos: {hosts_alive} | Hallazgos totales: {total_vulns}</p>
<div class="summary-grid">{stats_html}</div>

<h2>Inventario de Activos</h2>
<table>
<thead><tr><th>IP</th><th>Estado</th><th>Hostname</th><th>MAC</th><th>SO estimado</th><th>Tipo</th><th>Puertos abiertos</th><th>Vulns</th></tr></thead>
<tbody>{"".join(rows_summary)}</tbody>
</table>

<h2>Detalle por Host</h2>
{"".join(host_sections) if host_sections else "<p class='muted'>No hay hosts activos con hallazgos.</p>"}

<footer>Generado por IP Security Audit Tool. Uso exclusivo en infraestructuras propias o con autorizacion explicita.</footer>
</body></html>"""

    Path(output_path).write_text(document, encoding="utf-8")


def export_pdf(
    results: List[HostResult],
    output_path: str,
    title: str = "Reporte de Auditoria de Red",
    org_name: str = "Consortium Legal",
    org_location: str = "Guatemala",
    logo_path: Optional[str] = None,
) -> None:
    """Genera un PDF con membrete corporativo (barra de color, nombre de la
    organizacion, fecha de emision, pie de pagina), pensado para imprimir o
    archivar -- mismo contenido que export_html, otro formato de salida.

    Usa reportlab (puro Python, sin dependencias de sistema como GTK/Pango)
    para que compilar el .exe con PyInstaller siga siendo simple. logo_path
    es opcional: si se pasa la ruta a una imagen (PNG/JPG), se incrusta en
    el encabezado; si no, el membrete queda solo con el nombre en texto."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    HEADER_BLUE = colors.HexColor("#1d4ed8")
    DARK = colors.HexColor("#111827")
    MUTED = colors.HexColor("#6b7280")
    BORDER = colors.HexColor("#d1d5db")
    sev_colors = {s: colors.HexColor(hexval) for s, hexval in _SEVERITY_HEX.items()}

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("ReportTitle", fontSize=17, leading=21, textColor=DARK, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("Issued", fontSize=9, textColor=MUTED, spaceAfter=12))
    styles.add(ParagraphStyle("FieldLabel", fontSize=7.5, textColor=MUTED, fontName="Helvetica-Bold", leading=10))
    styles.add(ParagraphStyle("FieldValue", fontSize=10.5, textColor=DARK, leading=14))
    styles.add(ParagraphStyle("H2", fontSize=13, textColor=DARK, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=8))
    styles.add(ParagraphStyle("H3", fontSize=10.5, textColor=DARK, fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4))
    styles.add(ParagraphStyle("Cell", fontSize=8.3, textColor=DARK, leading=11))
    styles.add(ParagraphStyle("CellHeader", fontSize=8.3, textColor=colors.white, fontName="Helvetica-Bold", leading=11))
    styles.add(ParagraphStyle("SevChip", fontSize=8.3, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=11))
    styles.add(ParagraphStyle("SevCount", fontSize=15, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=18))

    def _header_footer(canvas, doc) -> None:
        canvas.saveState()
        page_w, page_h = A4
        canvas.setFillColor(HEADER_BLUE)
        canvas.rect(0, page_h - 7, page_w, 7, stroke=0, fill=1)
        canvas.setFillColor(DARK)
        canvas.setFont("Helvetica-Bold", 13)
        canvas.drawString(20 * mm, page_h - 20 * mm, org_name.upper())
        if logo_path and Path(logo_path).exists():
            try:
                canvas.drawImage(
                    logo_path, page_w - 45 * mm, page_h - 24 * mm, width=25 * mm, height=12 * mm,
                    preserveAspectRatio=True, mask="auto", anchor="e",
                )
            except Exception:
                pass
        canvas.setStrokeColor(BORDER)
        canvas.line(20 * mm, page_h - 24 * mm, page_w - 20 * mm, page_h - 24 * mm)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(20 * mm, 12 * mm, f"{org_name.upper()} · {org_location}")
        canvas.drawRightString(page_w - 20 * mm, 12 * mm, f"Pagina {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm, topMargin=32 * mm, bottomMargin=22 * mm,
        title=title,
    )

    hosts_alive = sum(1 for r in results if r.alive)
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    sev_totals = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for v in r.vulnerabilities:
            sev_totals[v.severity] += 1
    estado_txt = (
        "Hallazgos criticos/altos pendientes de revisar"
        if (sev_totals[Severity.CRITICAL] or sev_totals[Severity.HIGH])
        else "Sin hallazgos criticos ni altos"
    )

    story = [
        Paragraph(_esc(title), styles["ReportTitle"]),
        Paragraph(f"Emitido el {_fecha_larga_es()}", styles["Issued"]),
    ]

    field_rows = [
        [Paragraph("EQUIPOS ANALIZADOS", styles["FieldLabel"]), Paragraph(str(len(results)), styles["FieldValue"])],
        [Paragraph("EQUIPOS ACTIVOS", styles["FieldLabel"]), Paragraph(str(hosts_alive), styles["FieldValue"])],
        [Paragraph("HALLAZGOS TOTALES", styles["FieldLabel"]), Paragraph(str(total_vulns), styles["FieldValue"])],
        [Paragraph("ESTADO", styles["FieldLabel"]), Paragraph(_esc(estado_txt), styles["FieldValue"])],
    ]
    field_table = Table(field_rows, colWidths=[45 * mm, 125 * mm])
    field_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, BORDER),
    ]))
    story.append(field_table)
    story.append(Spacer(1, 8 * mm))

    sev_cells = [
        [Paragraph(str(sev_totals[s]), styles["SevCount"]) for s in SEVERITY_ORDER],
        [Paragraph(s.value, styles["SevChip"]) for s in SEVERITY_ORDER],
    ]
    sev_table = Table(sev_cells, colWidths=[29 * mm] * 5)
    sev_style = [
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, s in enumerate(SEVERITY_ORDER):
        sev_style.append(("BACKGROUND", (i, 0), (i, 1), sev_colors[s]))
    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph("Inventario de Activos", styles["H2"]))
    inv_rows = [[Paragraph(h, styles["CellHeader"]) for h in
                 ["IP", "Estado", "Hostname", "SO estimado", "Tipo", "Puertos", "Hallazgos"]]]
    for r in results:
        estado = "Activo" if r.alive else "Sin respuesta"
        inv_rows.append([
            Paragraph(_esc(r.ip), styles["Cell"]), Paragraph(_esc(estado), styles["Cell"]),
            Paragraph(_esc(r.hostname or r.netbios_name or "-"), styles["Cell"]),
            Paragraph(_esc(r.os_guess or "-"), styles["Cell"]), Paragraph(_esc(r.device_type), styles["Cell"]),
            Paragraph(_esc(", ".join(str(p) for p in r.open_ports) or "-"), styles["Cell"]),
            Paragraph(str(len(r.vulnerabilities)) if r.alive else "-", styles["Cell"]),
        ])
    inv_table = Table(inv_rows, colWidths=[22 * mm, 18 * mm, 32 * mm, 30 * mm, 20 * mm, 34 * mm, 19 * mm], repeatRows=1)
    inv_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(inv_table)

    host_blocks = []
    for r in results:
        if not r.alive or not r.vulnerabilities:
            continue
        ordered = sorted(r.vulnerabilities, key=lambda v: v.severity.rank, reverse=True)
        vuln_rows = [[Paragraph(h, styles["CellHeader"]) for h in ["Severidad", "Puerto", "Hallazgo", "Recomendacion"]]]
        for v in ordered:
            vuln_rows.append([
                Paragraph(_esc(v.severity.value), styles["CellHeader"]),
                Paragraph(_esc(v.port) if v.port else "-", styles["Cell"]),
                Paragraph(_esc(v.title), styles["Cell"]),
                Paragraph(_esc(v.recommendation), styles["Cell"]),
            ])
        vt = Table(vuln_rows, colWidths=[24 * mm, 16 * mm, 58 * mm, 77 * mm], repeatRows=1)
        vt_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, v in enumerate(ordered, start=1):
            vt_style.append(("BACKGROUND", (0, i), (0, i), sev_colors[v.severity]))
        vt.setStyle(TableStyle(vt_style))
        header = f"{r.ip} &mdash; {_esc(r.hostname or r.netbios_name or 'sin nombre')}"
        host_blocks.append(KeepTogether([Paragraph(header, styles["H3"]), vt]))

    if host_blocks:
        story.append(Paragraph("Detalle por Host", styles["H2"]))
        for block in host_blocks:
            story.append(block)
            story.append(Spacer(1, 4 * mm))
    else:
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("No hay hosts activos con hallazgos.", styles["Issued"]))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
