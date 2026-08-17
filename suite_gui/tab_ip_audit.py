"""Pestana 'Auditoria de Red' - envuelve ip_audit_core (equivalente GUI de
ip_audit_tool/main.py). La logica de analisis (analyze_host) es la misma
sin ningun cambio; aca solo se recolectan targets/opciones, se corre en un
hilo de fondo, y se muestran resultados."""
from __future__ import annotations

import ipaddress
import sys
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, ttk
from typing import List

from gui_common import (
    FindingsTable, LogConsole, SEVERITY_ORDER, UiBridge, ask_ethical_confirmation,
    get_float, get_int, int_entry, open_path, run_in_background,
)
from ip_audit_core.host_analyzer import analyze_host
from ip_audit_core.models import HostResult
from ip_audit_core.report import export_html, export_json, export_pdf
from ip_audit_core.vuln_db import DEFAULT_PORT_LIST

ETHICAL_WARNING = (
    "Esta herramienta escanea la red indicada (descubrimiento de hosts, puertos, "
    "servicios y vulnerabilidades conocidas). NUNCA intenta autenticarse contra los "
    "servicios encontrados. Usela unicamente sobre redes/equipos propios o con "
    "autorizacion explicita por escrito."
)

MAX_SENSIBLE_THREADS = 64


def expand_targets(raw_targets: List[str]) -> List[str]:
    """Copia fiel de ip_audit_tool/main.py::expand_targets (IPs, CIDR o
    rangos tipo 192.168.1.10-20)."""
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
                base, end = token.rsplit("-", 1)
                prefix = ".".join(base.split(".")[:3])
                start_octet = int(base.split(".")[-1])
                end_octet = int(end)
                if start_octet > end_octet:
                    continue
                for octet in range(start_octet, end_octet + 1):
                    ips.append(f"{prefix}.{octet}")
            else:
                ipaddress.ip_address(token)
                ips.append(token)
        except ValueError:
            continue
    seen, deduped = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    return deduped


def parse_ports(ports_arg: str) -> List[int]:
    if not ports_arg.strip():
        return DEFAULT_PORT_LIST
    result: List[int] = []
    for part in ports_arg.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if start <= end:
                    result.extend(range(start, end + 1))
            else:
                result.append(int(part))
        except ValueError:
            continue
    return sorted(set(result)) if result else DEFAULT_PORT_LIST


class IpAuditTab(ttk.Frame):
    def __init__(self, parent: tk.Widget):
        super().__init__(parent, padding=16)
        self._results: List[HostResult] = []
        self._ui = UiBridge(self)
        self._build()

    def _build(self) -> None:
        ttk.Label(self, text="Auditoria de Red (ip_audit_core)", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            self,
            text="Descubre hosts, puertos, servicios y correlaciona con vulnerabilidades conocidas. No autentica nada.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 12))

        form = ttk.Frame(self)
        form.pack(fill="x")

        ttk.Label(form, text="Objetivos (IP, CIDR, rango, separados por coma)").grid(row=0, column=0, sticky="w")
        self.targets_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.targets_var).grid(row=0, column=1, columnspan=3, sticky="we", pady=4)

        ttk.Label(form, text="Puertos (vacio = set curado)").grid(row=1, column=0, sticky="w")
        self.ports_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.ports_var).grid(row=1, column=1, sticky="we", pady=4)

        ttk.Label(form, text="Hilos").grid(row=1, column=2, sticky="e", padx=(12, 4))
        self.threads_entry = int_entry(form, 20)
        self.threads_entry.grid(row=1, column=3, sticky="w")

        ttk.Label(form, text="Timeout por puerto (s)").grid(row=2, column=0, sticky="w")
        self.port_timeout_entry = int_entry(form, 0)
        self.port_timeout_entry.var.set("0.9")
        self.port_timeout_entry.grid(row=2, column=1, sticky="w", pady=4)

        self.skip_mac_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(form, text="Omitir resolucion de MAC (no requiere administrador)", variable=self.skip_mac_var).grid(
            row=2, column=2, columnspan=2, sticky="w"
        )

        # Pruebas activas adicionales (mas ruidosas que el escaneo pasivo):
        # sondeo de inyeccion SQL en apps web y deteccion de exposicion a DDoS
        # por amplificacion. Activadas por defecto; se pueden apagar.
        self.check_sqli_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            form, text="Probar inyeccion SQL (SQLi) en servicios web",
            variable=self.check_sqli_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))

        self.check_ddos_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            form, text="Detectar exposicion a DDoS (amplificacion UDP)",
            variable=self.check_ddos_var,
        ).grid(row=4, column=2, columnspan=2, sticky="w", pady=(6, 0))

        self.check_conn_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            form, text="Prueba de conectividad / envio de paquetes (blackbox)",
            variable=self.check_conn_var,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(2, 6))

        ttk.Label(form, text="Carpeta de salida").grid(row=6, column=0, sticky="w")
        self.outdir_var = tk.StringVar(value="reportes")
        ttk.Entry(form, textvariable=self.outdir_var).grid(row=6, column=1, sticky="we", pady=4)
        ttk.Button(form, text="Elegir...", command=self._pick_outdir).grid(row=6, column=2, sticky="w", padx=(8, 0))

        form.grid_columnconfigure(1, weight=1)

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(12, 8))
        self.run_btn = ttk.Button(actions, text="Escanear", style="Accent.TButton", command=self._on_run)
        self.run_btn.pack(side="left")
        self.open_html_btn = ttk.Button(actions, text="Abrir reporte HTML", command=lambda: open_path(self._html_path) if self._html_path else None, state="disabled")
        self.open_html_btn.pack(side="left", padx=(8, 0))
        self.open_pdf_btn = ttk.Button(actions, text="Abrir reporte PDF", command=lambda: open_path(self._pdf_path) if self._pdf_path else None, state="disabled")
        self.open_pdf_btn.pack(side="left", padx=(8, 0))
        self.progress = ttk.Progressbar(actions, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True, padx=(16, 0))

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, pady=(8, 0))

        table_frame = ttk.Frame(paned)
        self.table = FindingsTable(table_frame, [
            ("ip", "IP", 110), ("sev", "Severidad", 90), ("title", "Hallazgo", 320),
            ("port", "Puerto", 60), ("category", "Categoria", 160),
        ])
        self.table.pack(fill="both", expand=True)
        paned.add(table_frame, weight=3)

        log_frame = ttk.Frame(paned)
        self.log = LogConsole(log_frame, height=8)
        self.log.pack(fill="both", expand=True)
        paned.add(log_frame, weight=1)

        self._html_path: Path | None = None
        self._pdf_path: Path | None = None

    def _pick_outdir(self) -> None:
        chosen = filedialog.askdirectory()
        if chosen:
            self.outdir_var.set(chosen)

    def _on_run(self) -> None:
        raw = [t for t in self.targets_var.get().split(",") if t.strip()]
        targets = expand_targets(raw)
        if not targets:
            self.log.log("No se resolvio ningun objetivo valido.", "error")
            return

        if not ask_ethical_confirmation(self, "Confirmacion de autorizacion", ETHICAL_WARNING):
            self.log.log("Operacion cancelada: autorizacion no confirmada.", "warn")
            return

        ports = parse_ports(self.ports_var.get())
        threads = min(get_int(self.threads_entry, 20), MAX_SENSIBLE_THREADS)
        port_timeout = get_float(self.port_timeout_entry, 0.9)
        skip_mac = self.skip_mac_var.get()
        check_sqli = self.check_sqli_var.get()
        check_ddos = self.check_ddos_var.get()
        check_conn = self.check_conn_var.get()
        output_dir = Path(self.outdir_var.get() or "reportes")

        self.table.clear()
        self.log.clear()
        self.log.log(f"{len(targets)} objetivo(s), {len(ports)} puertos por host, {threads} hilos.", "info")
        self.progress.configure(maximum=len(targets), value=0)
        self.run_btn.configure(state="disabled")
        self.open_html_btn.configure(state="disabled")
        self.open_pdf_btn.configure(state="disabled")

        def work():
            results: List[HostResult] = []
            with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
                futures = {
                    executor.submit(
                        analyze_host, ip, ports, port_timeout, 2.0, 3.0, 4.0, skip_mac,
                        check_sqli, check_ddos, check_conn,
                    ): ip
                    for ip in targets
                }
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = HostResult(ip=ip, errors=[str(exc)])
                    results.append(result)
                    self.log.log(f"  {ip}: {'vivo' if result.alive else 'sin respuesta'}, {len(result.vulnerabilities)} hallazgo(s)")
                    self._ui.post(lambda: self.progress.step(1))
            results.sort(key=lambda r: tuple(int(p) for p in r.ip.split(".")) if r.ip.count(".") == 3 else (0,))
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = output_dir / f"reporte_{timestamp}.json"
            html_path = output_dir / f"reporte_{timestamp}.html"
            pdf_path = output_dir / f"reporte_{timestamp}.pdf"
            export_json(results, str(json_path))
            export_html(results, str(html_path))
            export_pdf(results, str(pdf_path))
            return results, json_path, html_path, pdf_path

        def done(result, error) -> None:
            self.run_btn.configure(state="normal")
            if error is not None:
                self.log.log(f"Error durante el escaneo: {error}", "error")
                return
            results, json_path, html_path, pdf_path = result
            self._results = results
            self._html_path = html_path
            self._pdf_path = pdf_path
            total_vulns = 0
            for host in results:
                for vuln in host.vulnerabilities:
                    total_vulns += 1
                    self.table.add_row(
                        [host.ip, vuln.severity.value, vuln.title, vuln.port or "-", vuln.category],
                        severity_tag=vuln.severity.value,
                    )
            self.log.log(f"Listo: {len(results)} host(s), {total_vulns} hallazgo(s) en total.", "ok")
            self.log.log(f"JSON: {json_path}", "ok")
            self.log.log(f"HTML: {html_path}", "ok")
            self.log.log(f"PDF: {pdf_path}", "ok")
            self.open_html_btn.configure(state="normal")
            self.open_pdf_btn.configure(state="normal")

        run_in_background(self, work, done)
