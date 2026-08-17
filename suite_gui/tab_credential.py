"""Pestana 'Auditoria de Credenciales' - envuelve credential_core
(equivalente GUI de credential_audit_tool/main.py). Prueba credenciales
REALES contra cuentas LOCALES via SMB/WinRM. Conserva ambas salvaguardas
del original: frase de autorizacion tipeada Y confirmacion de alcance si
hay mas de 5 objetivos."""
from __future__ import annotations

import ipaddress
import sys
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, ttk
from typing import List, Optional

from gui_common import (
    FindingsTable, LogConsole, UiBridge, ask_ethical_confirmation, get_float, get_int,
    int_entry, open_path, run_in_background,
)
from credential_core import inventory, smb_cred, winrm_cred
from credential_core.models import CredentialAttemptResult, HostCredentialReport, WifiFinding
from credential_core.report import export_html, export_json
from credential_core.strength import evaluate_password
from credential_core.wordlist import load_usernames, load_wordlist

ETHICAL_WARNING = (
    "Esta herramienta realiza intentos de inicio de sesion REALES contra las cuentas "
    "locales indicadas. Puede bloquear cuentas si la politica de bloqueo esta activa "
    "(eso es una senal POSITIVA, no un error). Use esta herramienta UNICAMENTE contra "
    "equipos explicitamente designados para esta prueba, con autorizacion, y nunca "
    "contra la poblacion general de usuarios."
)
SCOPE_WARNING_THRESHOLD = 5


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
            continue
    seen, deduped = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    return deduped


def crack_host(ip: str, usernames: List[str], wordlist: List[str], delay_s: float, max_attempts: Optional[int]) -> HostCredentialReport:
    """Copia fiel de credential_audit_tool/main.py::crack_host."""
    report = HostCredentialReport(ip=ip)
    inv = inventory.gather_inventory(ip)
    report.alive = inv["alive"]
    report.mac = inv["mac"]
    report.hostname = inv["hostname"]
    report.os_guess = inv["os_guess"]

    if not report.alive:
        return report

    got_working_cred = None

    for username in usernames:
        outcome, password, attempts = smb_cred.crack_smb_account(ip, username, wordlist, delay_s, max_attempts)
        protocol = "SMB"

        if outcome in ("not_found", "unreachable", "denied"):
            outcome2, password2, attempts2 = winrm_cred.crack_winrm_account(ip, username, wordlist, delay_s, max_attempts)
            if outcome2 != "unreachable":
                outcome, password, attempts, protocol = outcome2, password2, attempts + attempts2, "WinRM"

        result = CredentialAttemptResult(username=username, outcome=outcome, password=password, attempts_made=attempts, protocol=protocol)
        if outcome == "cracked":
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


class CredentialTab(ttk.Frame):
    def __init__(self, parent: tk.Widget):
        super().__init__(parent, padding=16)
        self._ui = UiBridge(self)
        self._html_path: Optional[Path] = None
        self._build()

    def _build(self) -> None:
        ttk.Label(self, text="Auditoria de Credenciales (credential_core)", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            self,
            text="Prueba credenciales REALES contra cuentas locales (nunca de dominio). Puede bloquear cuentas.",
            style="Muted.TLabel",
        ).pack(anchor="w")
        warn = tk.Label(
            self, bg="#7f1d1d", fg="white", font=("Segoe UI", 9, "bold"), padx=10, pady=6, justify="left",
            text="El reporte generado puede contener contrasenas reales en TEXTO PLANO. Manejelo como secreto y rote de inmediato cualquier contrasena encontrada.",
            wraplength=760,
        )
        warn.pack(anchor="w", fill="x", pady=(6, 12))

        form = ttk.Frame(self)
        form.pack(fill="x")

        ttk.Label(form, text="Objetivos (IP/CIDR, separados por coma)").grid(row=0, column=0, sticky="w")
        self.targets_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.targets_var).grid(row=0, column=1, columnspan=3, sticky="we", pady=4)

        ttk.Label(form, text="Usuarios locales (vacio = solo Administrator)").grid(row=1, column=0, sticky="w")
        self.users_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.users_var).grid(row=1, column=1, columnspan=3, sticky="we", pady=4)

        ttk.Label(form, text="Wordlist propia (vacio = lista curada incorporada)").grid(row=2, column=0, sticky="w")
        self.wordlist_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.wordlist_var).grid(row=2, column=1, columnspan=2, sticky="we", pady=4)
        ttk.Button(form, text="Elegir...", command=self._pick_wordlist).grid(row=2, column=3, sticky="w", padx=(8, 0))

        ttk.Label(form, text="Delay entre intentos (s)").grid(row=3, column=0, sticky="w")
        self.delay_entry = int_entry(form, 0)
        self.delay_entry.var.set("2.0")
        self.delay_entry.grid(row=3, column=1, sticky="w", pady=4)

        ttk.Label(form, text="Max. intentos por cuenta (0 = toda la lista)").grid(row=3, column=2, sticky="e", padx=(12, 4))
        self.max_attempts_entry = int_entry(form, 0)
        self.max_attempts_entry.grid(row=3, column=3, sticky="w")

        ttk.Label(form, text="Equipos en paralelo").grid(row=4, column=0, sticky="w")
        self.threads_entry = int_entry(form, 4)
        self.threads_entry.grid(row=4, column=1, sticky="w", pady=4)

        ttk.Label(form, text="Carpeta de salida").grid(row=5, column=0, sticky="w")
        self.outdir_var = tk.StringVar(value="reportes_credenciales")
        ttk.Entry(form, textvariable=self.outdir_var).grid(row=5, column=1, columnspan=2, sticky="we", pady=4)
        ttk.Button(form, text="Elegir...", command=self._pick_outdir).grid(row=5, column=3, sticky="w", padx=(8, 0))

        form.grid_columnconfigure(1, weight=1)

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(12, 8))
        self.run_btn = ttk.Button(actions, text="Ejecutar validacion", style="Danger.TButton", command=self._on_run)
        self.run_btn.pack(side="left")
        self.open_btn = ttk.Button(actions, text="Abrir reporte HTML", command=self._open_report, state="disabled")
        self.open_btn.pack(side="left", padx=(8, 0))
        self.progress = ttk.Progressbar(actions, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True, padx=(16, 0))

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, pady=(8, 0))

        table_frame = ttk.Frame(paned)
        self.table = FindingsTable(table_frame, [
            ("ip", "IP", 110), ("host", "Hostname", 130), ("user", "Usuario/SSID", 130),
            ("outcome", "Resultado", 90), ("password", "Contrasena", 140),
            ("strength", "Fortaleza", 90), ("protocol", "Protocolo", 80),
        ])
        self.table.pack(fill="both", expand=True)
        paned.add(table_frame, weight=3)

        log_frame = ttk.Frame(paned)
        self.log = LogConsole(log_frame, height=8)
        self.log.pack(fill="both", expand=True)
        paned.add(log_frame, weight=1)

    def _pick_wordlist(self) -> None:
        chosen = filedialog.askopenfilename()
        if chosen:
            self.wordlist_var.set(chosen)

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

        if not ask_ethical_confirmation(
            self, "Confirmacion de autorizacion", ETHICAL_WARNING,
            required_phrase="confirmo autorizacion",
        ):
            self.log.log("Operacion cancelada: autorizacion no confirmada.", "warn")
            return

        if len(targets) > SCOPE_WARNING_THRESHOLD:
            if not ask_ethical_confirmation(
                self, "Confirmar alcance",
                f"{len(targets)} equipos resueltos como objetivo. Esto supera el umbral esperado para "
                "una prueba puntual. Verifique que no se le haya colado un rango mas amplio de lo previsto.",
                required_phrase=str(len(targets)),
                header="Confirmar alcance",
            ):
                self.log.log("Alcance no confirmado. Cancelando.", "warn")
                return

        usernames = load_usernames(self.users_var.get(), None)
        wordlist = load_wordlist(self.wordlist_var.get() or None)
        delay_s = get_float(self.delay_entry, 2.0)
        max_attempts_raw = get_int(self.max_attempts_entry, 0)
        max_attempts = max_attempts_raw if max_attempts_raw > 0 else None
        threads = max(1, get_int(self.threads_entry, 4))
        output_dir = Path(self.outdir_var.get() or "reportes_credenciales")

        self.table.clear()
        self.log.clear()
        self.log.log(
            f"{len(targets)} equipo(s), {len(usernames)} usuario(s) por equipo, "
            f"{len(wordlist)} contrasena(s) por usuario, delay {delay_s}s.", "info",
        )
        self.progress.configure(maximum=len(targets), value=0)
        self.run_btn.configure(state="disabled")
        self.open_btn.configure(state="disabled")

        def work():
            reports: List[HostCredentialReport] = []
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {
                    executor.submit(crack_host, ip, usernames, wordlist, delay_s, max_attempts): ip
                    for ip in targets
                }
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        report = future.result()
                    except Exception as exc:
                        report = HostCredentialReport(ip=ip, errors=[str(exc)])
                    reports.append(report)
                    cracked = sum(1 for a in report.attempts if a.outcome == "cracked")
                    self.log.log(f"  {ip}: {'vivo' if report.alive else 'sin respuesta'}, {cracked} credencial(es) debil(es)")
                    self._ui.post(lambda: self.progress.step(1))
            reports.sort(key=lambda r: tuple(int(p) for p in r.ip.split(".")) if r.ip.count(".") == 3 else (0,))
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = output_dir / f"credenciales_{timestamp}.json"
            html_path = output_dir / f"credenciales_{timestamp}.html"
            export_json(reports, str(json_path))
            export_html(reports, str(html_path))
            return reports, json_path, html_path

        def done(result, error) -> None:
            self.run_btn.configure(state="normal")
            if error is not None:
                self.log.log(f"Error durante la validacion: {error}", "error")
                return
            reports, json_path, html_path = result
            self._html_path = html_path
            total_cracked = 0
            total_locked = 0
            for report in reports:
                if not report.alive:
                    continue
                for a in report.attempts:
                    if a.outcome == "cracked":
                        total_cracked += 1
                    if a.outcome == "locked":
                        total_locked += 1
                    self.table.add_row(
                        [report.ip, report.hostname or "-", a.username, a.outcome,
                         a.password if a.outcome == "cracked" else "-",
                         a.strength_label or "-", a.protocol or "-"],
                        severity_tag="Critica" if a.outcome == "cracked" else None,
                    )
                for w in report.wifi_findings:
                    self.table.add_row(
                        [report.ip, report.hostname or "-", f"SSID: {w.ssid}", "wifi guardado",
                         w.password or "-", w.strength_label, "WiFi"],
                        severity_tag="Critica" if w.password else None,
                    )
            self.log.log(f"Listo: {total_cracked} credencial(es) debil(es), {total_locked} cuenta(s) bloqueada(s) durante la prueba.", "ok")
            if total_cracked:
                self.log.log("El reporte contiene contrasenas en texto plano. Rotelas de inmediato.", "warn")
            self.log.log(f"JSON: {json_path}", "ok")
            self.log.log(f"HTML: {html_path}", "ok")
            self.open_btn.configure(state="normal")

        run_in_background(self, work, done)

    def _open_report(self) -> None:
        if self._html_path:
            open_path(self._html_path)
