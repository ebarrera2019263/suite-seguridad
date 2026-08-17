"""Pestana 'Hardening Local' - envuelve hardening_core (equivalente GUI de
hardening_tool/main.py). Mismos checks/fixes originales, mismas salvaguardas
(confirmacion reforzada en sesion remota para cambios de alto impacto,
punto de restauracion opcional, script de reversion)."""
from __future__ import annotations

import sys
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from typing import Callable, List, Optional, Tuple

from gui_common import (
    FindingsTable, LogConsole, UiBridge, ask_ethical_confirmation, open_path, run_in_background,
)
from hardening_core import admin, restore
from hardening_core.checks import (
    accounts, defender, firewall, network_exposure, rdp, remote_tools, smb, ssh, telnet, tls, updates, winrm,
)
from hardening_core.models import CheckResult, Severity
from hardening_core.report import export_html, export_json

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

_HIGH_IMPACT_IDS = {"firewall_profiles", "rdp_nla", "winrm_basic_auth"}


class HardeningTab(ttk.Frame):
    def __init__(self, parent: tk.Widget):
        super().__init__(parent, padding=16)
        self._ui = UiBridge(self)
        self._results: List[CheckResult] = []
        self._undo_entries: List[Tuple[str, str]] = []
        self._html_path: Optional[Path] = None
        self._build()
        self._refresh_admin_banner()

    def _build(self) -> None:
        ttk.Label(self, text="Hardening Local (hardening_core)", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            self,
            text="Diagnostica y corrige la configuracion de seguridad de ESTE equipo. No tiene alcance de red.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 8))

        self.admin_banner = ttk.Label(self, text="", style="Muted.TLabel")
        self.admin_banner.pack(anchor="w")
        self.elevate_btn = ttk.Button(self, text="Reiniciar como Administrador", command=self._relaunch_admin)

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(12, 8))
        self.diag_btn = ttk.Button(actions, text="Diagnosticar", style="Accent.TButton", command=self._on_diagnose)
        self.diag_btn.pack(side="left")
        self.fix_btn = ttk.Button(actions, text="Aplicar correcciones pendientes", command=self._on_fix_all, state="disabled")
        self.fix_btn.pack(side="left", padx=(8, 0))
        self.open_btn = ttk.Button(actions, text="Abrir reporte HTML", command=lambda: open_path(self._html_path) if self._html_path else None, state="disabled")
        self.open_btn.pack(side="left", padx=(8, 0))
        self.progress = ttk.Progressbar(actions, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True, padx=(16, 0))

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, pady=(8, 0))

        table_frame = ttk.Frame(paned)
        self.table = FindingsTable(table_frame, [
            ("estado", "Estado", 100), ("sev", "Severidad", 90), ("title", "Verificacion", 300),
            ("category", "Categoria", 200), ("fix", "Correccion", 100),
        ])
        self.table.pack(fill="both", expand=True)
        paned.add(table_frame, weight=3)

        log_frame = ttk.Frame(paned)
        self.log = LogConsole(log_frame, height=8)
        self.log.pack(fill="both", expand=True)
        paned.add(log_frame, weight=1)

    def _refresh_admin_banner(self) -> None:
        if admin.is_admin():
            self.admin_banner.configure(text="✔ Ejecutando con privilegios de Administrador.")
            self.elevate_btn.pack_forget()
        else:
            self.admin_banner.configure(
                text="⚠ Sin privilegios de Administrador: el diagnostico puede ser incompleto y las correcciones fallaran."
            )
            self.elevate_btn.pack(anchor="w", pady=(2, 0))

    def _relaunch_admin(self) -> None:
        if admin.relaunch_as_admin():
            self.log.log("Reiniciando como Administrador...", "info")
            self.winfo_toplevel().after(300, sys.exit)
        else:
            self.log.log("No se pudo relanzar como Administrador. Ejecute la app como Administrador manualmente.", "error")

    # ---- Diagnostico ---------------------------------------------------

    def _on_diagnose(self) -> None:
        self.table.clear()
        self.log.clear()
        self.diag_btn.configure(state="disabled")
        self.fix_btn.configure(state="disabled")
        self.progress.configure(maximum=len(CHECK_REGISTRY), value=0)
        self.log.log(f"Ejecutando {len(CHECK_REGISTRY)} verificaciones locales...", "info")

        def work() -> List[CheckResult]:
            results: List[CheckResult] = []
            for check_fn, _ in CHECK_REGISTRY:
                try:
                    results.append(check_fn())
                except Exception as exc:
                    results.append(CheckResult(
                        check_id=getattr(check_fn, "__name__", "desconocido"),
                        title=f"Error al ejecutar verificacion {getattr(check_fn, '__name__', '')}",
                        category="Error interno", severity=Severity.INFO, vulnerable=False,
                        determinable=False, detail=str(exc),
                        recommendation="Reintentar manualmente la verificacion correspondiente.", fixable=False,
                    ))
                self._ui.post(lambda: self.progress.step(1))
            return results

        def done(results, error) -> None:
            self.diag_btn.configure(state="normal")
            if error is not None:
                self.log.log(f"Error durante el diagnostico: {error}", "error")
                return
            self._results = results
            self._render_table()
            pending = self._pending_fixes()
            self.fix_btn.configure(state="normal" if pending else "disabled")
            vulnerable = sum(1 for r in results if r.vulnerable)
            self.log.log(f"Diagnostico completo: {len(results)} verificaciones, {vulnerable} hallazgo(s), {len(pending)} corregible(s) automaticamente.", "ok")
            self._write_reports()

        run_in_background(self, work, done)

    def _render_table(self) -> None:
        self.table.clear()
        ordered = sorted(self._results, key=lambda r: (not r.vulnerable, -r.severity.rank))
        for r in ordered:
            estado = "VULNERABLE" if r.vulnerable else ("No verificable" if not r.determinable else "OK")
            if not r.vulnerable:
                fix_state = "-"
            elif r.manual_only:
                fix_state = "Manual"
            elif r.fix_applied is True:
                fix_state = "Aplicada"
            elif r.fix_applied is False:
                fix_state = "Fallo"
            else:
                fix_state = "Pendiente" if r.fixable else "Sin auto-fix"
            self.table.add_row(
                [estado, r.severity.value, r.title, r.category, fix_state],
                severity_tag=r.severity.value if r.vulnerable else None,
                iid=r.check_id,
            )

    def _pending_fixes(self) -> List[Tuple[CheckResult, Callable]]:
        pending = [
            (result, fix_fn)
            for result, (_, fix_fn) in zip(self._results, CHECK_REGISTRY)
            if result.vulnerable and not result.manual_only and result.fixable and fix_fn is not None
        ]
        pending.sort(key=lambda pair: pair[0].severity.rank, reverse=True)
        return pending

    # ---- Correccion -----------------------------------------------------

    def _on_fix_all(self) -> None:
        pending = self._pending_fixes()
        if not pending:
            self.log.log("No hay correcciones automaticas pendientes.", "info")
            return

        create_rp = ask_ethical_confirmation(
            self, "Punto de restauracion",
            "Se recomienda crear un punto de restauracion de Windows antes de aplicar correcciones, "
            "por si algun cambio necesita revertirse manualmente. Windows solo permite uno cada 24hs.",
            header="Antes de continuar", confirm_label="Crear un punto de restauracion ahora.",
        )
        self._undo_entries = []
        self.fix_btn.configure(state="disabled")

        def after_restore_point() -> None:
            self._process_pending(pending, 0)

        if create_rp:
            self.log.log("Creando punto de restauracion...", "info")

            def work():
                return restore.create_restore_point()

            def done(result, error) -> None:
                if error is not None:
                    self.log.log(f"No se pudo crear el punto de restauracion: {error}", "warn")
                else:
                    ok, message = result
                    self.log.log(message, "ok" if ok else "warn")
                after_restore_point()

            run_in_background(self, work, done)
        else:
            after_restore_point()

    def _process_pending(self, pending: List[Tuple[CheckResult, Callable]], index: int) -> None:
        if index >= len(pending):
            self._render_table()
            self._write_reports(write_undo=True)
            self.fix_btn.configure(state="normal" if self._pending_fixes() else "disabled")
            self.log.log("Correcciones finalizadas.", "ok")
            return

        result, fix_fn = pending[index]
        remote = admin.is_remote_session()
        high_impact = remote and result.check_id in _HIGH_IMPACT_IDS

        message = f"{result.detail}\n\nRecomendacion: {result.recommendation}"
        if high_impact:
            message += (
                "\n\nADVERTENCIA: esta sesion parece ser remota (RDP). Este cambio "
                "(firewall/RDP/WinRM) podria afectar el acceso remoto actual."
            )
        confirmed = ask_ethical_confirmation(
            self, f"Confirmar correccion ({index + 1}/{len(pending)})", message,
            required_phrase="confirmo" if high_impact else None,
            header=f"[{result.severity.value}] {result.title}",
            confirm_label="Aplicar esta correccion ahora.",
        )

        if not confirmed:
            self.log.log(f"Omitido: {result.title}", "warn")
            self._process_pending(pending, index + 1)
            return

        self.log.log(f"Aplicando: {result.title}...", "info")

        def work():
            return fix_fn()

        def done(fix_result, error) -> None:
            if error is not None:
                result.fix_applied = False
                result.fix_message = str(error)
                self.log.log(f"Excepcion al aplicar {result.title}: {error}", "error")
            else:
                ok, message_, undo_cmd = fix_result
                result.fix_applied = ok
                result.fix_message = message_
                result.undo_hint = undo_cmd
                if ok:
                    self.log.log(f"Aplicada: {message_}", "ok")
                    if undo_cmd:
                        self._undo_entries.append((result.title, undo_cmd))
                else:
                    self.log.log(f"No se pudo aplicar {result.title}: {message_}", "error")
                    if undo_cmd and undo_cmd not in ("# no aplicable", "# nada que deshacer"):
                        self._undo_entries.append((f"{result.title} (aplicacion PARCIAL o fallida — revisar)", undo_cmd))
            self._process_pending(pending, index + 1)

        run_in_background(self, work, done)

    # ---- Reportes ---------------------------------------------------------

    def _write_reports(self, write_undo: bool = False) -> None:
        output_dir = Path("reportes_hardening")
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = output_dir / f"diagnostico_{timestamp}.json"
        html_path = output_dir / f"diagnostico_{timestamp}.html"
        export_json(self._results, str(json_path))
        export_html(self._results, str(html_path))
        self._html_path = html_path
        self.open_btn.configure(state="normal")
        self.log.log(f"Reporte JSON: {json_path}", "ok")
        self.log.log(f"Reporte HTML: {html_path}", "ok")
        if write_undo and self._undo_entries:
            undo_path = restore.write_undo_script(output_dir, self._undo_entries)
            self.log.log(f"Script de reversion: {undo_path}", "ok")
