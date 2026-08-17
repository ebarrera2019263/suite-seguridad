"""Pestana 'Parche Remoto' - envuelve remote_patch_core (equivalente GUI de
remote_patch_tool/main.py). Modulo de mayor riesgo de la suite: actua sobre
UN equipo remoto via WinRM. Conserva la guarda anti-autobloqueo (incluido
el fallo-cerrado si no se puede enumerar IPs locales), la confirmacion
etica tipeada, la prueba de conectividad previa, y la revalidacion de
conectividad despues de cada cambio."""
from __future__ import annotations

import ipaddress
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from typing import Callable, List, Optional, Tuple

from gui_common import LogConsole, UiBridge, ask_ethical_confirmation, open_path, run_in_background
from remote_patch_core import local_ip, remote_ps

ETHICAL_WARNING = (
    "Esta herramienta modifica de forma REMOTA la configuracion de un equipo que NO es "
    "el que esta ejecutando esta aplicacion (firewall + registro TLS). Uselo solo contra "
    "equipos de su organizacion, con autorizacion, y confirme que bloquear RDP no es la "
    "unica via de acceso remoto a ese equipo."
)


class RemotePatchTab(ttk.Frame):
    def __init__(self, parent: tk.Widget):
        super().__init__(parent, padding=16)
        self._ui = UiBridge(self)
        self._results: dict = {}
        self._username: Optional[str] = None
        self._password: Optional[str] = None
        self._build()

    def _build(self) -> None:
        ttk.Label(self, text="Parche Remoto (remote_patch_core)", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            self,
            text="Bloquea RDP y endurece TLS via WinRM en UNA maquina remota indicada por IP. Riesgo alto: revise antes de aplicar.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 12))

        form = ttk.Frame(self)
        form.pack(fill="x")

        ttk.Label(form, text="IP del equipo remoto").grid(row=0, column=0, sticky="w")
        self.ip_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.ip_var, width=24).grid(row=0, column=1, sticky="w", pady=4)

        self.undo_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(form, text="Deshacer en vez de aplicar", variable=self.undo_var).grid(row=0, column=2, sticky="w", padx=(16, 0))

        self.alt_creds_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            form, text="Usar credenciales distintas a esta sesion", variable=self.alt_creds_var,
            command=self._toggle_creds,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        ttk.Label(form, text="Usuario (ej. DOMINIO\\usuario)").grid(row=2, column=0, sticky="w")
        self.user_var = tk.StringVar()
        self.user_entry = ttk.Entry(form, textvariable=self.user_var, state="disabled")
        self.user_entry.grid(row=2, column=1, sticky="we", pady=4)

        ttk.Label(form, text="Contrasena").grid(row=3, column=0, sticky="w")
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(form, textvariable=self.pass_var, show="*", state="disabled")
        self.pass_entry.grid(row=3, column=1, sticky="we", pady=4)

        ttk.Label(form, text="Carpeta de salida").grid(row=4, column=0, sticky="w")
        self.outdir_var = tk.StringVar(value="reportes_remotos")
        ttk.Entry(form, textvariable=self.outdir_var).grid(row=4, column=1, sticky="we", pady=4)

        form.grid_columnconfigure(1, weight=1)

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(12, 8))
        self.run_btn = ttk.Button(actions, text="Ejecutar", style="Danger.TButton", command=self._on_run)
        self.run_btn.pack(side="left")

        self.log = LogConsole(self, height=20)
        self.log.pack(fill="both", expand=True, pady=(8, 0))

    def _toggle_creds(self) -> None:
        state = "normal" if self.alt_creds_var.get() else "disabled"
        self.user_entry.configure(state=state)
        self.pass_entry.configure(state=state)

    def _on_run(self) -> None:
        ip = self.ip_var.get().strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.log.log(f"IP invalida: {ip}", "error")
            return

        is_local, enum_reliable = local_ip.is_local_target(ip)
        if is_local:
            self.log.log(
                f"{ip} parece ser ESTA MISMA maquina. No se puede continuar: bloquearse el propio "
                "RDP de forma remota puede dejarlo sin acceso. Ejecute esta herramienta desde OTRO "
                "equipo para modificar este.", "error",
            )
            return
        if not enum_reliable:
            self.log.log(
                "No se pudo verificar de forma confiable si esta IP es esta misma maquina (ningun "
                "metodo de deteccion de IP local funciono: sin salida de red, o PowerShell no "
                "disponible/restringido). Por seguridad, no se continua.", "error",
            )
            return

        if not ask_ethical_confirmation(
            self, "Confirmacion de autorizacion", ETHICAL_WARNING,
            required_phrase="confirmo autorizacion",
        ):
            self.log.log("Operacion cancelada: autorizacion no confirmada.", "warn")
            return

        username = self.user_var.get().strip() or None if self.alt_creds_var.get() else None
        password = self.pass_var.get() or None if self.alt_creds_var.get() else None
        # Se guardan para reutilizarlos en la revalidacion de conectividad
        # posterior a cada cambio: pywinrm necesita credenciales explicitas en
        # cada llamada (no puede heredar una sesion Windows como el antiguo
        # Invoke-Command), y desde macOS/Linux no existe tal sesion.
        self._username = username
        self._password = password
        is_undo = self.undo_var.get()
        output_dir = Path(self.outdir_var.get() or "reportes_remotos")

        self.log.clear()
        self.run_btn.configure(state="disabled")
        self.log.log(f"Probando conectividad WinRM con {ip}...", "info")

        def work():
            return remote_ps.test_connectivity(ip, username, password)

        def done(result, error) -> None:
            if error is not None or not result[0]:
                self.run_btn.configure(state="normal")
                msg = str(error) if error is not None else result[1]
                self.log.log(f"No se pudo conectar: {msg}", "error")
                self.log.log("Verifique que WinRM este habilitado en el equipo objetivo (Enable-PSRemoting) y que el firewall permita el puerto 5985/5986.", "warn")
                return
            _, _, data = result
            self.log.log(f"Conectado. Host remoto: {data.get('Hostname')}, usuario efectivo: {data.get('EffectiveUser')}", "ok")
            self._results = {}
            actions = self._build_undo_actions(ip, username, password) if is_undo else self._build_apply_actions(ip, username, password)
            self._process_actions(actions, 0, ip, output_dir, is_undo)

        run_in_background(self, work, done)

    def _build_apply_actions(self, ip: str, username, password) -> List[Tuple[str, str, Callable, bool]]:
        """Cada entrada: (clave_resultado, pregunta_de_confirmacion, funcion, revalidar_conectividad)."""
        return [
            ("block_rdp", "¿Bloquear RDP (TCP 3389 entrante) en este equipo?", lambda: remote_ps.block_rdp(ip, username, password), True),
            ("harden_tls", "¿Forzar TLS mas seguro (deshabilitar SSLv2/SSLv3/TLS1.0/1.1 y cifrados debiles)?", lambda: remote_ps.harden_tls(ip, username, password), True),
        ]

    def _build_undo_actions(self, ip: str, username, password) -> List[Tuple[str, str, Callable, bool]]:
        return [
            ("undo_block_rdp", "¿Revertir el bloqueo de RDP en este equipo?", lambda: remote_ps.undo_block_rdp(ip, username, password), False),
            ("undo_harden_tls", "¿Revertir el endurecimiento de TLS en este equipo?", lambda: remote_ps.undo_harden_tls(ip, username, password), False),
        ]

    def _process_actions(self, actions: List[Tuple[str, str, Callable, bool]], index: int, ip: str, output_dir: Path, is_undo: bool) -> None:
        if index >= len(actions):
            self._write_report(ip, output_dir, is_undo)
            self.run_btn.configure(state="normal")
            self.log.log("Finalizado.", "ok")
            return

        key, question, action_fn, revalidate = actions[index]
        if not ask_ethical_confirmation(self, "Confirmar accion", question, header="Confirmar accion sobre el equipo remoto"):
            self.log.log(f"{key}: omitido.", "warn")
            self._process_actions(actions, index + 1, ip, output_dir, is_undo)
            return

        self.log.log(f"Aplicando {key}...", "info")

        def work():
            return action_fn()

        def done(result, error) -> None:
            if error is not None:
                self._results[key] = {"ok": False, "mensaje": str(error), "detalle": None}
                self.log.log(f"{key}: error - {error}", "error")
                self._process_actions(actions, index + 1, ip, output_dir, is_undo)
                return
            ok, msg, data = result
            self._results[key] = {"ok": ok, "mensaje": msg, "detalle": data}
            if ok:
                self.log.log(f"{key}: OK. {data.get('Detail') if data else ''}", "ok")
            else:
                self.log.log(f"{key}: fallo - {msg}", "error")

            if ok and revalidate:
                self._revalidate(ip, key, actions, index, output_dir, is_undo)
            else:
                self._process_actions(actions, index + 1, ip, output_dir, is_undo)

        run_in_background(self, work, done)

    def _revalidate(self, ip: str, action_key: str, actions, index: int, output_dir: Path, is_undo: bool) -> None:
        self.log.log("Revalidando conectividad WinRM tras el cambio...", "info")

        def work():
            return remote_ps.test_connectivity(ip, self._username, self._password)

        def done(result, error) -> None:
            if error is not None or not result[0]:
                msg = str(error) if error is not None else result[1]
                self._results[f"{action_key}_post_check"] = {"ok": False, "mensaje": msg, "detalle": None}
                self.log.log(
                    f"ALERTA: no se pudo confirmar conectividad WinRM despues de aplicar el cambio ({msg}). "
                    "El cambio pudo haberse aplicado igual (revise el reporte); intente reconectar por otra via "
                    "(consola local, iDRAC/iLO, otro admin) antes de asumir que el equipo esta bien.", "error",
                )
            else:
                self._results[f"{action_key}_post_check"] = {"ok": True, "mensaje": "OK", "detalle": result[2]}
                self.log.log("Conectividad WinRM confirmada despues del cambio.", "ok")
            self._process_actions(actions, index + 1, ip, output_dir, is_undo)

        run_in_background(self, work, done)

    def _write_report(self, ip: str, output_dir: Path, is_undo: bool) -> None:
        import json
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = output_dir / f"parche_remoto_{ip.replace('.', '-')}_{timestamp}.json"
        report_path.write_text(
            json.dumps(
                {"ip": ip, "fecha": datetime.now().isoformat(timespec="seconds"), "modo": "undo" if is_undo else "apply", "resultados": self._results},
                indent=2, ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        self.log.log(f"Reporte: {report_path}", "ok")
        if not is_undo:
            self.log.log(f"Para revertir: marque 'Deshacer en vez de aplicar' con la misma IP ({ip}).", "info")
