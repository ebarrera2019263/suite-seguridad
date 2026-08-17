#!/usr/bin/env python
"""
Suite de Seguridad Interna
===========================
Interfaz grafica unica que agrupa las 4 herramientas de auditoria y
hardening (antes 4 .exe separados): auditoria de red, hardening local,
auditoria de credenciales y parche remoto. Cada pestana usa exactamente la
misma logica de analisis/remediacion que su herramienta de linea de
comandos original. La auditoria de red usa ip_audit_core, un paquete
COMPARTIDO en la raiz del repo que consume tanto esta GUI como el CLI
ip_audit_tool (fuente unica, sin copias divergentes); hardening_core /
credential_core / remote_patch_core siguen como copias locales de cada
core/ original. Esta aplicacion solo agrega la interfaz.

USO ETICO OBLIGATORIO: use esta aplicacion unicamente sobre redes/equipos
propios o con autorizacion explicita por escrito.
"""
from __future__ import annotations

import os
import platform
import sys
import tempfile
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

# ip_audit_core es un paquete COMPARTIDO ubicado en la raiz del repo (una sola
# fuente para la GUI y para el CLI ip_audit_tool). Al correr desde el codigo
# fuente hay que anadir la raiz del repo al path para poder importarlo; ya
# empaquetado con PyInstaller el paquete viaja en el bundle y esto es inocuo.
# Debe ejecutarse ANTES de importar los modulos tab_* (que importan
# ip_audit_core en su cabecera).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gui_common import BG, FG, apply_dark_theme

# Imports ESTATICOS (no dinamicos): PyInstaller solo empaqueta lo que puede
# ver por analisis estatico del codigo. Antes estas 4 pestanas se cargaban
# con __import__(nombre_variable), que funciona corriendo "python app.py"
# (el interprete busca el .py en disco) pero NO en el .exe congelado: el
# analizador de PyInstaller nunca veia una referencia literal a estos
# modulos, asi que no los incluia en el bundle, y las 4 pestanas fallaban
# con "No module named 'tab_ip_audit'" -- silenciado por el propio
# try/except de mas abajo, que evito que la app crasheara pero oculto el
# problema. Con "import tab_x" literal, PyInstaller los detecta y bundlea.
IS_WINDOWS = platform.system().lower() == "windows"

import tab_ip_audit
import tab_credential
import tab_remote_patch

# La pestana de Hardening Local ausculta y modifica configuracion de
# seguridad de ESTE equipo Windows (Registro, Defender, firewall de Windows,
# RDP, SMBv1...). Sus modulos importan 'winreg', que solo existe en Windows;
# en macOS/Linux ni siquiera se pueden importar. Por eso el import es
# condicional: en Windows PyInstaller sigue viendo la referencia literal
# 'import tab_hardening' (el analisis estatico ignora el if) y lo empaqueta;
# en Mac se omite y la pestana se reemplaza por un aviso (ver main()).
if IS_WINDOWS:
    import tab_hardening

_LOG_PATH = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "SuiteSeguridadInterna" / "inicio.log"


def _log_startup(message: str) -> None:
    """Deja un rastro minimo de que pestanas cargaron bien en cada arranque.
    Util porque esta es una app --windowed (sin consola): si algo falla al
    cargar una pestana, este archivo es la unica forma de diagnosticarlo
    sin tener que reproducir el problema con una terminal a mano."""
    try:
        _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now().isoformat(timespec='seconds')} {message}\n")
    except Exception:
        pass


def _selftest_pdf() -> None:
    """Genera un PDF de 1 pagina a un archivo temporal para confirmar que
    reportlab (con sus fuentes/datos empaquetados por PyInstaller via
    --collect-all) funciona de verdad DENTRO del .exe congelado, no solo
    que el modulo se pudo importar. Se corre una vez al arrancar; el
    resultado queda en el mismo log de arranque."""
    try:
        from ip_audit_core.report import export_pdf

        tmp_path = Path(tempfile.gettempdir()) / "suite_seguridad_selftest.pdf"
        export_pdf([], str(tmp_path), title="Autoprueba de arranque")
        size = tmp_path.stat().st_size
        tmp_path.unlink(missing_ok=True)
        if size > 0:
            _log_startup(f"OK: autoprueba de generacion de PDF ({size} bytes)")
        else:
            _log_startup("FALLO: autoprueba de PDF genero un archivo vacio")
    except Exception as exc:
        _log_startup(f"FALLO: autoprueba de generacion de PDF: {exc!r}")


def _hardening_placeholder(parent: tk.Widget) -> ttk.Frame:
    """Pestana sustituta de 'Hardening Local' en sistemas no-Windows. El
    hardening local ausculta configuracion propia de Windows (Registro,
    Defender, firewall de Windows, RDP...) que no tiene equivalente en macOS,
    por eso no se puede portar: seria otra herramienta. Las otras 3 pestanas
    (red, credenciales, parche remoto) SI operan sobre equipos Windows
    remotos y funcionan desde este equipo."""
    frame = ttk.Frame(parent, padding=24)
    tk.Label(
        frame, bg=BG, fg=FG, justify="left", font=("Helvetica", 13, "bold"),
        text="Hardening Local no disponible en macOS",
    ).pack(anchor="w")
    tk.Label(
        frame, bg=BG, fg="#9aa0aa", justify="left", wraplength=760,
        text=(
            "Esta funcion diagnostica y corrige la configuracion de seguridad del "
            "PROPIO equipo Windows (Registro de Windows, Windows Defender, firewall "
            "de Windows, RDP, SMBv1, etc.). Ninguno de esos componentes existe en "
            "macOS, por lo que no puede ejecutarse aqui.\n\n"
            "Para endurecer un equipo Windows, ejecute esta pestana desde ese equipo "
            "Windows. Las demas pestanas de esta suite (Auditoria de Red, Auditoria "
            "de Credenciales y Parche Remoto) SI funcionan desde esta Mac contra "
            "equipos Windows de su red."
        ),
    ).pack(anchor="w", pady=(12, 0))
    return frame


def main() -> int:
    root = tk.Tk()
    root.title("Suite de Seguridad Interna")
    root.geometry("1040x720")
    root.minsize(860, 600)
    apply_dark_theme(root)

    header = ttk.Frame(root, padding=(16, 12, 16, 0))
    header.pack(fill="x")
    tk.Label(header, text="Suite de Seguridad Interna", bg=BG, fg=FG, font=("Segoe UI", 15, "bold")).pack(side="left")
    tk.Label(
        header, bg=BG, fg="#9aa0aa", font=("Segoe UI", 9),
        text="Uso exclusivo sobre equipos/redes propios o con autorizacion explicita.",
    ).pack(side="right")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=12, pady=12)

    hardening_factory = tab_hardening.HardeningTab if IS_WINDOWS else _hardening_placeholder
    tabs = [
        ("Auditoria de Red", tab_ip_audit.IpAuditTab),
        ("Hardening Local", hardening_factory),
        ("Auditoria de Credenciales", tab_credential.CredentialTab),
        ("Parche Remoto", tab_remote_patch.RemotePatchTab),
    ]
    _log_startup(f"Iniciando Suite de Seguridad Interna (frozen={getattr(sys, 'frozen', False)})")
    _selftest_pdf()
    for label, tab_cls in tabs:
        try:
            frame = tab_cls(notebook)
            notebook.add(frame, text=label)
            _log_startup(f"OK: {label}")
        except Exception as exc:  # pragma: no cover - red de seguridad de la GUI
            _log_startup(f"FALLO: {label}: {exc!r}")
            placeholder = ttk.Frame(notebook, padding=16)
            tk.Label(
                placeholder, bg=BG, fg="#f87171", justify="left",
                text=f"No se pudo cargar esta pestana:\n{exc}",
            ).pack(anchor="w")
            notebook.add(placeholder, text=f"{label} (error)")

    root.mainloop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover
        _log_startup(f"ERROR FATAL: {exc!r}")
        try:
            messagebox.showerror("Error inesperado", str(exc))
        except Exception:
            print(f"Error inesperado: {exc}", file=sys.stderr)
        sys.exit(1)
