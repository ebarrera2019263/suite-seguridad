"""Utilidades compartidas por las 4 pestanas de la Suite de Seguridad.

Nada de logica de auditoria/hardening vive aca: esto es solo la capa de
interfaz (consola de log thread-safe, ejecucion en segundo plano, dialogos
de confirmacion etica) que envuelve a ip_audit_core / hardening_core /
credential_core / remote_patch_core sin modificarlos.
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Callable, Optional

SEVERITY_HEX = {
    "Critica": "#7f1d1d",
    "Alta": "#b91c1c",
    "Media": "#b45309",
    "Baja": "#0e7490",
    "Informativa": "#4b5563",
}
SEVERITY_ORDER = {"Critica": 4, "Alta": 3, "Media": 2, "Baja": 1, "Informativa": 0}

BG = "#1e1f24"
PANEL = "#2a2b32"
FG = "#e6e6e9"
ACCENT = "#4f8cff"
MUTED = "#9aa0aa"


def apply_dark_theme(root: tk.Tk) -> None:
    root.configure(bg=BG)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL, font=("Segoe UI", 10))
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED)
    style.configure("Header.TLabel", background=BG, foreground=FG, font=("Segoe UI", 13, "bold"))
    style.configure("TButton", background="#33343c", foreground=FG, padding=6)
    style.map("TButton", background=[("active", "#3d3e47")])
    style.configure("Accent.TButton", background=ACCENT, foreground="white", padding=8)
    style.map("Accent.TButton", background=[("active", "#3a72d9"), ("disabled", "#3a3b42")])
    style.configure("Danger.TButton", background="#b91c1c", foreground="white", padding=8)
    style.map("Danger.TButton", background=[("active", "#961717")])
    style.configure("TEntry", fieldbackground=PANEL, foreground=FG, insertcolor=FG)
    style.configure("TCheckbutton", background=BG, foreground=FG)
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background="#26272d", foreground=MUTED, padding=(14, 8))
    style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", FG)])
    style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, rowheight=24, borderwidth=0)
    style.configure("Treeview.Heading", background="#33343c", foreground=FG, relief="flat")
    style.map("Treeview", background=[("selected", "#3a4a63")])


class LogConsole(ttk.Frame):
    """Panel de log con scroll, seguro para escribir desde otros hilos:
    log() solo encola el mensaje; el widget se actualiza en el hilo
    principal de Tk via after()."""

    LEVEL_COLORS = {
        "info": FG,
        "ok": "#4ade80",
        "warn": "#fbbf24",
        "error": "#f87171",
    }

    def __init__(self, parent: tk.Widget, height: int = 14):
        super().__init__(parent, style="Panel.TFrame")
        self._queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self.text = tk.Text(
            self, height=height, bg=PANEL, fg=FG, insertbackground=FG,
            relief="flat", wrap="word", state="disabled", font=("Consolas", 9),
        )
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True, padx=(2, 0), pady=2)
        scroll.pack(side="right", fill="y")
        for level, color in self.LEVEL_COLORS.items():
            self.text.tag_configure(level, foreground=color)
        self.after(120, self._drain)

    def log(self, message: str, level: str = "info") -> None:
        """Llamable desde cualquier hilo."""
        self._queue.put((message, level))

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def _drain(self) -> None:
        drained = False
        try:
            while True:
                message, level = self._queue.get_nowait()
                self.text.configure(state="normal")
                self.text.insert("end", message + "\n", (level,))
                self.text.configure(state="disabled")
                drained = True
        except queue.Empty:
            pass
        if drained:
            self.text.see("end")
        self.after(120, self._drain)


class UiBridge:
    """Puente generico hilo-de-trabajo -> hilo principal de Tk. Cualquier
    hilo puede post() una funcion sin argumentos; se ejecuta en el hilo de
    Tk la proxima vez que se vacia la cola. Evita el error comun de llamar
    metodos de un widget (incluido .after()) directamente desde un hilo que
    no es el principal, que Tcl/Tk no garantiza soportar."""

    def __init__(self, root: tk.Widget, interval_ms: int = 80):
        self._root = root
        self._queue: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self._interval_ms = interval_ms
        self._root.after(self._interval_ms, self._pump)

    def post(self, fn: Callable[[], None]) -> None:
        self._queue.put(fn)

    def _pump(self) -> None:
        try:
            while True:
                fn = self._queue.get_nowait()
                try:
                    fn()
                except Exception:
                    pass
        except queue.Empty:
            pass
        self._root.after(self._interval_ms, self._pump)


def run_in_background(
    root: tk.Widget,
    work: Callable[[], object],
    on_done: Optional[Callable[[Optional[object], Optional[BaseException]], None]] = None,
) -> threading.Thread:
    """Corre `work()` en un hilo daemon aparte. Cuando termina (con
    resultado o excepcion), programa `on_done(resultado, excepcion)` en el
    hilo principal de Tk via root.after(), nunca toca widgets directamente
    desde el hilo de trabajo."""

    def _runner() -> None:
        result: Optional[object] = None
        error: Optional[BaseException] = None
        try:
            result = work()
        except BaseException as exc:  # noqa: BLE001 - se reporta a la GUI, no se traga
            error = exc
        if on_done is not None:
            root.after(0, lambda: on_done(result, error))

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    return thread


class BusyButton(ttk.Button):
    """Boton que se deshabilita y cambia de texto mientras una accion en
    segundo plano esta en curso, para que el usuario no pueda lanzar la
    misma accion dos veces en paralelo."""

    def __init__(self, parent, text: str, command: Callable[[], None], busy_text: str = "Ejecutando...", **kw):
        self._idle_text = text
        self._busy_text = busy_text
        self._command = command
        super().__init__(parent, text=text, command=self._on_click, **kw)

    def _on_click(self) -> None:
        self._command()

    def set_busy(self, busy: bool) -> None:
        self.configure(text=self._busy_text if busy else self._idle_text)
        self.configure(state="disabled" if busy else "normal")


def labeled_row(parent: tk.Widget, row: int, label: str, widget_factory: Callable[[tk.Widget], tk.Widget], hint: str = "") -> tk.Widget:
    """Arma una fila de formulario: etiqueta a la izquierda, widget al
    medio, hint chico opcional a la derecha. Devuelve el widget creado."""
    ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=4)
    widget = widget_factory(parent)
    widget.grid(row=row, column=1, sticky="we", pady=4)
    if hint:
        ttk.Label(parent, text=hint, style="Muted.TLabel").grid(row=row, column=2, sticky="w", padx=(8, 0))
    parent.grid_columnconfigure(1, weight=1)
    return widget


def open_path(path: os.PathLike | str) -> None:
    """Abre un archivo/carpeta con la aplicacion asociada del sistema.
    Multiplataforma: os.startfile en Windows, 'open' en macOS, 'xdg-open' en
    Linux. (os.startfile solo existe en Windows, por eso no se puede usar a
    secas: en Mac lanzaba AttributeError que se tragaba el except y el boton
    'Abrir reporte' no hacia nada.)"""
    target = str(path)
    try:
        startfile = getattr(os, "startfile", None)
        if startfile is not None:  # Windows
            startfile(target)  # noqa: S606 - abre un reporte propio recien generado, no una URL/ruta externa
            return
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.Popen([opener, target])
    except Exception:
        pass


class EthicalConfirmDialog(tk.Toplevel):
    """Modal que replica la confirmacion etica/legal que cada CLI original
    exige antes de escanear o modificar algo. No es decorativo: si el
    usuario no confirma (o no escribe la frase exacta cuando se exige),
    self.confirmed queda False y el llamador NO debe ejecutar la accion."""

    def __init__(
        self, parent: tk.Widget, title: str, warning: str,
        required_phrase: Optional[str] = None, header: str = "⚠  Aviso legal y etico",
        confirm_label: str = "Confirmo que cuento con autorizacion para esta accion.",
    ):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.confirmed = False
        self._required_phrase = required_phrase

        container = ttk.Frame(self, padding=18)
        container.pack(fill="both", expand=True)

        header_lbl = tk.Label(container, text=header, bg=BG, fg="#fbbf24", font=("Segoe UI", 12, "bold"))
        header_lbl.pack(anchor="w", pady=(0, 8))

        msg = tk.Label(container, text=warning, bg=BG, fg=FG, justify="left", wraplength=480, font=("Segoe UI", 10))
        msg.pack(anchor="w", pady=(0, 12))

        if required_phrase:
            ttk.Label(container, text=f"Escriba exactamente: \"{required_phrase}\"").pack(anchor="w")
            self._entry_var = tk.StringVar()
            entry = ttk.Entry(container, textvariable=self._entry_var, width=40)
            entry.pack(anchor="w", pady=(4, 12), fill="x")
            entry.focus_set()
        else:
            self._check_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                container, variable=self._check_var,
                text=confirm_label,
            ).pack(anchor="w", pady=(0, 12))

        btns = ttk.Frame(container)
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancelar", command=self._cancel).pack(side="right", padx=(8, 0))
        ttk.Button(btns, text="Confirmar", style="Accent.TButton", command=self._confirm).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.update_idletasks()
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - self.winfo_width()) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - self.winfo_height()) // 2)
        self.geometry(f"+{x}+{y}")

    def _confirm(self) -> None:
        if self._required_phrase:
            self.confirmed = self._entry_var.get().strip().lower() == self._required_phrase.strip().lower()
        else:
            self.confirmed = bool(self._check_var.get())
        self.destroy()

    def _cancel(self) -> None:
        self.confirmed = False
        self.destroy()


def ask_ethical_confirmation(
    parent: tk.Widget, title: str, warning: str, required_phrase: Optional[str] = None,
    header: str = "⚠  Aviso legal y etico",
    confirm_label: str = "Confirmo que cuento con autorizacion para esta accion.",
) -> bool:
    dialog = EthicalConfirmDialog(parent, title, warning, required_phrase, header, confirm_label)
    parent.wait_window(dialog)
    return dialog.confirmed


class FindingsTable(ttk.Frame):
    """Tabla de hallazgos ordenable por severidad, comun a las 4 pestanas."""

    def __init__(self, parent: tk.Widget, columns: list[tuple[str, str, int]]):
        """columns: lista de (key, encabezado, ancho)."""
        super().__init__(parent)
        self._keys = [c[0] for c in columns]
        self.tree = ttk.Treeview(self, columns=self._keys, show="headings", selectmode="browse")
        for key, heading, width in columns:
            self.tree.heading(key, text=heading)
            self.tree.column(key, width=width, anchor="w")
        vscroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")
        for sev, hexcolor in SEVERITY_HEX.items():
            self.tree.tag_configure(sev, foreground=hexcolor)

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())

    def add_row(self, values: list, severity_tag: Optional[str] = None, iid: Optional[str] = None) -> str:
        tags = (severity_tag,) if severity_tag in SEVERITY_HEX else ()
        return self.tree.insert("", "end", iid=iid, values=values, tags=tags)


def int_entry(parent: tk.Widget, default: int) -> ttk.Entry:
    var = tk.StringVar(value=str(default))
    entry = ttk.Entry(parent, textvariable=var, width=10)
    entry.var = var  # type: ignore[attr-defined]
    return entry


def get_int(entry: ttk.Entry, fallback: int) -> int:
    try:
        return int(entry.var.get().strip())  # type: ignore[attr-defined]
    except Exception:
        return fallback


def get_float(entry: ttk.Entry, fallback: float) -> float:
    try:
        return float(entry.var.get().strip())  # type: ignore[attr-defined]
    except Exception:
        return fallback
