"""Punto de restauracion del sistema y script de reversion de cambios.
Todo opera exclusivamente sobre el equipo local."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from .ps import run_ps


def create_restore_point(description: str = "IP Hardening Tool - antes de aplicar correcciones") -> Tuple[bool, str]:
    """Intenta crear un punto de restauracion de Windows. No todos los
    equipos lo tienen habilitado (Windows Server no lo trae por defecto, y
    Windows solo permite un punto de restauracion cada 24h salvo que se
    cambie esa politica). Un fallo aqui NO detiene la ejecucion del resto
    de la herramienta, solo se informa al usuario."""
    try:
        proc = run_ps(
            f'Checkpoint-Computer -Description "{description}" -RestorePointType "MODIFY_SETTINGS"',
            timeout=60,
        )
        if proc.returncode == 0:
            return True, "Punto de restauracion creado correctamente."
        msg = (proc.stderr or proc.stdout or "").strip()
        return False, f"No se pudo crear el punto de restauracion: {msg[:300] or 'motivo desconocido'}"
    except Exception as exc:
        return False, f"No se pudo crear el punto de restauracion: {exc}"


def write_undo_script(output_dir: Path, undo_entries: List[Tuple[str, str]]) -> Path:
    """Genera un script de PowerShell con los comandos para revertir cada
    correccion aplicada en esta sesion. undo_entries: lista de (titulo, comando)."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"deshacer_{timestamp}.ps1"

    lines = [
        "# Script de reversion generado por IP Hardening Tool.",
        "# Ejecutar como Administrador SOLO si necesita revertir manualmente",
        "# alguna de las correcciones aplicadas en la sesion correspondiente.",
        "# Revise cada linea antes de ejecutarla: algunas revierten a un",
        "# estado MENOS seguro (se marcan explicitamente).",
        "",
    ]
    if not undo_entries:
        lines.append("# No se aplico ninguna correccion en esta sesion; nada que deshacer.")
    for title, command in undo_entries:
        lines.append(f"# --- {title} ---")
        lines.append(command)
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
