"""Modelos de datos para el motor de verificacion/remediacion local."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "Critica"
    HIGH = "Alta"
    MEDIUM = "Media"
    LOW = "Baja"
    INFO = "Informativa"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]

    @property
    def color(self) -> str:
        colors = {
            Severity.CRITICAL: "bold white on red",
            Severity.HIGH: "bold red",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold cyan",
            Severity.INFO: "dim",
        }
        return colors[self]

    @property
    def hex(self) -> str:
        colors = {
            Severity.CRITICAL: "#7f1d1d",
            Severity.HIGH: "#b91c1c",
            Severity.MEDIUM: "#b45309",
            Severity.LOW: "#0e7490",
            Severity.INFO: "#4b5563",
        }
        return colors[self]


@dataclass
class CheckResult:
    """Resultado de una verificacion de configuracion local."""

    check_id: str
    title: str
    category: str
    severity: Severity
    vulnerable: bool
    detail: str
    recommendation: str
    fixable: bool = False
    manual_only: bool = False
    determinable: bool = True
    fix_applied: Optional[bool] = None
    fix_message: Optional[str] = None
    undo_hint: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.check_id,
            "titulo": self.title,
            "categoria": self.category,
            "severidad": self.severity.value,
            "vulnerable": self.vulnerable,
            "determinable": self.determinable,
            "detalle": self.detail,
            "recomendacion": self.recommendation,
            "corregible_automaticamente": self.fixable,
            "solo_manual": self.manual_only,
            "correccion_aplicada": self.fix_applied,
            "mensaje_correccion": self.fix_message,
            "sugerencia_para_deshacer": self.undo_hint,
        }
