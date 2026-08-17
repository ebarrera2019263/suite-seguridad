"""Modelos de datos para la auditoria de credenciales."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class WifiFinding:
    ssid: str
    password: Optional[str]
    strength_label: str
    strength_notes: str

    def to_dict(self) -> dict:
        return {
            "ssid": self.ssid,
            "contrasena": self.password,
            "fortaleza": self.strength_label,
            "notas": self.strength_notes,
        }


@dataclass
class CredentialAttemptResult:
    username: str
    outcome: str  # "cracked" | "not_found" | "locked" | "unreachable" | "error"
    password: Optional[str] = None
    attempts_made: int = 0
    strength_label: Optional[str] = None
    strength_notes: Optional[str] = None
    protocol: Optional[str] = None  # "SMB" | "WinRM"
    detail: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "usuario": self.username,
            "resultado": self.outcome,
            "contrasena": self.password,
            "intentos_realizados": self.attempts_made,
            "fortaleza": self.strength_label,
            "notas_fortaleza": self.strength_notes,
            "protocolo": self.protocol,
            "detalle": self.detail,
        }


@dataclass
class HostCredentialReport:
    ip: str
    alive: bool = False
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    os_exact: Optional[str] = None
    attempts: List[CredentialAttemptResult] = field(default_factory=list)
    wifi_findings: List[WifiFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def any_cracked(self) -> bool:
        return any(a.outcome == "cracked" for a in self.attempts)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "activo": self.alive,
            "mac": self.mac,
            "hostname": self.hostname,
            "sistema_operativo_estimado": self.os_guess,
            "sistema_operativo_exacto": self.os_exact,
            "intentos_de_credenciales": [a.to_dict() for a in self.attempts],
            "hallazgos_wifi": [w.to_dict() for w in self.wifi_findings],
            "errores": self.errors,
        }
