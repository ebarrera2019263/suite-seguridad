"""Modelos de datos compartidos por toda la herramienta."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


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


@dataclass
class Vulnerability:
    """Un hallazgo individual asociado a un host (y opcionalmente a un puerto)."""

    title: str
    category: str
    severity: Severity
    description: str
    recommendation: str
    port: Optional[int] = None
    evidence: Optional[str] = None
    cve_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "titulo": self.title,
            "categoria": self.category,
            "severidad": self.severity.value,
            "puerto": self.port,
            "descripcion": self.description,
            "evidencia": self.evidence,
            "recomendacion": self.recommendation,
            "cves": self.cve_refs,
        }


@dataclass
class ServiceInfo:
    """Información recolectada sobre un servicio detectado en un puerto abierto."""

    port: int
    name: str = "desconocido"
    banner: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "puerto": self.port,
            "servicio": self.name,
            "banner": self.banner,
            "producto": self.product,
            "version": self.version,
            "detalle": self.extra,
        }


@dataclass
class HostResult:
    """Resultado consolidado del análisis de un host."""

    ip: str
    alive: bool = False
    mac: Optional[str] = None
    hostname: Optional[str] = None
    netbios_name: Optional[str] = None
    os_guess: Optional[str] = None
    device_type: str = "Desconocido"
    ttl: Optional[int] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, ServiceInfo] = field(default_factory=dict)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_duration_s: float = 0.0
    errors: List[str] = field(default_factory=list)

    def add_vuln(self, vuln: Vulnerability) -> None:
        self.vulnerabilities.append(vuln)

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.vulnerabilities:
            return None
        return max((v.severity for v in self.vulnerabilities), key=lambda s: s.rank)

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "activo": self.alive,
            "mac": self.mac,
            "hostname": self.hostname,
            "nombre_netbios": self.netbios_name,
            "sistema_operativo": self.os_guess,
            "tipo_dispositivo": self.device_type,
            "ttl": self.ttl,
            "puertos_abiertos": self.open_ports,
            "servicios": {str(p): s.to_dict() for p, s in self.services.items()},
            "vulnerabilidades": [v.to_dict() for v in self.vulnerabilities],
            "resumen_severidad": self.severity_counts(),
            "duracion_escaneo_s": round(self.scan_duration_s, 2),
            "errores": self.errors,
        }
