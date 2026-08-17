"""Heurísticas para estimar sistema operativo y tipo de dispositivo.

No sustituye a un fingerprinting completo (nmap -O / p0f). Se basa en:
  * TTL de la respuesta ICMP (Windows ~128, Linux/Unix ~64, red Cisco ~255).
  * Puertos abiertos característicos (445+3389 => Windows; 22 sin 445 => *nix).
  * Banners de servicios ya capturados por otros módulos.
"""
from __future__ import annotations

from typing import Dict, Iterable, Optional

from .models import ServiceInfo


def guess_os_from_ttl(ttl: Optional[int]) -> Optional[str]:
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/Unix (TTL<=64)"
    if ttl <= 128:
        return "Windows (TTL<=128)"
    return "Red/Dispositivo (TTL>128, posible router/switch)"


def refine_os_guess(base_guess: Optional[str], open_ports: Iterable[int], services: Dict[int, ServiceInfo]) -> str:
    open_ports = set(open_ports)
    banners = " ".join((s.banner or "") for s in services.values()).lower()

    if "windows" in banners or "microsoft" in banners:
        return "Windows"
    if "ubuntu" in banners or "debian" in banners:
        return "Linux (Debian/Ubuntu)"
    if "centos" in banners or "red hat" in banners or "rhel" in banners:
        return "Linux (RHEL/CentOS)"

    has_windows_ports = bool(open_ports & {135, 139, 445, 3389, 5985, 5986})
    has_unix_ports = 22 in open_ports and not (open_ports & {135, 445, 3389})

    if has_windows_ports:
        return base_guess or "Windows (heuristico por puertos)"
    if has_unix_ports:
        return base_guess or "Linux/Unix (heuristico por puertos)"

    return base_guess or "Desconocido"


def guess_device_type(open_ports: Iterable[int], hostname: Optional[str] = None) -> str:
    open_ports = set(open_ports)
    hostname = (hostname or "").lower()

    server_signals = len(
        open_ports & {21, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 5432, 8080, 8443, 25565}
    )
    workstation_only_signals = bool(open_ports & {3389, 5900}) and not server_signals

    if any(tag in hostname for tag in ("srv", "server", "dc", "sql", "web", "app")):
        return "Servidor"
    if any(tag in hostname for tag in ("pc-", "ws-", "desktop", "laptop", "notebook")):
        return "Estacion de trabajo"

    if server_signals >= 1:
        return "Servidor"
    if workstation_only_signals:
        return "Estacion de trabajo"
    if open_ports:
        return "Dispositivo de red / IoT (indeterminado)"
    return "Desconocido"
