"""Inventario basico sin autenticacion: vida del host, MAC, hostname y una
estimacion de SO por TTL. Mismo enfoque que ip_audit_tool, reescrito aqui
para que esta carpeta sea autocontenida."""
from __future__ import annotations

import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Optional

IS_WINDOWS = platform.system().lower() == "windows"


@dataclass
class PingResult:
    alive: bool
    ttl: Optional[int] = None


def ping_host(ip: str, timeout_s: float = 1.5) -> PingResult:
    timeout_ms = int(timeout_s * 1000)
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if IS_WINDOWS else ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 2)
    except Exception:
        return PingResult(alive=False)
    output = proc.stdout or ""
    alive = proc.returncode == 0 and "ttl" in output.lower()
    ttl_match = re.search(r"[Tt][Tt][Ll][=:](\d+)", output)
    ttl = int(ttl_match.group(1)) if ttl_match else None
    return PingResult(alive=alive, ttl=ttl)


def tcp_probe_alive(ip: str, ports=(445, 3389, 135, 80, 443), timeout_s: float = 0.8) -> bool:
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout_s):
                return True
        except Exception:
            continue
    return False


def reverse_dns(ip: str, timeout_s: float = 2.0) -> Optional[str]:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_s)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def get_mac_address(ip: str) -> Optional[str]:
    try:
        if IS_WINDOWS:
            proc = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3)
            m = re.search(r"([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", proc.stdout)
            return m.group(0).upper().replace("-", ":") if m else None
        proc = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
        m = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", proc.stdout)
        return m.group(0).upper() if m else None
    except Exception:
        return None


def guess_os_from_ttl(ttl: Optional[int]) -> Optional[str]:
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/Unix (TTL<=64)"
    if ttl <= 128:
        return "Windows (TTL<=128)"
    return "Red/Dispositivo (TTL>128)"


def gather_inventory(ip: str) -> dict:
    ping = ping_host(ip)
    alive = ping.alive or tcp_probe_alive(ip)
    return {
        "alive": alive,
        "mac": get_mac_address(ip) if alive else None,
        "hostname": reverse_dns(ip) if alive else None,
        "os_guess": guess_os_from_ttl(ping.ttl),
    }
