"""
Descubrimiento de host: vida (ping), direccion MAC, hostname (DNS inverso
y NetBIOS) y TTL (usado luego para estimar el sistema operativo).

Se evita depender obligatoriamente de Scapy/Npcap: se usa el comando
'ping' del sistema (subprocess) como metodo primario, portable entre
Windows y Linux/macOS, y se intenta Scapy solo si esta disponible y el
proceso tiene privilegios (para ARP en LAN local).
"""
from __future__ import annotations

import platform
import re
import socket
import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

IS_WINDOWS = platform.system().lower() == "windows"

try:
    from scapy.all import ARP, Ether, srp  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


@dataclass
class PingResult:
    alive: bool
    ttl: Optional[int] = None
    avg_ms: Optional[float] = None


def ping_host(ip: str, timeout_s: float = 1.5) -> PingResult:
    """Hace ping usando el binario del sistema operativo (no requiere privilegios
    de administrador, a diferencia de ICMP raw sockets)."""
    timeout_ms = int(timeout_s * 1000)
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), ip]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 2,
        )
    except Exception:
        return PingResult(alive=False)

    output = proc.stdout or ""
    alive = proc.returncode == 0 and (
        "TTL=" in output.upper() or "ttl=" in output
    )
    ttl = None
    ttl_match = re.search(r"[Tt][Tt][Ll][=:](\d+)", output)
    if ttl_match:
        ttl = int(ttl_match.group(1))

    avg_ms = None
    avg_match = re.search(r"(?:Average|avg)[^0-9]*([0-9.]+)\s*ms", output, re.IGNORECASE)
    if not avg_match:
        avg_match = re.search(r"time[=<]([0-9.]+)\s*ms", output, re.IGNORECASE)
    if avg_match:
        try:
            avg_ms = float(avg_match.group(1))
        except ValueError:
            pass

    return PingResult(alive=alive, ttl=ttl, avg_ms=avg_ms)


def tcp_probe_alive(ip: str, ports=(80, 443, 22, 3389, 445), timeout_s: float = 0.8) -> bool:
    """Fallback: si ICMP esta bloqueado, intenta abrir conexion TCP a puertos
    comunes para confirmar que el host esta vivo."""
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout_s):
                return True
        except Exception:
            continue
    return False


def reverse_dns(ip: str, timeout_s: float = 2.0) -> Optional[str]:
    ## socket.gethostbyaddr() no acepta un timeout por-llamada; el unico
    ## mecanismo del modulo socket es setdefaulttimeout(), que es GLOBAL AL
    ## PROCESO (no por hilo). Como analyze_host() corre en paralelo dentro
    ## de un ThreadPoolExecutor, usar setdefaulttimeout() aqui pisaria el
    ## timeout de otros hilos en pleno vuelo. En su lugar, se corre la
    ## resolucion en un hilo propio y se le aplica el timeout con join(),
    ## sin tocar ningun estado global compartido.
    result: dict = {"name": None}

    def _resolve() -> None:
        try:
            result["name"], _, _ = socket.gethostbyaddr(ip)
        except Exception:
            pass

    thread = threading.Thread(target=_resolve, daemon=True)
    thread.start()
    thread.join(timeout_s)
    return result["name"]


def netbios_name(ip: str, timeout_s: float = 2.0) -> Optional[str]:
    """Obtiene el nombre NetBIOS de la maquina. En Windows usa 'nbtstat -A',
    en otros sistemas intenta una consulta NBT cruda sobre UDP/137."""
    if IS_WINDOWS:
        try:
            proc = subprocess.run(
                ["nbtstat", "-A", ip],
                capture_output=True,
                text=True,
                timeout=timeout_s + 2,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                m = re.match(r"^([A-Za-z0-9\-_.]+)\s+<00>\s+UNIQUE", line)
                if m:
                    return m.group(1)
        except Exception:
            return None
        return None

    # Consulta NBT minima (UDP/137) para sistemas no Windows.
    try:
        transaction_id = b"\x82\x28"
        header = transaction_id + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        query = (
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
            b"\x00\x21\x00\x01"
        )
        packet = header + query
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout_s)
            s.sendto(packet, (ip, 137))
            data, _ = s.recvfrom(1024)
            # El primer nombre NetBIOS empieza en offset 57, longitud 15 (padded).
            raw_name = data[57:57 + 15].decode("ascii", errors="ignore").strip()
            return raw_name if raw_name else None
    except Exception:
        return None


def get_mac_address(ip: str, timeout_s: float = 2.0) -> Optional[str]:
    """Obtiene la MAC. Primero intenta Scapy/ARP (requiere admin/root + Npcap
    en Windows); si no esta disponible, recurre a leer la tabla ARP del SO
    (requiere que el host ya haya sido contactado, p.ej. via ping)."""
    if SCAPY_AVAILABLE:
        try:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=timeout_s,
                verbose=False,
            )
            for _, received in answered:
                return received.hwsrc
        except Exception:
            pass

    return _mac_from_arp_table(ip)


def _mac_from_arp_table(ip: str) -> Optional[str]:
    try:
        if IS_WINDOWS:
            proc = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3)
            mac_match = re.search(r"([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", proc.stdout)
        else:
            proc = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
            mac_match = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", proc.stdout)
        if mac_match:
            return mac_match.group(0).upper().replace("-", ":")
    except Exception:
        return None
    return None


def discover_host(ip: str, ping_timeout_s: float = 1.5) -> dict:
    """Orquesta el descubrimiento basico de un host. Devuelve un dict con
    alive/ttl/mac/hostname/netbios_name."""
    ping = ping_host(ip, timeout_s=ping_timeout_s)
    alive = ping.alive
    if not alive:
        alive = tcp_probe_alive(ip)

    result = {
        "alive": alive,
        "ttl": ping.ttl,
        "mac": None,
        "hostname": None,
        "netbios_name": None,
    }
    if not alive:
        return result

    result["mac"] = get_mac_address(ip)
    result["hostname"] = reverse_dns(ip)
    result["netbios_name"] = netbios_name(ip)
    return result
