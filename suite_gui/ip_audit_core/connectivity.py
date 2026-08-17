"""Prueba de conectividad de caja negra (blackbox): verifica que un host es
alcanzable y que los paquetes efectivamente se envian y regresan, midiendo
paquetes enviados/recibidos, perdida y latencia. Es un diagnostico de red
estandar (equivalente a un 'ping' + prueba de handshake TCP + sondeo UDP),
NO un ataque: la cantidad de paquetes esta acotada por diseno (nunca inunda).

Blackbox = solo necesita la IP del objetivo; no requiere credenciales ni
conocimiento interno del host.
"""
from __future__ import annotations

import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional

_IS_WINDOWS = platform.system().lower() == "windows"

# Tope duro: por mas que se pida mas, nunca se envian mas de estos paquetes
# por protocolo. Asi la prueba jamas se convierte en una inundacion.
_MAX_PACKETS = 10


@dataclass
class TcpPortProbe:
    port: int
    attempts: int
    established: int
    avg_ms: Optional[float]


@dataclass
class ConnectivityResult:
    ip: str
    reachable: bool = False
    # ICMP (ping del sistema)
    icmp_sent: int = 0
    icmp_recv: int = 0
    icmp_loss_pct: Optional[float] = None
    icmp_avg_ms: Optional[float] = None
    # TCP (handshake a puertos)
    tcp_probes: List[TcpPortProbe] = field(default_factory=list)
    # UDP (envio y espera de respuesta)
    udp_port: Optional[int] = None
    udp_sent: int = 0
    udp_responded: int = 0
    notes: List[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = []
        if self.icmp_sent:
            parts.append(f"ICMP {self.icmp_recv}/{self.icmp_sent} recibidos "
                         f"({self.icmp_loss_pct:.0f}% perdida"
                         + (f", {self.icmp_avg_ms:.1f} ms avg" if self.icmp_avg_ms is not None else "") + ")")
        for t in self.tcp_probes:
            parts.append(f"TCP {t.port}: {t.established}/{t.attempts} handshakes"
                         + (f", {t.avg_ms:.1f} ms avg" if t.avg_ms is not None else ""))
        if self.udp_sent:
            parts.append(f"UDP {self.udp_port}: {self.udp_responded}/{self.udp_sent} respondieron")
        return " | ".join(parts) if parts else "sin datos"


def _icmp_ping(ip: str, count: int, timeout_s: float, result: ConnectivityResult) -> None:
    count = max(1, min(count, _MAX_PACKETS))
    if _IS_WINDOWS:
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout_s * 1000)), ip]
    else:
        # macOS/Linux: -c cuenta, -t timeout total (mac) / se acota con timeout de subprocess.
        cmd = ["ping", "-c", str(count), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout_s + 5)
    except Exception as exc:
        result.notes.append(f"ICMP: no se pudo ejecutar ping ({exc})")
        return
    out = proc.stdout or ""
    result.icmp_sent = count

    # Recibidos: "N received" / "N packets received" (Unix) o "Received = N" (Windows).
    m_recv = re.search(r"(\d+)\s+(?:packets\s+)?received", out) or re.search(r"Received\s*=\s*(\d+)", out)
    if m_recv:
        result.icmp_recv = int(m_recv.group(1))
    # Perdida: "X% packet loss" (Unix) o "(N% loss)" (Windows).
    m_loss = re.search(r"([\d.]+)%\s*(?:packet )?loss", out)
    if m_loss:
        result.icmp_loss_pct = float(m_loss.group(1))
    elif result.icmp_sent:
        result.icmp_loss_pct = 100.0 * (result.icmp_sent - result.icmp_recv) / result.icmp_sent
    # Latencia promedio: "min/avg/max" (Unix) o "Average = Nms" (Windows).
    m_rtt = re.search(r"=\s*[\d.]+/([\d.]+)/", out) or re.search(r"Average\s*=\s*(\d+)ms", out)
    if m_rtt:
        result.icmp_avg_ms = float(m_rtt.group(1))
    if result.icmp_recv > 0:
        result.reachable = True


def _tcp_handshake(ip: str, port: int, attempts: int, timeout_s: float) -> TcpPortProbe:
    attempts = max(1, min(attempts, _MAX_PACKETS))
    established = 0
    times: List[float] = []
    for _ in range(attempts):
        t0 = time.time()
        try:
            with socket.create_connection((ip, port), timeout=timeout_s):
                established += 1
                times.append((time.time() - t0) * 1000.0)
        except Exception:
            pass
    avg = round(sum(times) / len(times), 1) if times else None
    return TcpPortProbe(port=port, attempts=attempts, established=established, avg_ms=avg)


def _udp_probe(ip: str, port: int, count: int, timeout_s: float) -> tuple:
    count = max(1, min(count, _MAX_PACKETS))
    responded = 0
    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout_s)
            sock.sendto(b"\x00", (ip, port))
            sock.recvfrom(4096)
            responded += 1
        except Exception:
            pass
        finally:
            sock.close()
    return count, responded


def connectivity_test(
    ip: str,
    tcp_ports: Optional[List[int]] = None,
    count: int = 4,
    timeout_s: float = 1.5,
    udp_port: Optional[int] = None,
) -> ConnectivityResult:
    """Ejecuta la prueba blackbox: ICMP (ping), handshake TCP a `tcp_ports` y
    un sondeo UDP opcional. `count` paquetes por prueba (acotado a
    _MAX_PACKETS). Devuelve un ConnectivityResult con las metricas."""
    result = ConnectivityResult(ip=ip)

    _icmp_ping(ip, count, timeout_s, result)

    # Handshake TCP a unos pocos puertos (los indicados, o un set por defecto).
    ports = tcp_ports or [443, 80, 445, 22]
    for port in ports[:6]:  # tope de puertos para no alargar la prueba
        probe = _tcp_handshake(ip, port, count, timeout_s)
        result.tcp_probes.append(probe)
        if probe.established > 0:
            result.reachable = True

    if udp_port is not None:
        result.udp_port = udp_port
        result.udp_sent, result.udp_responded = _udp_probe(ip, udp_port, count, timeout_s)
        if result.udp_responded > 0:
            result.reachable = True

    return result
