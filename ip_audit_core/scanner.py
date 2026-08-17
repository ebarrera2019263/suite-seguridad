"""Escaneo de puertos TCP con concurrencia y captura de banners."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from .vuln_db import COMMON_SERVICE_NAMES


def scan_port(ip: str, port: int, timeout_s: float = 0.9) -> bool:
    ## socket.create_connection() resuelve la familia (IPv4/IPv6) via
    ## getaddrinfo, asi que funciona con objetivos IPv6 -- antes se forzaba
    ## AF_INET y cualquier IP v6 daba 0 puertos abiertos (resultado
    ## falsamente "limpio").
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def scan_ports(
    ip: str,
    ports: List[int],
    timeout_s: float = 0.9,
    max_workers: int = 100,
) -> List[int]:
    """Escanea una lista de puertos para una IP en paralelo (hilos)."""
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(ports)))) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout_s): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                continue
    return sorted(open_ports)


def grab_banner(ip: str, port: int, timeout_s: float = 2.0, send_probe: bool = True) -> Optional[str]:
    """Intenta capturar el banner de un servicio TCP. Para servicios que no
    envian banner de forma proactiva (HTTP), envia una solicitud minima."""
    try:
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            try:
                data = sock.recv(1024)
            except socket.timeout:
                data = b""

            ## Solo enviar la sonda HTTP en claro a puertos HTTP planos. Antes
            ## se enviaba tambien a 443/8443 (TLS), donde el servidor espera un
            ## ClientHello: respondia con bytes de alerta TLS que se guardaban
            ## como "banner" basura. El header Server sobre HTTPS se obtiene
            ## aparte, reutilizando el socket TLS ya establecido (ver
            ## ssl_analyzer.grab_https_server_header).
            if not data and send_probe and port in (80, 8080, 8000):
                try:
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    data = sock.recv(2048)
                except Exception:
                    pass

            if data:
                return data.decode(errors="ignore").strip()
            return None
    except Exception:
        return None


def identify_service(port: int, banner: Optional[str]) -> str:
    name = COMMON_SERVICE_NAMES.get(port, "desconocido")
    if banner:
        lowered = banner.lower()
        if "ssh" in lowered:
            name = "ssh"
        elif "ftp" in lowered:
            name = "ftp"
        elif "http/1." in lowered or "server:" in lowered:
            name = "http"
        elif "smb" in lowered:
            name = "smb"
    return name
