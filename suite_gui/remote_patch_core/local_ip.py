"""Guarda de auto-objetivo: evita bloquear RDP o tocar TLS en la misma
maquina que esta ejecutando la herramienta (facil de hacer sin querer al
tipear una IP, y bloquearse el propio RDP de forma remota es dificil de
revertir si esa era la unica via de acceso).

La comparacion se hace SIEMPRE sobre la forma canonica de la IP (via
ipaddress), nunca por texto crudo: notaciones alternativas del mismo
loopback IPv6 (ej. "0:0:0:0:0:0:0:1" en vez de "::1") deben detectarse
igual que la forma corta."""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from typing import List, Optional, Tuple

_IS_WINDOWS = platform.system().lower() == "windows"


def get_local_ips() -> List[str]:
    ips, _reliable = get_local_ips_with_status()
    return ips


def get_local_ips_with_status() -> Tuple[List[str], bool]:
    """Enumera IPs locales por varias vias, para cubrir tambien VPN y
    adaptadores adicionales que un solo metodo podria no ver:
      - DNS del hostname local.
      - IP de la interfaz que gana la ruta de salida por defecto.
      - Get-NetIPAddress (PowerShell): TODAS las interfaces configuradas,
        incluida cualquier VPN o NIC secundaria.

    Devuelve (ips, confiable). 'confiable' es False cuando NINGUNO de los 3
    metodos funciono (p.ej. sin salida de red hacia Internet, o
    powershell.exe no disponible/restringido en el equipo). En ese caso la
    lista devuelta es solo loopback y NO alcanza para descartar que una IP
    real de esta maquina falte -- el llamador (is_local_target) debe fallar
    CERRADO en vez de asumir que ninguna IP local coincide."""
    ips = {"127.0.0.1", "::1"}
    any_method_ok = False

    try:
        hostname = socket.gethostname()
        _, _, addrs = socket.gethostbyname_ex(hostname)
        ips.update(addrs)
        any_method_ok = True
    except Exception:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
        any_method_ok = True
    except Exception:
        pass

    # Tercer metodo: enumerar TODAS las interfaces configuradas (incluida
    # cualquier VPN o NIC secundaria) con la herramienta nativa del SO.
    #   - Windows: Get-NetIPAddress (PowerShell).
    #   - macOS/Linux: 'ifconfig' (o 'ip addr' como respaldo), parseando las
    #     lineas 'inet' / 'inet6'.
    try:
        if _IS_WINDOWS:
            proc = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "(Get-NetIPAddress -ErrorAction SilentlyContinue).IPAddress",
                ],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0:
                for line in (proc.stdout or "").splitlines():
                    line = line.strip()
                    if line:
                        ips.add(line)
                any_method_ok = True
        else:
            proc = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
            output = proc.stdout or ""
            if proc.returncode != 0 or not output:
                # Respaldo en Linux minimalista sin ifconfig.
                proc = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=10)
                output = proc.stdout or ""
            # 'inet 192.168.1.5', 'inet6 fe80::1%en0', 'inet 10.0.0.2/24'
            for match in re.finditer(r"\binet6?\s+([0-9a-fA-F:.]+)", output):
                addr = match.group(1).split("/")[0].split("%")[0]
                if addr:
                    ips.add(addr)
                    any_method_ok = True
    except Exception:
        pass

    return sorted(ips), any_method_ok


def _normalize(ip_str: str) -> Optional[str]:
    """Forma canonica de una IP (colapsa todas las notaciones equivalentes,
    p.ej. IPv6 con ceros expandidos vs. forma corta). None si no es una IP
    valida (p.ej. un hostname o un scope-id sin limpiar)."""
    try:
        cleaned = ip_str.split("%")[0].strip()  # descarta zone-id (fe80::1%eth0) antes de parsear
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return None


def is_local_target(ip: str) -> Tuple[bool, bool]:
    """Devuelve (es_local, enumeracion_confiable).

    Si enumeracion_confiable es False, NINGUN metodo de deteccion de IP
    local funciono: es_local sera False en ese caso, pero eso NO significa
    "confirmado remoto" -- significa que no se pudo verificar. El llamador
    debe tratar ese caso como bloqueante (fallar cerrado) en vez de asumir
    que el objetivo no es esta misma maquina."""
    target_norm = _normalize(ip)
    if target_norm is None:
        return False, True

    ## Cubre TODO el rango loopback (127.0.0.0/8, no solo 127.0.0.1), ::1 en
    ## cualquier notacion, y 0.0.0.0/:: (unspecified -> en Windows conecta a
    ## localhost). Sin esto, --ip 127.0.0.5 o 0:0:0:0:0:0:0:1 esquivaban la
    ## guarda porque no coincidian exacto con las IPs enumeradas.
    try:
        obj = ipaddress.ip_address(target_norm)
        if obj.is_loopback or obj.is_unspecified:
            return True, True
    except ValueError:
        pass

    local_ips, reliable = get_local_ips_with_status()
    local_norms = {_normalize(x) for x in local_ips}
    local_norms.discard(None)
    return target_norm in local_norms, reliable
