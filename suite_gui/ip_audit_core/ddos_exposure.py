"""Deteccion de EXPOSICION a DDoS por amplificacion/reflexion.

Que hace (y que NO hace):
  - NO lanza un ataque de denegacion de servicio. No inunda al objetivo con
    trafico. Enviar trafico masivo contra un host para 'probar si se cae' es
    un ataque (y en muchos paises un delito); esta herramienta no lo hace.
  - SI detecta, con UN unico paquete benigno por servicio, si el host expone
    un servicio UDP de los que tipicamente se abusan como AMPLIFICADOR en
    ataques DDoS de reflexion (DNS, NTP, SSDP/UPnP, SNMP, memcached,
    CharGen). Si el host responde con un paquete MAS GRANDE que el enviado,
    un atacante podria falsificar la IP de una victima y usar a este host
    para multiplicar el volumen del ataque contra ella.

O sea: mide si ESTE host podria ser usado como 'altavoz' en un DDoS contra
terceros -- un hallazgo defensivo, real y accionable (cerrar/filtrar el
servicio), no un ataque. Un solo paquete por servicio = reconocimiento
seguro, no una inundacion.

Uso permitido: solo sobre equipos propios o con autorizacion escrita.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List

# --- Paquetes de sondeo (uno por servicio, minimos y benignos) --------------

# DNS: consulta recursiva ANY por la raiz "." -> respuesta tipicamente mucho
# mayor que la pregunta (vector de amplificacion DNS clasico).
_DNS_QUERY = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # header: ID, RD=1, QDCOUNT=1
    b"\x00"                                              # nombre raiz "."
    b"\x00\xff"                                          # QTYPE=ANY(255)
    b"\x00\x01"                                          # QCLASS=IN
)

# NTP: peticion cliente estandar (modo 3, v3). Si responde, el servicio NTP
# esta expuesto; muchas versiones antiguas amplifican via 'monlist'.
_NTP_QUERY = b"\x1b" + b"\x00" * 47

# SSDP/UPnP: M-SEARCH unicast. La respuesta suele ser varias veces mayor.
_SSDP_QUERY = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST:{ip}:1900\r\n"
    'MAN:"ssdp:discover"\r\n'
    "MX:1\r\n"
    "ST:ssdp:all\r\n\r\n"
)

# SNMPv1 GetRequest de sysDescr.0 con comunidad "public".
_SNMP_QUERY = bytes.fromhex(
    "302902010004067075626c6963a01c02040000000002010002010030"
    "0e300c06082b060102010101000500"
)

# memcached UDP: cabecera de 8 bytes + 'stats' -> respuesta enorme (el
# amplificador con mayor factor conocido, hasta ~51000x).
_MEMCACHED_QUERY = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"

# CharGen: cualquier byte dispara un chorro de caracteres.
_CHARGEN_QUERY = b"\x01"

# (puerto, nombre, factor tipico documentado, generador_de_payload)
_AMPLIFIERS = [
    (53, "DNS", "hasta ~54x", lambda ip: _DNS_QUERY),
    (123, "NTP", "hasta ~556x (monlist)", lambda ip: _NTP_QUERY),
    (1900, "SSDP/UPnP", "hasta ~30x", lambda ip: _SSDP_QUERY.format(ip=ip).encode()),
    (161, "SNMP", "hasta ~6x (GetBulk)", lambda ip: _SNMP_QUERY),
    (11211, "memcached", "hasta ~51000x", lambda ip: _MEMCACHED_QUERY),
    (19, "CharGen", "hasta ~358x", lambda ip: _CHARGEN_QUERY),
]


@dataclass
class AmplifierExposure:
    port: int
    service: str
    request_bytes: int
    response_bytes: int
    factor: float          # response_bytes / request_bytes
    typical_factor: str     # referencia documentada


@dataclass
class DdosExposureFindings:
    exposures: List[AmplifierExposure] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _probe_udp(ip: str, port: int, payload: bytes, timeout_s: float) -> int:
    """Envia UN paquete UDP y devuelve el tamano de la respuesta (0 si no
    respondio). No reintenta: un solo paquete de reconocimiento."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout_s)
        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(65535)
        return len(data)
    except socket.timeout:
        return 0
    except Exception:
        return 0
    finally:
        sock.close()


def analyze_ddos_exposure(ip: str, timeout_s: float = 2.0) -> DdosExposureFindings:
    """Sondea (un paquete c/u) los servicios UDP de amplificacion conocidos y
    reporta los que responden amplificando (respuesta > peticion)."""
    findings = DdosExposureFindings()

    def _one(entry):
        port, service, typical, make_payload = entry
        try:
            payload = make_payload(ip)
            resp_len = _probe_udp(ip, port, payload, timeout_s)
        except Exception as exc:
            return ("error", f"{service}/{port}: {exc}")
        req_len = len(payload)
        # Solo interesa si respondio Y amplifica (respuesta mayor que la
        # peticion): ese es el requisito para servir de reflector util.
        if resp_len > req_len:
            return ("exp", AmplifierExposure(
                port=port, service=service, request_bytes=req_len,
                response_bytes=resp_len, factor=round(resp_len / req_len, 1),
                typical_factor=typical,
            ))
        return ("none", None)

    # Los 6 sondeos en paralelo: cada uno es un solo paquete UDP, asi el peor
    # caso (todos timeout) es ~un timeout, no la suma de los seis.
    with ThreadPoolExecutor(max_workers=len(_AMPLIFIERS)) as executor:
        for kind, value in executor.map(_one, _AMPLIFIERS):
            if kind == "exp":
                findings.exposures.append(value)
            elif kind == "error":
                findings.errors.append(value)
    return findings
