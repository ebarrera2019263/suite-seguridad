"""Analisis de seguridad de capa TLS/SSL: certificados y protocolos/cifrados."""
from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass, field
from typing import List, Optional

from cryptography import x509

from .vuln_db import WEAK_CIPHER_KEYWORDS


@dataclass
class TlsFindings:
    reachable: bool = False
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_expired: Optional[bool] = None
    cert_self_signed: Optional[bool] = None
    cert_not_after: Optional[str] = None
    negotiated_protocol: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    weak_cipher: bool = False
    obsolete_protocols_supported: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# Mapeo de protocolo -> constructor de contexto SSL forzando esa version,
# usado unicamente para *probar* si el servidor aun los acepta (no se
# realiza ninguna autenticacion ni transferencia de datos sensibles).
def _context_for_protocol(protocol_name: str) -> Optional[ssl.SSLContext]:
    try:
        if protocol_name == "SSLv3":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.SSLv3  # type: ignore[attr-defined]
            ctx.maximum_version = ssl.TLSVersion.SSLv3  # type: ignore[attr-defined]
        elif protocol_name == "TLSv1.0":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif protocol_name == "TLSv1.1":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        else:
            return None
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except (AttributeError, ValueError, ssl.SSLError):
        # OpenSSL moderno suele deshabilitar SSLv3/TLS1.0/1.1 en tiempo de
        # compilacion; en ese caso simplemente no se puede probar (no implica
        # que el servidor remoto sea seguro, solo que este cliente no soporta
        # negociar ese protocolo obsoleto).
        return None


def _probe_obsolete_protocols(ip: str, port: int, timeout_s: float) -> List[str]:
    supported: List[str] = []
    for name in ("SSLv3", "TLSv1.0", "TLSv1.1"):
        ctx = _context_for_protocol(name)
        if ctx is None:
            continue
        try:
            with socket.create_connection((ip, port), timeout=timeout_s) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip):
                    supported.append(name)
        except Exception:
            continue
    return supported


# Cadena de cifrados legacy en formato OpenSSL, usada solo para *probar* si
# el servidor todavia acepta alguno (mismo principio que _probe_obsolete_
# protocols: si el OpenSSL local ya los elimino en tiempo de compilacion,
# set_ciphers() falla y simplemente no se puede probar, no implica que el
# servidor sea seguro).
_WEAK_CIPHER_OPENSSL_STRING = "RC4:DES-CBC3-SHA:DES-CBC-SHA:EXPORT:eNULL:aNULL:MD5"


def _probe_weak_cipher(ip: str, port: int, timeout_s: float) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # TLS 1.3 no usa set_ciphers(): sus suites (todas fuertes, tipo
        # TLS_AES_256_GCM_SHA384) se negocian por un mecanismo aparte que
        # set_ciphers() no toca. Sin este limite, CUALQUIER servidor con
        # TLS 1.3 "aprobaria" esta prueba via TLS 1.3 sin haber ofrecido
        # jamas un cifrado debil real -- ese era exactamente el falso
        # positivo. Se limita explicitamente a <=TLS 1.2 para que, si el
        # handshake igual tiene exito, sea unicamente porque el servidor
        # acepto de verdad uno de los cifrados debiles listados.
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(_WEAK_CIPHER_OPENSSL_STRING)
    except (ssl.SSLError, AttributeError, ValueError):
        return False  # este cliente ya no puede ni ofrecer cifrados debiles (OpenSSL moderno los quito)

    try:
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                cipher = tls_sock.cipher()
                if not cipher:
                    return False
                # Doble verificacion (ademas del tope de version de arriba):
                # el cifrado realmente negociado debe coincidir con la lista
                # de palabras clave debiles, no solo "hubo handshake".
                return any(kw.lower() in cipher[0].lower() for kw in WEAK_CIPHER_KEYWORDS)
    except Exception:
        return False


def _parse_certificate(der_cert: bytes) -> dict:
    """Parsea el certificado DER con `cryptography`, independientemente del
    verify_mode usado en el handshake (con verify_mode=CERT_NONE,
    ssl.SSLSocket.getpeercert() sin binary_form devuelve siempre un dict
    vacio, por eso no se puede usar esa via para inspeccionar certificados
    autofirmados/invalidos -- que es justamente el caso que interesa)."""
    result = {
        "subject": None, "issuer": None, "self_signed": None,
        "not_after": None, "expired": None,
    }
    try:
        cert = x509.load_der_x509_certificate(der_cert)
    except Exception:
        return result

    try:
        result["subject"] = cert.subject.rfc4514_string()
        result["issuer"] = cert.issuer.rfc4514_string()
        result["self_signed"] = cert.subject == cert.issuer
    except Exception:
        pass

    try:
        not_after = getattr(cert, "not_valid_after_utc", None)
        if not_after is None:
            not_after = cert.not_valid_after  # cryptography <42 no tiene la variante *_utc
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=datetime.timezone.utc)
        result["not_after"] = not_after.isoformat()
        result["expired"] = not_after < datetime.datetime.now(datetime.timezone.utc)
    except Exception:
        pass

    return result


def probe_http_server_header(ip: str, port: int, timeout_s: float = 3.0) -> Optional[str]:
    """Envia un HEAD / sobre una conexion TLS propia para leer el header
    'Server:' de servicios que solo exponen HTTP sobre el puerto TLS (p.ej.
    appliances de gestion en 443, WinRM-HTTPS en 5986) y por lo tanto nunca
    responden a la sonda HTTP en claro de scanner.grab_banner (que solo
    prueba 80/8000/8080). Sin esto, esos hosts no reciben chequeo de
    version/CVE para su servicio web (ver GENERIC_VERSION_RULES)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                tls_sock.settimeout(timeout_s)
                request = (
                    f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n"
                    "User-Agent: ip_audit_tool\r\nConnection: close\r\n\r\n"
                )
                tls_sock.sendall(request.encode("ascii", errors="ignore"))
                data = b""
                while len(data) < 8192 and b"\r\n\r\n" not in data:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
    except Exception:
        return None

    text = data.decode("iso-8859-1", errors="ignore")
    for line in text.split("\r\n"):
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return None


def analyze_tls(ip: str, port: int, timeout_s: float = 3.0) -> TlsFindings:
    findings = TlsFindings()

    default_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    default_ctx.check_hostname = False
    default_ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            with default_ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                findings.reachable = True
                findings.negotiated_protocol = tls_sock.version()
                cipher = tls_sock.cipher()
                if cipher:
                    findings.negotiated_cipher = cipher[0]
                    findings.weak_cipher = any(
                        kw.lower() in cipher[0].lower() for kw in WEAK_CIPHER_KEYWORDS
                    )

                der_cert = tls_sock.getpeercert(binary_form=True)
                if der_cert:
                    parsed = _parse_certificate(der_cert)
                    findings.cert_subject = parsed["subject"]
                    findings.cert_issuer = parsed["issuer"]
                    findings.cert_self_signed = parsed["self_signed"]
                    findings.cert_not_after = parsed["not_after"]
                    findings.cert_expired = parsed["expired"]
    except ssl.SSLError as exc:
        findings.errors.append(f"Error SSL: {exc}")
        return findings
    except Exception as exc:
        findings.errors.append(f"No se pudo establecer conexion TLS: {exc}")
        return findings

    findings.obsolete_protocols_supported = _probe_obsolete_protocols(ip, port, timeout_s)
    if not findings.weak_cipher:
        findings.weak_cipher = _probe_weak_cipher(ip, port, timeout_s)
    return findings
