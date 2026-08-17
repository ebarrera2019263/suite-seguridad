"""Analisis de seguridad de servicios SSH: banner/version y algoritmos
negociables (KEX/cifrado/MAC). No se realiza ningun intento de autenticacion
(usuario/contrasena) en ningun momento: solo se completa el intercambio de
identificacion y negociacion de algoritmos, que es publico por diseno del
protocolo SSH."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import List, Optional

from .vuln_db import WEAK_SSH_CIPHERS, WEAK_SSH_KEX, WEAK_SSH_MACS

try:
    import paramiko  # type: ignore

    PARAMIKO_AVAILABLE = True
except Exception:
    PARAMIKO_AVAILABLE = False


@dataclass
class SshFindings:
    reachable: bool = False
    banner: Optional[str] = None
    weak_kex: List[str] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)
    weak_macs: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def get_ssh_banner(ip: str, port: int = 22, timeout_s: float = 3.0) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            data = sock.recv(256)
            return data.decode(errors="ignore").strip()
    except Exception:
        return None


def analyze_ssh_algorithms(ip: str, port: int = 22, timeout_s: float = 4.0) -> SshFindings:
    findings = SshFindings()
    findings.banner = get_ssh_banner(ip, port, timeout_s)
    findings.reachable = findings.banner is not None

    if not PARAMIKO_AVAILABLE:
        findings.errors.append(
            "paramiko no disponible: se omite el analisis de algoritmos KEX/cifrado/MAC"
        )
        return findings

    sock = None
    transport = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout_s)
        transport = paramiko.Transport(sock)
        # start_client negocia algoritmos pero NO autentica: no se envian
        # credenciales de ningun tipo.
        transport.start_client(timeout=timeout_s)

        opts = transport.get_security_options()
        offered_kex = set(opts.kex)
        offered_ciphers = set(opts.ciphers)
        offered_macs = set(opts.mac)

        findings.weak_kex = sorted(offered_kex & WEAK_SSH_KEX)
        findings.weak_ciphers = sorted(offered_ciphers & WEAK_SSH_CIPHERS)
        findings.weak_macs = sorted(offered_macs & WEAK_SSH_MACS)
    except Exception as exc:
        findings.errors.append(f"No se pudo negociar algoritmos SSH: {exc}")
    finally:
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            if sock:
                sock.close()
        except Exception:
            pass

    return findings
