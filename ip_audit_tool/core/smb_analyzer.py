"""Analisis SMB por negociacion real (sin autenticar, sin dependencias
externas): detecta si el servidor acepta SMBv1 (candidato a MS17-010 /
EternalBlue) y si exige firma SMB (SMB signing). Reproduce lo que marcan
nmap smb-protocols / smb-security-mode y Nessus, que la version por-puerto
de esta herramienta no cubria.

Solo se completa la fase de NEGOTIATE del protocolo (publica, previa a
cualquier autenticacion): nunca se envian usuarios ni contrasenas."""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class SmbFindings:
    reachable: bool = False
    smbv1_enabled: Optional[bool] = None
    signing_required: Optional[bool] = None
    signing_enabled: Optional[bool] = None
    detail: str = ""


# --- SMBv1 NEGOTIATE (solo dialectos SMB1) ---------------------------------
# NetBIOS Session Service (4 bytes: 0x00 + longitud de 3 bytes) + SMB1 header
# (empieza con 0xFF 'SMB', comando 0x72 NEGOTIATE) + lista de dialectos SMB1.
def _build_smb1_negotiate() -> bytes:
    dialects = b""
    for d in (b"LANMAN1.0", b"LM1.2X002", b"NT LANMAN 1.0", b"NT LM 0.12"):
        dialects += b"\x02" + d + b"\x00"
    body = (
        b"\xffSMB"          # protocolo SMB1
        b"\x72"             # SMB_COM_NEGOTIATE
        b"\x00\x00\x00\x00" # status
        b"\x18"             # flags
        b"\x53\x28"         # flags2
        b"\x00\x00"         # PIDHigh
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # signature
        b"\x00\x00"         # reserved
        b"\x00\x00"         # TID
        b"\x2f\x4b"         # PIDLow
        b"\x00\x00"         # UID
        b"\xc5\x5e"         # MID
        b"\x00"             # WordCount
        + struct.pack("<H", len(dialects))  # ByteCount
        + dialects
    )
    netbios = b"\x00" + struct.pack(">I", len(body))[1:]  # tipo 0x00 + long 3 bytes
    return netbios + body


def _build_smb2_negotiate() -> bytes:
    # SMB2 header (64 bytes)
    header = (
        b"\xfeSMB"              # ProtocolId SMB2
        + struct.pack("<H", 64) # StructureSize
        + struct.pack("<H", 0)  # CreditCharge
        + struct.pack("<I", 0)  # Status
        + struct.pack("<H", 0)  # Command = NEGOTIATE (0)
        + struct.pack("<H", 1)  # CreditRequest
        + struct.pack("<I", 0)  # Flags
        + struct.pack("<I", 0)  # NextCommand
        + struct.pack("<Q", 0)  # MessageId
        + struct.pack("<I", 0)  # Reserved (ProcessId)
        + struct.pack("<I", 0)  # TreeId
        + struct.pack("<Q", 0)  # SessionId
        + b"\x00" * 16          # Signature
    )
    ## NO incluir 0x0311 (SMB 3.1.1): ese dialecto exige contextos de
    ## negociacion adicionales en el request y, sin ellos, el servidor
    ## responde con un SMB2 ERROR (StructureSize 9) en vez del NEGOTIATE
    ## response, dejando SecurityMode ilegible. Ofrecer hasta 3.0.2 alcanza
    ## para leer SecurityMode (firma) de forma fiable.
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = (
        struct.pack("<H", 36)                  # StructureSize
        + struct.pack("<H", len(dialects))     # DialectCount
        + struct.pack("<H", 1)                 # SecurityMode = SIGNING_ENABLED
        + struct.pack("<H", 0)                 # Reserved
        + struct.pack("<I", 0)                 # Capabilities
        + b"\x00" * 16                         # ClientGuid
        + struct.pack("<Q", 0)                 # ClientStartTime
        + b"".join(struct.pack("<H", d) for d in dialects)
    )
    smb2 = header + body
    netbios = b"\x00" + struct.pack(">I", len(smb2))[1:]
    return netbios + smb2


def _recv_response(sock: socket.socket) -> bytes:
    ## Lee la cabecera NetBIOS (4 bytes) para saber cuanto leer.
    head = sock.recv(4)
    if len(head) < 4:
        return head
    length = struct.unpack(">I", b"\x00" + head[1:])[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _probe_smbv1(ip: str, timeout_s: float) -> Optional[bool]:
    """True solo si el servidor NEGOCIA con exito un dialecto SMBv1.

    No basta con que la respuesta venga en formato SMB1 (0xFF 'SMB'): un
    servidor Samba (NAS QNAP/Synology, Linux) con 'min protocol = SMB2'
    puede responder EN FORMATO SMB1 solo para RECHAZAR la negociacion
    (status de error, o DialectIndex=0xFFFF = 'ninguno de los dialectos que
    ofreciste'). Interpretar eso como 'SMBv1 habilitado' era un falso
    positivo. Aca se exige: framing SMB1 + status de exito (0) + un
    DialectIndex valido (distinto de 0xFFFF)."""
    try:
        with socket.create_connection((ip, 445), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            sock.sendall(_build_smb1_negotiate())
            resp = _recv_response(sock)
            if not resp or len(resp) < 35:
                return False
            if resp[:4] != b"\xffSMB":
                return False  # respondio SMB2 (0xFE) u otra cosa -> SMBv1 no negociado

            ## NT_Status (offset 5, 4 bytes LE): != 0 => el servidor devolvio un
            ## error al negotiate SMB1 -> SMBv1 no usable.
            nt_status = struct.unpack_from("<I", resp, 5)[0]
            if nt_status != 0:
                return False

            ## WordCount (offset 32) y DialectIndex (offset 33, 2 bytes).
            word_count = resp[32]
            if word_count < 1:
                return False
            dialect_index = struct.unpack_from("<H", resp, 33)[0]
            if dialect_index == 0xFFFF:
                return False  # 'ninguno de los dialectos SMB1 ofrecidos' -> no habilitado

            return True  # nego un dialecto SMBv1 concreto -> realmente habilitado
    except ConnectionResetError:
        return False
    except Exception:
        return None


def _probe_smb2_signing(ip: str, timeout_s: float):
    try:
        with socket.create_connection((ip, 445), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            sock.sendall(_build_smb2_negotiate())
            resp = _recv_response(sock)
            if len(resp) < 68 or resp[:4] != b"\xfeSMB":
                return None, None
            ## SecurityMode: 2 bytes al inicio del cuerpo NEGOTIATE Response
            ## (offset 64 = fin del header SMB2; StructureSize ocupa 64-65;
            ## SecurityMode ocupa 66-67).
            security_mode = struct.unpack_from("<H", resp, 66)[0]
            signing_enabled = bool(security_mode & 0x0001)
            signing_required = bool(security_mode & 0x0002)
            return signing_required, signing_enabled
    except Exception:
        return None, None


def analyze_smb(ip: str, timeout_s: float = 3.0) -> SmbFindings:
    findings = SmbFindings()

    smbv1 = _probe_smbv1(ip, timeout_s)
    signing_required, signing_enabled = _probe_smb2_signing(ip, timeout_s)

    findings.smbv1_enabled = smbv1
    findings.signing_required = signing_required
    findings.signing_enabled = signing_enabled
    findings.reachable = smbv1 is not None or signing_required is not None

    parts = []
    if smbv1 is True:
        parts.append("SMBv1 HABILITADO (candidato a MS17-010/EternalBlue)")
    elif smbv1 is False:
        parts.append("SMBv1 no habilitado")
    if signing_required is True:
        parts.append("firma SMB requerida")
    elif signing_required is False:
        parts.append("firma SMB NO requerida")
    findings.detail = "; ".join(parts)
    return findings
