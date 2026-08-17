"""
Base de conocimiento local (offline) de puertos, servicios y patrones de
versiones vulnerables conocidas. No requiere conexión a internet ni APIs
externas de CVE: es una heurística curada para uso educativo / de auditoría
rápida. Para un análisis de CVE exhaustivo y actualizado se recomienda
complementar con NVD/Vulners/Nessus/OpenVAS.
"""
from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional

# ---------------------------------------------------------------------------
# Catálogo de puertos relevantes para el módulo de "conexiones remotas"
# ---------------------------------------------------------------------------
# NOTA: se quitaron 7070 y 6568 ("AnyDesk posible") porque son puertos
# ambiguos (RealServer/RTSP, apps web, proxies) y generaban falsos positivos
# de "software de acceso remoto no autorizado" por el solo numero de puerto.
# La deteccion de AnyDesk/TeamViewer ahora exige confirmacion por banner
# (ver host_analyzer._check_remote_access_exposure).
REMOTE_ACCESS_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    5938: "TeamViewer",
}

# Puertos comunes de gestión remota / MDM / agentes de administración
MDM_MANAGEMENT_PORTS: Dict[int, str] = {
    135: "RPC/WMI (gestion remota Windows)",
    445: "SMB (gestion remota Windows / GPO)",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    4444: "Puerto 4444 abierto - verificar servicio (Selenium/Metasploit/dev)",
    8530: "WSUS (gestion de parches)",
    8531: "WSUS HTTPS",
    1723: "PPTP VPN (obsoleto)",
    10000: "Webmin",
    9090: "Puerto 9090 abierto - verificar (Cockpit/Prometheus/otros)",
    623: "IPMI (gestion fuera de banda)",
}

# Puertos con servicios susceptibles de fuerza bruta por defecto
BRUTE_FORCE_PRONE_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    5900: "VNC",
}

# Lista general de puertos a escanear por defecto (superset de todo lo anterior
# + servicios web habituales para TLS)
DEFAULT_PORT_LIST: List[int] = sorted(
    set(
        list(REMOTE_ACCESS_PORTS)
        + list(MDM_MANAGEMENT_PORTS)
        + list(BRUTE_FORCE_PRONE_PORTS)
        + [25, 53, 80, 110, 135, 139, 143, 443, 465, 636, 993, 995, 8080, 8443]
    )
)

COMMON_SERVICE_NAMES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "rpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1723: "pptp",
    3306: "mysql",
    3389: "rdp",
    4444: "generic-mgmt",
    5432: "postgresql",
    5900: "vnc",
    5901: "vnc",
    5938: "teamviewer",
    5985: "winrm",
    5986: "winrm-ssl",
    6568: "anydesk",
    623: "ipmi",
    7070: "anydesk",
    8080: "http-alt",
    8443: "https-alt",
    8530: "wsus",
    8531: "wsus-ssl",
    9090: "cockpit",
    10000: "webmin",
    465: "smtps",
    636: "ldaps",
}

# 3389 (RDP) deliberadamente NO esta incluido: RDP negocia un preambulo
# X.224 antes de arrancar TLS en la misma conexion, no acepta un ClientHello
# directo como estos otros puertos. analyze_tls() envolveria el socket
# inmediatamente y fallaria con un error generico (no una senal real sobre
# el estado de RDP), asi que se omite en vez de generar ruido enganoso.
TLS_PORTS = {443, 8443, 993, 995, 465, 636, 5986}

# ---------------------------------------------------------------------------
# Patrones de versiones de SSH con CVEs conocidos (curado, no exhaustivo)
# ---------------------------------------------------------------------------
class VersionRule(NamedTuple):
    pattern: str  # regex sobre el banner completo
    max_affected: Optional[str]  # version limite (string comparable simple)
    title: str
    severity: str
    cves: List[str]
    description: str
    # Si se define, la regla dispara SOLO para estas versiones exactas (no un
    # rango <=). Evita el falso positivo de marcar como vulnerables versiones
    # anteriores/parcheadas cuando el CVE afecta a una version puntual (ej.
    # Apache 2.4.49/2.4.50, backdoor de vsFTPd 2.3.4).
    exact_versions: Optional[frozenset] = None


# NOTA sobre falsos positivos: el numero de version del banner de OpenSSH NO
# refleja los backports de seguridad de las distros (RHEL/CentOS 7 se queda en
# OpenSSH_7.4, Ubuntu 16.04 en 7.2p2, etc., pero con los CVEs parcheados por
# detras). Por eso estas reglas se reportan como INFORMATIVAS/orientativas: son
# un recordatorio de verificar la version real del paquete, no un hallazgo
# confirmado. Los algoritmos SSH debiles (que SI se miden en vivo por
# negociacion, no por banner) se reportan aparte con severidad real.
SSH_VULN_RULES: List[VersionRule] = [
    VersionRule(
        pattern=r"OpenSSH_([0-9]+\.[0-9]+)",
        max_affected="7.3",
        title="OpenSSH con banner antiguo (verificar backports de la distro)",
        severity="Informativa",
        cves=["CVE-2018-15473", "CVE-2016-10009", "CVE-2016-0777"],
        description=(
            "El banner reporta OpenSSH <= 7.3. Multiples CVEs publicos afectan a esas "
            "versiones upstream (enumeracion de usuarios, fuga de claves, etc.), PERO el "
            "banner no refleja los backports de RHEL/CentOS/Ubuntu, que parchean sin subir "
            "la version. Verificar la version real del paquete del SO antes de tratarlo como "
            "confirmado; no asumir vulnerable solo por el banner."
        ),
    ),
    VersionRule(
        pattern=r"Cygwin",
        max_affected=None,
        title="Servidor SSH sobre Cygwin (informativo)",
        severity="Informativa",
        cves=[],
        description="Implementacion SSH sobre Cygwin; verificar que este actualizada.",
    ),
]

# Algoritmos SSH considerados debiles / obsoletos
WEAK_SSH_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
WEAK_SSH_CIPHERS = {"3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc", "des-cbc", "none"}
WEAK_SSH_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "none"}

# ---------------------------------------------------------------------------
# TLS/SSL
# ---------------------------------------------------------------------------
OBSOLETE_TLS_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon", "PSK"]

# Banners de servicios web/ftp/telnet con versiones desactualizadas conocidas
GENERIC_VERSION_RULES: List[VersionRule] = [
    VersionRule(
        pattern=r"vsFTPd ([0-9.]+)",
        max_affected=None,
        title="vsFTPd 2.3.4 - posible backdoor (requiere confirmacion activa)",
        severity="Alta",
        cves=["CVE-2011-2523"],
        description=(
            "El tarball upstream de vsFTPd 2.3.4 (jul-2011) contenia un backdoor que abre "
            "un shell en el puerto 6200 al enviar un usuario terminado en ':)'. Los paquetes "
            "de distro con esa version NO lo contienen; requiere confirmacion activa antes de "
            "tratarlo como real."
        ),
        exact_versions=frozenset({"2.3.4"}),
    ),
    VersionRule(
        pattern=r"Apache/([0-9.]+)",
        max_affected=None,
        title="Apache HTTPD 2.4.49/2.4.50 - path traversal/RCE",
        severity="Alta",
        cves=["CVE-2021-41773", "CVE-2021-42013"],
        description=(
            "Solo Apache 2.4.49 (CVE-2021-41773) y 2.4.50 (CVE-2021-42013) son vulnerables; "
            "se corrigio en 2.4.51. El numero de version del banner no es confiable en distros "
            "que aplican backports sin cambiarlo: confirmar la version real del paquete."
        ),
        exact_versions=frozenset({"2.4.49", "2.4.50"}),
    ),
    VersionRule(
        pattern=r"Microsoft-IIS/([0-9.]+)",
        max_affected="7.5",
        title="IIS muy antiguo (SO probablemente fuera de soporte)",
        severity="Media",
        cves=[],
        description=(
            "Version de IIS asociada a sistemas operativos Windows fuera de soporte "
            "(Server 2008/2008 R2 o anterior). Confirmar el SO subyacente y su estado de soporte."
        ),
    ),
]


def _version_leq(v: str, limit: str) -> bool:
    """Compara versiones tipo '7.4' <= '7.4' de forma tolerante."""
    def parts(s: str):
        return [int(x) for x in re.findall(r"\d+", s)]

    va, vb = parts(v), parts(limit)
    va += [0] * (max(len(va), len(vb)) - len(va))
    vb += [0] * (max(len(va), len(vb)) - len(vb))
    return va <= vb


def match_version_rules(banner: str, rules: List[VersionRule]) -> List[VersionRule]:
    matches = []
    if not banner:
        return matches
    for rule in rules:
        m = re.search(rule.pattern, banner)
        if not m:
            continue

        # Versiones exactas: solo dispara si la version capturada esta en el set.
        if rule.exact_versions is not None:
            try:
                version = m.group(1)
            except IndexError:
                continue
            if version in rule.exact_versions:
                matches.append(rule)
            continue

        if rule.max_affected is None:
            matches.append(rule)
            continue
        try:
            version = m.group(1)
        except IndexError:
            matches.append(rule)
            continue
        if _version_leq(version, rule.max_affected):
            matches.append(rule)
    return matches
