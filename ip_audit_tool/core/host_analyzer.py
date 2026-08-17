"""Orquesta el analisis completo de un host: descubrimiento, escaneo de
puertos, banners, TLS, SSH y correlacion de vulnerabilidades. Es el modulo
que "conecta" todos los demas y produce un HostResult listo para reportar.

Importante (uso etico): esta herramienta NUNCA intenta autenticarse contra
los servicios encontrados (no prueba usuarios/contrasenas). El riesgo de
"fuerza bruta" se reporta como EXPOSICION (puerto sensible accesible sin
controles compensatorios visibles), no como resultado de un ataque real.
"""
from __future__ import annotations

import time
from typing import List

from . import discovery, os_detector, smb_analyzer, ssh_analyzer, ssl_analyzer
from .models import HostResult, ServiceInfo, Severity, Vulnerability
from .scanner import grab_banner, identify_service, scan_ports
from .vuln_db import (
    BRUTE_FORCE_PRONE_PORTS,
    DEFAULT_PORT_LIST,
    GENERIC_VERSION_RULES,
    MDM_MANAGEMENT_PORTS,
    OBSOLETE_TLS_PROTOCOLS,
    REMOTE_ACCESS_PORTS,
    SSH_VULN_RULES,
    TLS_PORTS,
    match_version_rules,
)


def analyze_host(
    ip: str,
    ports: List[int] = None,
    port_timeout_s: float = 0.9,
    banner_timeout_s: float = 2.0,
    tls_timeout_s: float = 3.0,
    ssh_timeout_s: float = 4.0,
    skip_mac: bool = False,
) -> HostResult:
    start = time.time()
    ports = ports or DEFAULT_PORT_LIST
    result = HostResult(ip=ip)

    disc = discovery.discover_host(ip)
    result.alive = disc["alive"]
    result.ttl = disc["ttl"]
    result.hostname = disc["hostname"]
    result.netbios_name = disc["netbios_name"]
    if not skip_mac:
        result.mac = disc["mac"]

    if not result.alive:
        result.scan_duration_s = time.time() - start
        return result

    result.os_guess = os_detector.guess_os_from_ttl(result.ttl)

    open_ports = scan_ports(ip, ports, timeout_s=port_timeout_s)
    result.open_ports = open_ports

    for port in open_ports:
        banner = grab_banner(ip, port, timeout_s=banner_timeout_s)
        service_name = identify_service(port, banner)
        svc = ServiceInfo(port=port, name=service_name, banner=banner)
        result.services[port] = svc

    result.os_guess = os_detector.refine_os_guess(result.os_guess, open_ports, result.services)
    result.device_type = os_detector.guess_device_type(open_ports, result.hostname or result.netbios_name)

    _run_check("Exposicion de acceso remoto", result, _check_remote_access_exposure, result)
    _run_check("Exposicion MDM", result, _check_mdm_exposure, result)
    _run_check("Riesgo de fuerza bruta", result, _check_brute_force_risk, result)
    _run_check("SMB", result, _check_smb, result, tls_timeout_s)
    _run_check("SSH", result, _check_ssh, result, ssh_timeout_s)
    _run_check("TLS", result, _check_tls, result, tls_timeout_s)
    # Corre despues de SMB/SSH/TLS: esos chequeos pueden completar el banner
    # de un servicio (p.ej. header 'Server:' leido sobre el socket TLS de un
    # host HTTPS-only) que esta regla de version necesita para poder matchear.
    _run_check("Vulnerabilidades de version", result, _check_generic_version_vulns, result)
    _run_check("Privilegios para MAC", result, _check_missing_mac_privileges, result, skip_mac)
    _run_check("Consolidacion de hallazgos", result, _consolidate_port_findings, result)

    result.scan_duration_s = time.time() - start
    return result


def _run_check(label: str, result: HostResult, fn, *args) -> None:
    """Aisla cada chequeo: si uno falla por una excepcion no prevista, se
    pierde solo ese hallazgo (registrado en result.errors), no el resto de
    los datos ya recolectados del host (puertos, banners, SO, MAC...)."""
    try:
        fn(*args)
    except Exception as exc:
        result.errors.append(f"{label}: fallo interno del chequeo ({exc})")


def _consolidate_port_findings(result: HostResult) -> None:
    """Reduce el ruido: cuando un mismo puerto ya tiene un hallazgo de
    'Conexiones remotas expuestas', se fusiona en el el hallazgo de 'Riesgo de
    fuerza bruta' del mismo puerto (que dice esencialmente lo mismo: el
    servicio esta accesible) en vez de listarlo por separado. Antes, un 445
    abierto generaba 3 hallazgos casi identicos. La categoria MDM se conserva
    aparte porque describe una superficie distinta (gestion)."""
    exposure_by_port = {
        v.port: v
        for v in result.vulnerabilities
        if v.category == "Conexiones remotas no autorizadas/expuestas" and v.port is not None
    }
    kept = []
    for v in result.vulnerabilities:
        if (
            v.category == "Riesgo de fuerza bruta / configuraciones por defecto"
            and v.port in exposure_by_port
        ):
            target = exposure_by_port[v.port]
            if "fuerza bruta" not in target.recommendation.lower():
                target.recommendation += (
                    " Ademas, por ser un servicio propenso a fuerza bruta, verificar "
                    "rate-limiting, bloqueo de cuenta y MFA."
                )
            continue  # se descarta el hallazgo de fuerza bruta duplicado
        kept.append(v)
    result.vulnerabilities = kept


def _check_remote_access_exposure(result: HostResult) -> None:
    for port, label in REMOTE_ACCESS_PORTS.items():
        if port not in result.open_ports:
            continue
        if port == 23:
            severity = Severity.CRITICAL
            desc = (
                "Telnet transmite credenciales y datos en texto plano. "
                "Un atacante en la misma red puede interceptar sesiones "
                "completas mediante sniffing."
            )
        elif port in (5900, 5901):
            severity = Severity.HIGH
            desc = "VNC expuesto; muchas implementaciones usan autenticacion debil o sin cifrado por defecto."
        elif port == 3389:
            severity = Severity.HIGH
            desc = "RDP expuesto a la red; objetivo frecuente de ataques de fuerza bruta y exploits (p.ej. BlueKeep en versiones sin parchear)."
        elif port == 22:
            severity = Severity.MEDIUM
            desc = "SSH expuesto; revisar mas abajo hallazgos especificos de version/algoritmos."
        elif port == 5938:
            ## TeamViewer: exigir confirmacion por banner para no marcar por el
            ## solo numero de puerto (evita falso positivo si otro servicio lo usa).
            banner = (result.services.get(port).banner or "") if result.services.get(port) else ""
            if "teamviewer" in banner.lower():
                severity = Severity.MEDIUM
                desc = "Software de acceso remoto TeamViewer confirmado por banner; verificar si es autorizado."
            else:
                severity = Severity.INFO
                desc = "Puerto 5938 abierto (asociado a TeamViewer) pero SIN confirmar por banner; puede ser otro servicio. Verificar."
        else:
            severity = Severity.MEDIUM
            desc = f"Servicio de acceso remoto ({label}) expuesto en la red."

        result.add_vuln(
            Vulnerability(
                title=f"Servicio de acceso remoto expuesto: {label} (puerto {port})",
                category="Conexiones remotas no autorizadas/expuestas",
                severity=severity,
                description=desc,
                recommendation=(
                    "Restringir el acceso mediante firewall/VPN/listas blancas, "
                    "deshabilitar el servicio si no es necesario, y si es "
                    "imprescindible, forzar autenticacion multifactor y cifrado "
                    "fuerte (evitar Telnet/VNC sin TLS)."
                ),
                port=port,
                evidence=(result.services.get(port).banner if result.services.get(port) else None),
            )
        )


# Puertos de gestion cuyo numero es ambiguo (lo usan tambien servicios no de
# gestion): se degradan a INFO cuando no hay banner que confirme el rol.
_AMBIGUOUS_MDM_PORTS = {4444, 9090}


def _check_mdm_exposure(result: HostResult) -> None:
    for port, label in MDM_MANAGEMENT_PORTS.items():
        if port not in result.open_ports:
            continue
        banner = (result.services.get(port).banner if result.services.get(port) else None)
        if port in _AMBIGUOUS_MDM_PORTS:
            severity = Severity.INFO
            description = (
                f"Puerto {port} abierto ({label}). Es un numero ambiguo usado por varios "
                "servicios; no se pudo confirmar un rol de gestion por banner. Verificar que "
                "servicio corre realmente antes de tratarlo como superficie de administracion."
            )
        else:
            severity = Severity.MEDIUM
            description = (
                f"Se detecto el puerto {port} ({label}) abierto, tipicamente usado para "
                "administracion remota. Si no esta restringido a redes de gestion dedicadas, "
                "aumenta la superficie de ataque."
            )
        result.add_vuln(
            Vulnerability(
                title=f"Servicio de gestion remota/MDM expuesto: {label} (puerto {port})",
                category="Gestion de dispositivos (MDM) y agentes",
                severity=severity,
                description=description,
                recommendation=(
                    "Limitar el acceso a redes de administracion segregadas "
                    "(VLAN de gestion), aplicar autenticacion fuerte y "
                    "mantener el agente/servicio actualizado."
                ),
                port=port,
                evidence=banner,
            )
        )


def _check_brute_force_risk(result: HostResult) -> None:
    for port, label in BRUTE_FORCE_PRONE_PORTS.items():
        if port not in result.open_ports:
            continue
        result.add_vuln(
            Vulnerability(
                title=f"Riesgo de fuerza bruta por exposicion: {label} (puerto {port})",
                category="Riesgo de fuerza bruta / configuraciones por defecto",
                severity=Severity.MEDIUM,
                description=(
                    f"El servicio {label} esta accesible desde la red analizada. "
                    "No se realizaron intentos de autenticacion (fuera del "
                    "alcance etico de esta herramienta); se reporta como "
                    "riesgo de exposicion: si el servicio carece de "
                    "rate-limiting, bloqueo de cuenta o MFA, es susceptible "
                    "de ataques de fuerza bruta/diccionario."
                ),
                recommendation=(
                    "Verificar manualmente politicas de bloqueo de cuenta, "
                    "rate-limiting y MFA. Considerar fail2ban/NLA (RDP), "
                    "listas blancas de IP y deshabilitar cuentas/contrasenas "
                    "por defecto."
                ),
                port=port,
            )
        )


def _check_generic_version_vulns(result: HostResult) -> None:
    for port, svc in result.services.items():
        if not svc.banner:
            continue
        for rule in match_version_rules(svc.banner, GENERIC_VERSION_RULES):
            result.add_vuln(
                Vulnerability(
                    title=rule.title,
                    category="Falta de actualizaciones y parches",
                    severity=Severity(rule.severity) if rule.severity in [s.value for s in Severity] else Severity.MEDIUM,
                    description=rule.description,
                    recommendation="Actualizar el servicio a la ultima version estable soportada por el fabricante.",
                    port=port,
                    evidence=svc.banner,
                    cve_refs=rule.cves,
                )
            )


def _check_smb(result: HostResult, timeout_s: float) -> None:
    """Negocia SMB (sin autenticar) para detectar SMBv1 (MS17-010/EternalBlue)
    y si la firma SMB es requerida -- lo que marcan nmap smb-protocols /
    smb-security-mode y Nessus, y que la deteccion por-puerto no cubria."""
    if 445 not in result.open_ports:
        return

    findings = smb_analyzer.analyze_smb(result.ip, timeout_s=timeout_s)
    if not findings.reachable:
        return

    if findings.smbv1_enabled is True:
        result.add_vuln(
            Vulnerability(
                title="SMBv1 habilitado (candidato a MS17-010/EternalBlue)",
                category="Falta de actualizaciones y parches",
                severity=Severity.CRITICAL,
                description=(
                    "El servidor acepta negociar el protocolo SMBv1, obsoleto y sin soporte. "
                    "Es el vector de EternalBlue/WannaCry (MS17-010). Confirmado por negociacion "
                    "SMB real (no por numero de puerto)."
                ),
                recommendation=(
                    "Deshabilitar SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false y "
                    "Disable-WindowsOptionalFeature -FeatureName SMB1Protocol) y aplicar el parche "
                    "MS17-010. Reiniciar para completar."
                ),
                port=445,
                evidence=findings.detail,
                cve_refs=["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145"],
            )
        )

    if findings.signing_required is False:
        result.add_vuln(
            Vulnerability(
                title="Firma SMB no requerida (SMB signing not required)",
                category="Riesgo de fuerza bruta / configuraciones por defecto",
                severity=Severity.MEDIUM,
                description=(
                    "El servidor SMB no exige firma de mensajes (SecurityMode sin el bit "
                    "SIGNING_REQUIRED). Permite ataques de SMB relay/MITM dentro de la red local. "
                    "Confirmado por negociacion SMB real."
                ),
                recommendation=(
                    "Exigir firma SMB: Set-SmbServerConfiguration -RequireSecuritySignature $true "
                    "(o via GPO 'Servidor de red Microsoft: firmar digitalmente las comunicaciones (siempre)')."
                ),
                port=445,
                evidence=findings.detail,
            )
        )


def _check_ssh(result: HostResult, timeout_s: float) -> None:
    if 22 not in result.open_ports:
        return

    findings = ssh_analyzer.analyze_ssh_algorithms(result.ip, 22, timeout_s=timeout_s)
    if findings.banner:
        svc = result.services.setdefault(22, ServiceInfo(port=22, name="ssh"))
        svc.banner = svc.banner or findings.banner

        for rule in match_version_rules(findings.banner, SSH_VULN_RULES):
            result.add_vuln(
                Vulnerability(
                    title=rule.title,
                    category="Falta de actualizaciones y parches",
                    severity=Severity(rule.severity) if rule.severity in [s.value for s in Severity] else Severity.MEDIUM,
                    description=rule.description,
                    recommendation="Actualizar OpenSSH/implementacion SSH a una version soportada y aplicar hardening (sshd_config).",
                    port=22,
                    evidence=findings.banner,
                    cve_refs=rule.cves,
                )
            )

    if findings.weak_kex or findings.weak_ciphers or findings.weak_macs:
        detalle = []
        if findings.weak_kex:
            detalle.append(f"KEX debiles: {', '.join(findings.weak_kex)}")
        if findings.weak_ciphers:
            detalle.append(f"Cifrados debiles: {', '.join(findings.weak_ciphers)}")
        if findings.weak_macs:
            detalle.append(f"MACs debiles: {', '.join(findings.weak_macs)}")
        result.add_vuln(
            Vulnerability(
                title="Algoritmos criptograficos SSH debiles habilitados",
                category="Seguridad en capa de red y cifrado (SSH)",
                severity=Severity.HIGH,
                description=(
                    "El servidor SSH ofrece algoritmos de intercambio de "
                    "claves, cifrado o MAC considerados obsoletos/inseguros. "
                    + "; ".join(detalle)
                ),
                recommendation=(
                    "Editar sshd_config para deshabilitar KexAlgorithms, "
                    "Ciphers y MACs debiles, dejando solo opciones modernas "
                    "(p.ej. curve25519-sha256, chacha20-poly1305/aes-gcm, "
                    "hmac-sha2-256-etm)."
                ),
                port=22,
                evidence="; ".join(detalle),
            )
        )

    for err in findings.errors:
        result.errors.append(f"SSH: {err}")


# Subconjunto de TLS_PORTS donde vale la pena sondear un HEAD / HTTP: los
# demas (993 IMAPS, 995 POP3S, 465 SMTPS, 636 LDAPS) no hablan HTTP y solo
# perderian tiempo hasta el timeout sin devolver un header 'Server:'.
_HTTP_LIKE_TLS_PORTS = {443, 8443, 5986}


def _check_tls(result: HostResult, timeout_s: float) -> None:
    tls_ports = [p for p in result.open_ports if p in TLS_PORTS]
    for port in tls_ports:
        findings = ssl_analyzer.analyze_tls(result.ip, port, timeout_s=timeout_s)
        if not findings.reachable:
            for err in findings.errors:
                result.errors.append(f"TLS:{port}: {err}")
            continue

        svc = result.services.setdefault(port, ServiceInfo(port=port, name="tls"))
        svc.extra["tls_protocol"] = findings.negotiated_protocol or "desconocido"
        svc.extra["tls_cipher"] = findings.negotiated_cipher or "desconocido"

        if not svc.banner and port in _HTTP_LIKE_TLS_PORTS:
            http_banner = ssl_analyzer.probe_http_server_header(result.ip, port, timeout_s=timeout_s)
            if http_banner:
                svc.banner = http_banner
                svc.name = "https"

        if findings.cert_expired:
            result.add_vuln(
                Vulnerability(
                    title=f"Certificado TLS caducado (puerto {port})",
                    category="Seguridad en capa de red y cifrado (SSL/TLS)",
                    severity=Severity.HIGH,
                    description=f"El certificado presentado expiro el {findings.cert_not_after}.",
                    recommendation="Renovar el certificado TLS antes de su expiracion y automatizar su renovacion (p.ej. ACME/Let's Encrypt).",
                    port=port,
                    evidence=findings.cert_not_after,
                )
            )

        if findings.cert_self_signed:
            result.add_vuln(
                Vulnerability(
                    title=f"Certificado TLS autofirmado (puerto {port})",
                    category="Seguridad en capa de red y cifrado (SSL/TLS)",
                    severity=Severity.MEDIUM,
                    description="El certificado es autofirmado (emisor = sujeto), lo que impide validar confianza y expone a ataques MITM.",
                    recommendation="Emitir un certificado firmado por una CA confiable (interna o publica) para servicios de produccion.",
                    port=port,
                    evidence=findings.cert_subject,
                )
            )

        if findings.obsolete_protocols_supported:
            result.add_vuln(
                Vulnerability(
                    title=f"Protocolos TLS/SSL obsoletos habilitados (puerto {port})",
                    category="Seguridad en capa de red y cifrado (SSL/TLS)",
                    severity=Severity.HIGH,
                    description=(
                        "El servidor acepta protocolos obsoletos: "
                        + ", ".join(findings.obsolete_protocols_supported)
                        + f". Referencia de protocolos considerados inseguros: {', '.join(OBSOLETE_TLS_PROTOCOLS)}."
                    ),
                    recommendation="Deshabilitar SSLv2/SSLv3/TLS1.0/TLS1.1 y forzar TLS 1.2 o superior.",
                    port=port,
                    evidence=", ".join(findings.obsolete_protocols_supported),
                )
            )

        if findings.weak_cipher:
            result.add_vuln(
                Vulnerability(
                    title=f"Cifrado TLS debil negociado (puerto {port})",
                    category="Seguridad en capa de red y cifrado (SSL/TLS)",
                    severity=Severity.MEDIUM,
                    description=f"El cifrado negociado por defecto ({findings.negotiated_cipher}) contiene componentes considerados debiles.",
                    recommendation="Reconfigurar la suite de cifrado del servidor para priorizar AEAD modernos (AES-GCM, ChaCha20-Poly1305) y forward secrecy (ECDHE).",
                    port=port,
                    evidence=findings.negotiated_cipher,
                )
            )

        for err in findings.errors:
            result.errors.append(f"TLS:{port}: {err}")


def _check_missing_mac_privileges(result: HostResult, skip_mac: bool) -> None:
    if not skip_mac and result.alive and not result.mac:
        result.errors.append(
            "No se pudo obtener la direccion MAC (requiere privilegios de "
            "administrador/root y, en Windows, Npcap instalado; o que el "
            "host este en la misma subred L2)."
        )
