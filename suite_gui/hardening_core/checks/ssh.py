"""Verificacion del servidor OpenSSH de Windows (si esta instalado):
algoritmos de intercambio de claves/cifrado/MAC debiles en sshd_config."""
from __future__ import annotations

import os
import re
import shutil
from datetime import datetime
from pathlib import Path

from ..models import CheckResult, Severity
from ..ps import run_ps, run_ps_json

_SSHD_CONFIG = Path(r"C:\ProgramData\ssh\sshd_config")

_WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
_WEAK_CIPHERS = {"3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc", "des-cbc", "none"}
_WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "none"}

_DIRECTIVES = {
    "KexAlgorithms": _WEAK_KEX,
    "Ciphers": _WEAK_CIPHERS,
    "MACs": _WEAK_MACS,
}

## Whitelists modernas (solo algoritmos fuertes) que se escriben explicitamente
## cuando una categoria no queda con una directiva fuerte propia, para no
## depender de los defaults de la version de OpenSSH desplegada.
_STRONG_DIRECTIVES = {
    "KexAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256",
    "Ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
    "MACs": "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512",
}


def _ssh_server_present() -> bool:
    data = run_ps_json("Get-Service sshd -ErrorAction SilentlyContinue | Select-Object Status")
    return data is not None


def _strip_inline_comment(line: str) -> str:
    """Elimina un comentario de fin de linea (todo despues de un '#'
    precedido de espacio, igual que el parser real de sshd_config), para
    que no se cuele como parte del ultimo algoritmo de la lista."""
    match = re.search(r"\s#", line)
    return line[:match.start()] if match else line


def _parse_weak_directives(text: str):
    findings = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = _strip_inline_comment(stripped).strip()
        if not stripped:
            continue
        for directive, weak_set in _DIRECTIVES.items():
            if stripped.lower().startswith(directive.lower()):
                values = re.split(r"\s+", stripped, maxsplit=1)
                if len(values) < 2:
                    continue
                items = [v.strip().lstrip("+-^") for v in values[1].split(",")]
                weak = [v for v in items if v.lower() in weak_set]
                if weak:
                    findings[directive] = weak
    return findings


def _effective_weak_algos():
    """Devuelve {directiva: [algoritmos debiles ofrecidos]} usando 'sshd -T'
    (config efectiva, incluye los defaults de la version), o None si no se
    pudo ejecutar. sshd -T imprime las directivas en minusculas."""
    proc = run_ps(f'& sshd -T -f "{_SSHD_CONFIG}" 2>&1; "EXITCODE:$LASTEXITCODE"')
    out = proc.stdout or ""
    if "EXITCODE:0" not in out:
        return None
    dumped = {"KexAlgorithms": "kexalgorithms", "Ciphers": "ciphers", "MACs": "macs"}
    findings = {}
    lowered = {line.split(None, 1)[0].lower(): line for line in out.splitlines() if line.strip()}
    for directive, key in dumped.items():
        line = lowered.get(key)
        if not line:
            continue
        parts = re.split(r"\s+", line.strip(), maxsplit=1)
        if len(parts) < 2:
            continue
        offered = [v.strip().lower() for v in parts[1].split(",")]
        weak = [v for v in offered if v in _DIRECTIVES[directive]]
        if weak:
            findings[directive] = weak
    return findings


def check_ssh_weak_algorithms() -> CheckResult:
    if not _ssh_server_present():
        return CheckResult(
            check_id="ssh_weak_algorithms",
            title="Algoritmos SSH debiles habilitados",
            category="Seguridad en capa de red y cifrado (SSH)",
            severity=Severity.HIGH,
            vulnerable=False,
            determinable=True,
            detail="El servidor OpenSSH (sshd) no esta instalado/en ejecucion en este equipo.",
            recommendation="No aplica.",
            fixable=False,
        )

    if not _SSHD_CONFIG.exists():
        return CheckResult(
            check_id="ssh_weak_algorithms",
            title="Algoritmos SSH debiles habilitados",
            category="Seguridad en capa de red y cifrado (SSH)",
            severity=Severity.HIGH,
            vulnerable=False,
            determinable=False,
            detail=f"El servicio sshd esta presente pero no se encontro {_SSHD_CONFIG}.",
            recommendation="Verificar la ubicacion real de sshd_config.",
            fixable=False,
        )

    ## Preferir la config EFECTIVA (incluye defaults) via 'sshd -T'; si no se
    ## puede, caer al parseo del archivo (solo ve directivas explicitas).
    effective = _effective_weak_algos()
    if effective is not None:
        findings = effective
        source = "config efectiva (sshd -T, incluye defaults)"
    else:
        findings = _parse_weak_directives(_SSHD_CONFIG.read_text(encoding="utf-8", errors="ignore"))
        source = "sshd_config (solo directivas explicitas; no se pudo obtener la config efectiva con sshd -T)"

    vulnerable = bool(findings)
    detail_parts = [f"{k}: {', '.join(v)}" for k, v in findings.items()]
    return CheckResult(
        check_id="ssh_weak_algorithms",
        title="Algoritmos SSH debiles habilitados",
        category="Seguridad en capa de red y cifrado (SSH)",
        severity=Severity.HIGH,
        vulnerable=vulnerable,
        detail=(f"[{source}] algoritmos obsoletos ofrecidos -> " + "; ".join(detail_parts)) if vulnerable else f"[{source}] no se ofrecen algoritmos KEX/cifrado/MAC debiles.",
        recommendation="Eliminar los algoritmos debiles de las directivas KexAlgorithms/Ciphers/MACs en sshd_config y reiniciar el servicio sshd.",
        fixable=True,
    )


def fix_ssh_weak_algorithms():
    if not _SSHD_CONFIG.exists():
        return False, "sshd_config no encontrado.", "# no aplica"

    text = _SSHD_CONFIG.read_text(encoding="utf-8", errors="ignore")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = _SSHD_CONFIG.with_name(f"sshd_config.bak_{timestamp}")
    shutil.copy2(_SSHD_CONFIG, backup_path)

    new_lines = []
    directive_has_strong_line = {d: False for d in _DIRECTIVES}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        comment_free = _strip_inline_comment(stripped).strip()
        matched_directive = None
        for directive, weak_set in _DIRECTIVES.items():
            if comment_free.lower().startswith(directive.lower()):
                matched_directive = (directive, weak_set)
                break
        if not matched_directive:
            new_lines.append(line)
            continue

        directive, weak_set = matched_directive
        parts = re.split(r"\s+", comment_free, maxsplit=1)
        if len(parts) < 2:
            new_lines.append(line)
            continue
        ## Se preserva el prefijo +/-/^ (sintaxis OpenSSH de "añadir/quitar del
        ## default") en los tokens que se conservan; solo se compara la parte
        ## sin prefijo contra el set de algoritmos debiles.
        items = [v.strip() for v in parts[1].split(",")]
        strong_items = [v for v in items if v.lstrip("+-^").lower() not in weak_set]
        if strong_items:
            new_lines.append(f"{directive} {','.join(strong_items)}")
            directive_has_strong_line[directive] = True
        # si no queda ninguno, se omite la linea (mas abajo se agrega una fuerte explicita)

    ## Cierra la brecha "los algoritmos debiles OFRECIDOS POR DEFECTO quedan sin
    ## tocar": para cada categoria sin directiva fuerte explicita, se agrega una
    ## whitelist moderna. Asi ssh-audit / nmap ssh2-enum-algos ya no ve
    ## diffie-hellman-group14-sha1, MACs SHA-1, etc. aunque estuvieran en el default.
    for directive, strong_value in _STRONG_DIRECTIVES.items():
        if not directive_has_strong_line[directive]:
            new_lines.append(f"{directive} {strong_value}")

    _SSHD_CONFIG.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    undo = (
        f'Copy-Item "{backup_path}" "{_SSHD_CONFIG}" -Force; Restart-Service sshd  '
        "# restaura la configuracion SSH previa (incluye los algoritmos debiles originales)"
    )

    ## Valida sintaxis ANTES de reiniciar el servicio, para no reportar éxito
    ## si la reescritura dejó sshd_config invalido (p.ej. por un caso borde de
    ## parseo). Si 'sshd' no esta en PATH, se continua sin poder validar
    ## (no es un caso de error, solo de imposibilidad de verificar).
    check_proc = run_ps(f'& sshd -t -f "{_SSHD_CONFIG}" 2>&1; "EXITCODE:$LASTEXITCODE"')
    check_output = check_proc.stdout or ""
    if "is not recognized" in check_output or "no se reconoce" in check_output.lower():
        config_valid = None  # no se pudo validar
    else:
        config_valid = "EXITCODE:0" in check_output

    if config_valid is False:
        shutil.copy2(backup_path, _SSHD_CONFIG)
        message = (
            "La reescritura de sshd_config quedo invalida (sshd -t fallo); se restauro "
            f"automaticamente el respaldo. Detalle: {check_output.strip()[:300]}"
        )
        return False, message, f'# No hace falta: ya se restauro automaticamente desde "{backup_path}"'

    restart_proc = run_ps("Restart-Service sshd")
    if restart_proc.returncode != 0:
        message = (
            f"sshd_config actualizado (respaldo en {backup_path.name}), pero el servicio sshd "
            f"NO pudo reiniciarse: {(restart_proc.stderr or '').strip()[:300]}. Reviselo manualmente; "
            "el archivo de configuracion en si es sintacticamente valido."
            if config_valid else
            f"sshd_config actualizado (respaldo en {backup_path.name}, sintaxis no verificable), pero "
            f"el servicio sshd NO pudo reiniciarse: {(restart_proc.stderr or '').strip()[:300]}."
        )
        return False, message, undo

    validated_note = "validado y " if config_valid else "(sintaxis no verificable, sshd no esta en PATH) "
    message = f"sshd_config actualizado (respaldo en {backup_path.name}), {validated_note}servicio sshd reiniciado correctamente."
    return True, message, undo
