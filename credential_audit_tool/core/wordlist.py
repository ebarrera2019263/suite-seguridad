"""Lista curada (pequena, no exhaustiva) de contrasenas debiles/comunes,
usada para validar politicas de contrasena -- NO es un diccionario de
fuerza bruta masivo tipo rockyou.txt. La idea es responder "¿esta
contrasena esta entre las mas obvias que probaria cualquiera?", no agotar
el espacio de busqueda."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

DEFAULT_WORDLIST: List[str] = [
    "", "123456", "12345678", "123456789", "1234567890",
    "password", "Password1", "Password1!", "P@ssw0rd", "P@ssword1",
    "Welcome1", "Welcome1!", "Admin123", "Admin123!", "Administrator1",
    "Qwerty123", "Qwerty123!", "Abc12345", "Abcd1234",
    "Cambiar123", "Cambiar123!", "Contrasena1", "Contrasena123",
    "Empresa123", "Empresa2026", "Verano2026!", "Enero2026!",
    "Password123", "Password2026", "Passw0rd!", "Iloveyou1",
    "letmein1", "Trustno1", "Monkey123", "Sunshine1",
    "12345", "1234", "111111", "000000",
]


def load_wordlist(custom_path: Optional[str]) -> List[str]:
    if not custom_path:
        return list(DEFAULT_WORDLIST)
    lines = Path(custom_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    words = [line.rstrip("\n") for line in lines if line.strip() or line == ""]
    return words or list(DEFAULT_WORDLIST)


def _is_local_account_name(u: str) -> bool:
    """El invariante central es "solo cuentas LOCALES" para acotar el radio de
    un bloqueo a una maquina. Se rechazan nombres calificados con dominio:
    'CORP\\alice', 'alice@corp.local', '.\\alice', o con '/'. Solo se permiten
    nombres SAM locales simples."""
    return not any(sep in u for sep in ("\\", "/", "@"))


def load_usernames(raw: Optional[str], file_path: Optional[str]) -> List[str]:
    import sys
    users: List[str] = []
    if file_path:
        users.extend(
            u.strip() for u in Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines() if u.strip()
        )
    if raw:
        users.extend(u.strip() for u in raw.split(",") if u.strip())

    ## Hace cumplir el invariante local-only (antes solo estaba en la doc):
    ## un 'CORP\alice' colado probaria credenciales contra el DC y podria
    ## bloquear una cuenta de dominio (radio de impacto = toda la organizacion).
    valid = []
    for u in users:
        if _is_local_account_name(u):
            valid.append(u)
        else:
            print(f"[!] Usuario con dominio descartado (solo cuentas locales): {u}", file=sys.stderr)
    users = valid

    # Siempre se incluye Administrator como cuenta local tipica a validar.
    if not any(u.lower() == "administrator" for u in users):
        users.append("Administrator")
    seen = set()
    deduped = []
    for u in users:
        if u.lower() not in seen:
            seen.add(u.lower())
            deduped.append(u)
    return deduped
