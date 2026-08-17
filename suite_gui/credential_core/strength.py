"""Evaluacion simple de fortaleza de una contrasena encontrada. No calcula
entropia criptografica exacta; da una etiqueta y notas utiles para el
reporte de validacion de politica."""
from __future__ import annotations

import re
from typing import Tuple

_COMMON_PATTERNS = [
    r"^123", r"^abc", r"password", r"qwerty", r"welcome",
    r"admin", r"contrasena", r"cambiar", r"empresa",
]


def evaluate_password(password: str, username: str = "", from_known_weak_list: bool = False) -> Tuple[str, str]:
    """Devuelve (etiqueta, notas).

    from_known_weak_list=True fuerza etiqueta 'Critica': si la contrasena se
    ADIVINO probandola de la lista de debiles/comunes, es critica por
    definicion sin importar su composicion (una '=Verano2026!' adivinada en
    <40 intentos NO es 'Media'). Se usa para el path de credenciales
    crackeadas; el scoring por composicion se conserva para el WiFi cosechado
    (contrasenas reales fuera de la lista)."""
    if from_known_weak_list:
        _, notes = _evaluate_composition(password, username)
        return "Critica", f"ADIVINADA de la lista de contrasenas debiles/comunes. {notes}"
    return _evaluate_composition(password, username)


def _evaluate_composition(password: str, username: str = "") -> Tuple[str, str]:
    if password == "":
        return "Critica", "Contrasena en blanco."

    notes = []
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    variety = sum([has_lower, has_upper, has_digit, has_symbol])

    if length < 8:
        notes.append(f"longitud muy corta ({length} caracteres)")
    elif length < 12:
        notes.append(f"longitud por debajo de lo recomendado ({length} caracteres, se recomienda 12+)")

    if variety <= 1:
        notes.append("usa un solo tipo de caracter")
    elif variety == 2:
        notes.append("combina solo 2 tipos de caracter")

    if username and password.lower().startswith(username.lower()[:4]) and len(username) >= 4:
        notes.append("contiene/deriva del nombre de usuario")

    for pattern in _COMMON_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            notes.append(f"coincide con un patron comun ('{pattern}')")
            break

    if re.search(r"(.)\1{2,}", password):
        notes.append("contiene caracteres repetidos consecutivos")

    if length < 8 or variety == 1:
        label = "Critica"
    elif length < 10 or variety <= 2:
        label = "Alta"
    elif length < 12:
        label = "Media"
    else:
        label = "Baja"

    if not notes:
        notes.append("cumple longitud/variedad minimas, pero igual estaba en la lista de contrasenas debiles probadas")

    return label, "; ".join(notes)
