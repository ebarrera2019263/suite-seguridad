"""Helpers minimos sobre el registro de Windows (solo el equipo local:
HKEY_LOCAL_MACHINE/HKEY_CURRENT_USER de la maquina en la que corre el
proceso; el modulo winreg de Python no admite -ni se usa aqui- un host
remoto)."""
from __future__ import annotations

from typing import Optional

try:
    import winreg
except ImportError:  # no-Windows, solo para poder importar el paquete en otros SO
    winreg = None  # type: ignore


def read_value(hive, path: str, name: str):
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(hive, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except FileNotFoundError:
        return None
    except OSError:
        return None


def write_dword(hive, path: str, name: str, value: int) -> bool:
    if winreg is None:
        return False
    try:
        with winreg.CreateKey(hive, path) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        return True
    except OSError:
        return False


def write_string(hive, path: str, name: str, value: str) -> bool:
    if winreg is None:
        return False
    try:
        with winreg.CreateKey(hive, path) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        return True
    except OSError:
        return False


def delete_value(hive, path: str, name: str) -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def enum_subkey_names(hive, path: str):
    if winreg is None:
        return []
    names = []
    try:
        with winreg.OpenKey(hive, path) as key:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    return names


def hive_name(hive) -> str:
    if winreg is None:
        return str(hive)
    mapping = {
        winreg.HKEY_LOCAL_MACHINE: "HKLM",
        winreg.HKEY_CURRENT_USER: "HKCU",
    }
    return mapping.get(hive, str(hive))
