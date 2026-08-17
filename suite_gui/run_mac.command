#!/bin/zsh
# Lanzador para macOS de la Suite de Seguridad Interna.
# Doble clic en Finder para ejecutar (o correr './run_mac.command' en Terminal).
# La primera vez instala las dependencias de Python; luego solo abre la app.

cd "$(dirname "$0")" || exit 1

echo "== Suite de Seguridad Interna (macOS) =="

# Elegir interprete de Python 3 disponible.
if command -v python3 >/dev/null 2>&1; then
    PY=python3
else
    echo "ERROR: no se encontro Python 3. Instalalo desde https://www.python.org/downloads/ o con 'brew install python'."
    read "?Enter para cerrar..."
    exit 1
fi

# Instalar dependencias si falta alguna de las clave (chequeo rapido).
if ! $PY -c "import winrm, smbclient, rich, reportlab, paramiko" >/dev/null 2>&1; then
    echo "Instalando dependencias (solo la primera vez)..."
    $PY -m pip install --user --disable-pip-version-check -r requirements.txt || {
        echo "Fallo la instalacion de dependencias."; read "?Enter para cerrar..."; exit 1;
    }
fi

echo "Abriendo la aplicacion..."
exec $PY app.py
