# Ejecutar la Suite de Seguridad en macOS

La app ahora corre en Mac. Se reemplazaron las partes que dependian de
comandos exclusivos de Windows (`net use`, `powershell.exe`/WinRM) por
librerias de Python multiplataforma, para que 3 de las 4 herramientas
funcionen desde esta Mac contra equipos Windows de la red.

## Como abrirla

**Opcion facil (doble clic):** en Finder, doble clic en **`run_mac.command`**.
La primera vez instala las dependencias solo; despues abre la app directo.

> Si macOS dice "no se puede abrir porque es de un desarrollador no
> identificado": clic derecho sobre `run_mac.command` → **Abrir** → **Abrir**.

**Opcion terminal:**

```bash
cd suite_gui
python3 -m pip install -r requirements.txt   # solo la primera vez
python3 app.py
```

Requiere Python 3 (ya instalado en esta Mac: 3.12).

## Que funciona y que no en Mac

| Pestana | En Mac | Notas |
|---|---|---|
| **Auditoria de Red** | ✅ Nativa | Escaneo de puertos/servicios y correlacion de vulnerabilidades, igual que en Windows. |
| **Auditoria de Credenciales** | ✅ Contra Windows remoto | Ahora usa SMB (`smbprotocol`) y WinRM (`pywinrm`) en vez de `net use`/`powershell.exe`. Respeta la politica de bloqueo de cuentas. |
| **Parche Remoto** | ✅ Contra Windows remoto | Bloqueo de RDP / hardening TLS via WinRM. **Requiere credenciales explicitas** (usuario + contrasena) de un admin del equipo remoto: marque "Usar credenciales distintas a esta sesion". |
| **Hardening Local** | ⚠️ No disponible | Ausculta configuracion propia de Windows (Registro, Defender, firewall de Windows...) que no existe en macOS. La pestana muestra un aviso. Para endurecer un Windows, ejecute esa pestana desde ese Windows. |

## Requisitos en el equipo Windows objetivo

Las pestanas de Credenciales y Parche Remoto hablan con el equipo Windows
remoto, que debe tener habilitado el canal correspondiente:

- **SMB (Credenciales):** puerto **445** accesible.
- **WinRM (Credenciales via WinRM y Parche Remoto):** `Enable-PSRemoting` en el
  equipo destino y el firewall permitiendo el puerto **5985** (HTTP).

## Nota de verificacion

Las rutas de error (host caido, puerto cerrado, credenciales rechazadas) se
probaron en esta Mac. La autenticacion real y la aplicacion de cambios
requieren un equipo Windows de prueba con SMB/WinRM habilitado — validalas
en tu entorno antes de usarlo en produccion.
