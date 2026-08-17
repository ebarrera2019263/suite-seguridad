# Suite de Seguridad Interna (GUI unica)

Interfaz grafica unica que agrupa las 4 herramientas de la suite en un solo
`.exe`, pensada para que cualquiera del equipo la pueda usar sin memorizar
flags de linea de comandos:

- **Auditoria de Red** (`ip_audit_core`) — escaneo de puertos/servicios y
  correlacion con vulnerabilidades conocidas.
- **Hardening Local** (`hardening_core`) — diagnostico y correccion de la
  configuracion de seguridad de ESTE equipo.
- **Auditoria de Credenciales** (`credential_core`) — validacion real de
  contrasenas locales via SMB/WinRM.
- **Parche Remoto** (`remote_patch_core`) — bloqueo de RDP y endurecimiento
  de TLS en un equipo remoto via WinRM.

## Que es y que NO es este folder

`ip_audit_core/`, `hardening_core/`, `credential_core/` y
`remote_patch_core/` son **copias exactas, sin ningun cambio de logica**,
de los `core/` de `ip_audit_tool/`, `hardening_tool/`,
`credential_audit_tool/` y `remote_patch_tool/` respectivamente (solo se
renombro la carpeta para que las 4 puedan convivir en un mismo proceso de
Python sin pisarse el nombre `core`). Los 4 `.exe` originales siguen
existiendo y funcionando exactamente igual que antes; esto es una interfaz
grafica ADICIONAL, no un reemplazo.

Los archivos `app.py`, `gui_common.py` y `tab_*.py` son nuevos: son
unicamente la capa de interfaz (formularios, tabla de hallazgos, consola de
log, dialogos de confirmacion) — la logica de analisis/remediacion en si
no cambia.

## Salvaguardas conservadas

Cada pestana replica, con dialogos en vez de prompts de consola, las
mismas confirmaciones eticas/de seguridad que tenia la version de linea de
comandos: frase de autorizacion tipeada donde el original la exigia,
confirmacion reforzada para cambios de alto impacto (firewall/RDP/WinRM en
sesion remota), la guarda anti-autobloqueo de `remote_patch_tool`
(incluido el fallo-cerrado si no se puede verificar la IP local), y el
punto de restauracion opcional antes de aplicar correcciones de
hardening.

## Como recompilar

```powershell
.\build_exe.ps1
```

Genera `dist\SuiteSeguridadInterna.exe` (onefile, sin consola). Requiere
Python con las dependencias de `requirements.txt` (se instalan solas si no
estan).

## Como ejecutar en desarrollo (sin compilar)

```powershell
python app.py
```

Para el diagnostico/correccion de la pestana de Hardening Local conviene
ejecutar como Administrador (la pestana avisa y ofrece reiniciar elevado
si hace falta).
