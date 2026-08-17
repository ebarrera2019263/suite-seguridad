# Remote Patch Tool

Herramienta puntual: se le indica **una IP** y aplica remotamente (WinRM)
dos correcciones específicas — **bloquear RDP** y **forzar TLS más
seguro** — en esa máquina. No lee reportes, no escanea rangos, no toca
ninguna otra máquina.

## Qué hace

1. **Bloquear RDP**: crea una regla de Firewall de Windows que bloquea
   TCP 3389 entrante. No desinstala ni deshabilita el servicio de
   Escritorio Remoto — solo el puerto. **WinRM (5985/5986) no se toca a
   propósito**, para que esta misma herramienta pueda seguir alcanzando
   el equipo después (por ejemplo, para revertir el bloqueo).
2. **Forzar TLS más seguro**: deshabilita explícitamente SSLv2, SSLv3,
   TLS 1.0 y TLS 1.1 (registro SCHANNEL) y las suites de cifrado débiles
   (RC4/DES/3DES/MD5/EXPORT/NULL).

Cada acción se confirma **por separado** antes de aplicarse (salvo
`--skip-confirms`).

## ⚠️ Antes de usarla

- Requiere **WinRM habilitado** en el equipo objetivo (`Enable-PSRemoting`,
  suele venir ya configurado por GPO en entornos de dominio) y que quien
  ejecuta la herramienta tenga permisos de administrador ahí (de la
  sesión actual, o credenciales alternativas que se piden al vuelo).
- **Guarda de auto-objetivo incorporada**: la herramienta se niega a
  ejecutarse contra la IP de la propia máquina que la corre, para evitar
  bloquearse el propio RDP por error.
- **Verifique antes de bloquear RDP** que no es la única vía de acceso
  remoto a ese equipo. Si algo sale mal, revierta con `--undo`.
- TLS puede requerir **reiniciar el equipo remoto** para completarse del
  todo, y puede romper aplicaciones internas viejas que dependan de
  TLS 1.0/1.1 — revíselo antes de aplicar en producción.
- Uso exclusivo sobre equipos de su organización, con autorización.

## Uso

```bash
python main.py --ip 172.16.68.50
```

O sin `--ip`, para que lo pregunte interactivamente (también funciona con
el `.exe` de doble clic).

### Revertir

```bash
python main.py --ip 172.16.68.50 --undo
```

Quita la regla de bloqueo de RDP y los valores explícitos de TLS
(vuelve al comportamiento por defecto del sistema operativo; las suites
de cifrado débiles no se reactivan automáticamente por diseño).

### Parámetros

| Parámetro | Descripción |
|---|---|
| `--ip` | IP de la máquina objetivo (si se omite, se pregunta) |
| `--undo` | Revierte block_rdp y harden_tls en vez de aplicarlos |
| `--yes` | Omite la confirmación ética inicial |
| `--skip-confirms` | No pregunta antes de cada acción individual |
| `--output-dir` | Carpeta de reportes (default `reportes_remotos`) |
| `--no-pause` | No espera Enter al finalizar |

## Generar el .exe

```powershell
.\build_exe.ps1
```
