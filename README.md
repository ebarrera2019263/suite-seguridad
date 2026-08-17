# Suite de Seguridad

Suite de herramientas de auditoría y endurecimiento de seguridad para redes
y equipos Windows, con una **interfaz gráfica multiplataforma** (Windows y
macOS) además de herramientas de línea de comandos independientes.

> ⚠️ **Uso autorizado únicamente.** Estas herramientas están diseñadas para
> auditar sistemas y redes de tu propiedad o sobre los que tengas
> autorización explícita por escrito. El uso contra sistemas de terceros sin
> permiso es ilegal.

---

## Componentes

### 🖥️ `suite_gui/` — Aplicación con interfaz gráfica
Aplicación unificada con pestañas que integra las cuatro herramientas.
Funciona en **Windows y macOS**. Es el punto de entrada principal.

| Pestaña | Función |
|---------|---------|
| **Auditoría de IP** | Descubre hosts, inventario (IP/MAC/hostname/SO), puertos y servicios expuestos, correlación de vulnerabilidades, prueba blackbox de **inyección SQL** y evaluación de **exposición a DDoS** |
| **Auditoría de Credenciales** | Valida la resistencia de la política de contraseñas (SMB / WinRM) frente a una lista curada y pequeña |
| **Hardening** | Audita la configuración de seguridad del equipo y aplica correcciones con confirmación explícita |
| **Parche Remoto** | Aplica correcciones puntuales por WinRM a una máquina (bloquear RDP, forzar TLS seguro) |

Genera reportes en **JSON, HTML y PDF**.

### Herramientas independientes (CLI)
- **`ip_audit_tool/`** — Auditoría de seguridad de redes internas.
- **`credential_audit_tool/`** — Validación de política de contraseñas.
- **`hardening_tool/`** — Endurecimiento local del equipo Windows.
- **`remote_patch_tool/`** — Aplicación remota de parches específicos vía WinRM.

### Documentación y recursos adicionales
- `COMPARATIVA_NESSUS.md` — Comparativa de cobertura frente a Nessus.
- `COBERTURA_LIMITES.md` — Alcance y límites de las pruebas.
- `PLAN_ADMINISTRACION.md` / `.pdf` — Plan de administración.
- `GPO_HARDENING.md` / `.pdf` y `create_gpos.ps1` — Hardening por GPO.
- `patch_audit.ps1` — Script de auditoría de parches.

---

## Requisitos

- **Python 3.12+**
- Dependencias en `suite_gui/requirements.txt`:
  `rich`, `paramiko`, `cryptography`, `scapy`, `reportlab`,
  `pywinrm`, `smbprotocol`, `pyinstaller`

## Instalación y ejecución (GUI)

```bash
cd suite_gui
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
python app.py
```

En **macOS** también puedes usar el lanzador `suite_gui/run_mac.command`.
Ver `suite_gui/EJECUTAR_EN_MAC.md` para detalles.

---

## Notas

- La carpeta `reportes/` (resultados de auditorías reales) queda **excluida**
  del control de versiones por privacidad — ver `.gitignore`.
- Las herramientas piden **confirmación explícita** antes de aplicar cualquier
  cambio en un sistema.
