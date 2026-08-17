# Comparativa contra Nessus y hoja de ruta interna

Documento de referencia para responder una pregunta concreta: **¿qué le
faltaría a esta suite (`ip_audit_tool` + `hardening_tool` +
`credential_audit_tool` + `remote_patch_tool`) para acercarse a Nessus,
pensado para uso INTERNO sobre la propia flota (los ~110 equipos de
`172.16.68.0/24`, `172.16.69.0/24` y `192.168.60.0/24` descriptos en
`PLAN_ADMINISTRACION.md`), no para competir con Nessus como producto
general?** Complementa a `COBERTURA_LIMITES.md` (qué queda fuera de
alcance por diseño) con foco en qué SÍ conviene construir.

---

## 1. Resumen ejecutivo

Nessus es fuerte por tres cosas que esta suite no tiene ni le conviene
replicar del todo: un feed de ~70.000 plugins actualizado a diario, escaneo
credenciado de parches de SO contra el catálogo real de KBs de Microsoft, y
auditoría de compliance contra benchmarks formales (CIS/DISA STIG) con
miles de reglas ya escritas.

Pero para el uso real que le da este despacho — auditar y remediar SU
PROPIA flota, no un tercero — la suite ya cubre bien la superficie Windows
(SMB, RDP, TLS/SCHANNEL, cuentas, WinRM, Defender, firewall) con algo que
Nessus no hace: además de detectar, corrige (`hardening_tool`,
`remote_patch_tool`) y valida contraseñas reales (`credential_audit_tool`).
Lo que falta no es "todo Nessus", son ítems puntuales y bien acotados.

**La brecha más grande y más barata de cerrar es el patch-audit
credenciado de Windows** (sección 3.1): ya existe `patch_audit.ps1` en el
repo, corriendo por separado; integrarlo al reporte de `ip_audit_tool` es
la mejora individual de mayor impacto.

---

## 2. Lo que la suite YA hace al nivel de Nessus (o mejor)

No arrancar de cero: esto ya está bien resuelto y no hace falta tocarlo.

- **Negociación real de protocolo, no solo número de puerto**: SMBv1/firma
  SMB (`smb_analyzer.py`), algoritmos SSH débiles (`ssh_analyzer.py`),
  protocolos/cifrados TLS obsoletos (`ssl_analyzer.py`) — exactamente el
  mismo principio que `nmap --script smb-security-mode` / `ssl-enum-ciphers`
  / `testssl.sh`, con falsos positivos ya revisados y documentados en el
  propio código (TLS 1.3 con `set_ciphers`, SMB1 rechazado vs. negociado).
- **Remediación real**, algo que Nessus NO hace (solo detecta):
  `hardening_tool` corrige localmente con reversión (`restore.py`),
  `remote_patch_tool` corrige de forma remota vía WinRM.
- **Validación real de contraseñas** contra cuentas locales
  (`credential_audit_tool`), con salvaguardas de alcance (solo cuentas
  locales, nunca de dominio) que van más allá de lo que un Nessus sin
  credenciales puede confirmar.
- **Diseño ético explícito**: `ip_audit_tool` nunca autentica; los módulos
  que sí lo hacen exigen confirmación reforzada y limitan el radio de
  impacto. Es una diferencia deliberada y correcta frente a Nessus (que si
  se le dan credenciales, sí las prueba activamente).

---

## 3. Brecha por capacidad — qué hace Nessus que esta suite no

| Capacidad | Nessus | Esta suite hoy | ¿Vale la pena cerrarla acá? |
|---|---|---|---|
| Parches de SO (credenciado) | Lee KBs instalados reales vía WMI/registro contra catálogo de Microsoft | Heurística débil por fecha del último hotfix (`updates.py`); `patch_audit.ps1` existe pero corre aparte | **Sí — máxima prioridad** (3.1) |
| SNMP / UDP | Community string por defecto, sysDescr, etc. | Sin escaneo UDP en absoluto | **Sí** (3.2) — su propia red de switches/APs Ubiquiti típicamente expone SNMP |
| Cobertura de versiones/CVE | ~70.000 plugins, feed diario | ~10 reglas curadas a mano en `vuln_db.py`, sin Dropbear/MySQL/PostgreSQL/nginx | Parcial (3.3) — ampliar el set curado, no perseguir el feed completo |
| Reconocimiento de appliances | Plugins dedicados (iDRAC, impresoras HP, etc.) | Ninguno; el dato ya está en el JSON (CN del cert) pero no se usa | **Sí, barato** (3.4) — es literalmente su propio inventario conocido |
| CVSS / severidad estandarizada | Vector CVSS v2/v3 por hallazgo | Severidad fija asignada a mano, sin rank numérico | Parcial (3.5) — agregar rank, no el vector completo |
| Diff entre escaneos | Sí, nativo | Cada corrida es un JSON aislado | **Sí** (3.6) — encaja con la Fase 6 de `PLAN_ADMINISTRACION.md` |
| Compliance (CIS/DISA STIG) | Miles de reglas, pass/fail formal | `hardening_tool` cubre ítems sueltos de CIS, no el benchmark completo | No perseguir el benchmark completo; sí cerrar los ítems puntuales de la sección 3.7 |
| Credenciales por defecto (no-Windows) | Prueba activa segura contra catálogo de fabricantes | `ip_audit_tool` solo marca exposición, nunca prueba | Parcial (3.8) — extender el criterio ya validado de `credential_audit_tool` |
| Validación de cadena de certificado / tamaño de clave | Sí | Solo expirado/autofirmado | Parcial (3.9) |
| Feed de vulnerabilidades actualizado a diario | Sí, es su negocio principal | No aplica | **No** — no tiene sentido re-construir esto in-house (ver sección 4) |
| Escaneo de aplicaciones web (SQLi/XSS) | Básico | Fuera de alcance (documentado en `COBERTURA_LIMITES.md`) | **No** — correcto tal como está |

---

## 3. Qué construir, en orden de prioridad

### 3.1 Integrar el patch-audit credenciado al reporte principal (prioridad máxima)

Hoy `updates.py` en `hardening_tool` solo mira la fecha del último hotfix
instalado (heurística débil, ya marcada como "solo informativa" en el
propio código) y `patch_audit.ps1` corre como script suelto contra una
lista de equipos. Nessus gana su reputación principalmente por esto: leer
el catálogo real de actualizaciones vía `Get-HotFix`/`Get-CimInstance
Win32_QuickFixEngineering` o el COM object `Microsoft.Update.Session`
contra cada equipo credenciado, y compararlo contra qué KB es la vigente
para esa build de Windows.

**Propuesta concreta:** que `ip_audit_tool` (que ya recorre toda la red)
acepte credenciales opcionales de dominio y, para los hosts donde WinRM
responda, corra el equivalente de `patch_audit.ps1` inline y lo vuelque
como un hallazgo más del mismo JSON/HTML — hoy son dos herramientas y dos
reportes separados que el analista tiene que cruzar a mano.

### 3.2 Escaneo UDP acotado (SNMP)

Agregar sondeo UDP a puerto 161 con un `GET` de `sysDescr` usando
community strings `public`/`private` (2 intentos, sin más, mismo criterio
ético que ya aplica `credential_audit_tool`). Es de las pocas categorías
donde un pentest real casi siempre encuentra algo en redes con equipos de
red tipo Ubiquiti, y hoy es estructuralmente invisible para
`ip_audit_tool` (todo el escaneo es TCP connect).

### 3.3 Ampliar `GENERIC_VERSION_RULES` / `SSH_VULN_RULES`

Los propios reportes reales ya capturan banners de **Dropbear** (switches/
APs Ubiquiti) y de errores de **MySQL** sin ninguna regla que los evalúe.
Agregar reglas curadas (mismo formato ya usado, con el mismo cuidado por
falsos positivos que ya demuestra el archivo) para Dropbear, MySQL,
PostgreSQL, nginx, ProFTPD. Para que esto no requiera recompilar el `.exe`
cada vez que aparece una versión nueva, conviene mover `vuln_db.py` (o al
menos las listas de reglas) a un JSON externo que el `.exe` lea al
arrancar — así se actualiza el "feed" editando un archivo, no rehaciendo el
build.

### 3.4 Reconocer los appliances propios por fingerprint

El JSON de `ip_audit_tool` ya captura el **CN del certificado** (`CN=idrac-
CCYKYS3`, `unifi.local`, certificados de ESET) pero no lo usa para nada.
Una tabla chica de fingerprints conocidos (por CN, por banner, por puerto
característico) alcanza para reconocer específicamente **iDRAC, UniFi
Controller, ESET PROTECT, QNAP** — que son exactamente los cuatro
appliances que aparecen una y otra vez en `PLAN_ADMINISTRACION.md` — y
adjuntarles la guía de hardening específica (contraseña por defecto de
iDRAC, firmware, etc.) en vez de un genérico "certificado autofirmado".

### 3.5 Rank numérico de severidad

Agregar `severidad_rank` (entero) junto al string en español en
`Vulnerability.to_dict()` de los cuatro módulos. Bajo esfuerzo, y el propio
`README.md` de `ip_audit_tool` ya promociona el JSON como apto para
integrarse con un SIEM — hoy cualquier integrador tendría que hardcodear
los strings en español para poder ordenar por severidad.

### 3.6 Diff entre escaneos

Dado que `PLAN_ADMINISTRACION.md` ya define una rutina mensual ("menos
hallazgos mes a mes es tu mejor evidencia de trabajo"), conviene un
modo `--compare-with reporte_anterior.json` que señale: hosts nuevos, hosts
que desaparecieron, hallazgos nuevos, hallazgos resueltos. Es lógica pura
sobre dos JSON ya existentes, no requiere tocar ningún analizador.

### 3.7 Ítems puntuales de CIS que faltan en `hardening_tool`

De la lista larga de un benchmark CIS completo, los que más aplican a este
entorno (dominio AD, sin perseguir el benchmark entero):
política de contraseñas/bloqueo de cuenta, firma SMB del lado **cliente**
(hoy solo se audita el lado servidor), NoLMHash/WDigest, y el servicio
Print Spooler (PrintNightmare, CVE-2021-34527) — el equivalente moderno de
SMBv1/EternalBlue, que la suite ya trata como referencia de "vulnerabilidad
histórica de alto perfil" pero sin su sucesor más reciente.

### 3.8 Credenciales por defecto en servicios no-Windows expuestos

`ip_audit_tool` ya marca como expuestos MySQL/PostgreSQL/MSSQL/VNC/IPMI
pero nunca prueba nada (correcto, por diseño). Se podría extender el mismo
criterio ético ya validado en `credential_audit_tool` (opt-in explícito,
aviso legal, alcance acotado) a un intento único y no destructivo de
credenciales de fábrica conocidas (`admin`/`admin`, IPMI `ADMIN`/`ADMIN`,
etc.) contra ESOS mismos servicios, en vez de solo reportar la exposición.

### 3.9 Validación más profunda de certificados TLS

Sumar a `ssl_analyzer.py`: tamaño de clave RSA &lt; 2048, firma con SHA-1,
y aviso de "expira en menos de 30 días" (hoy es binario expirado/no
expirado). La librería `cryptography` que ya se usa alcanza para esto sin
agregar dependencias nuevas.

---

## 4. Lo que NO conviene intentar replicar

Coherente con el tono de `COBERTURA_LIMITES.md`: hay partes de Nessus que
son, en esencia, su producto principal, y perseguirlas in-house sale más
caro que usarlas cuando hagan falta.

- **Feed de CVEs actualizado a diario** (~70.000 plugins): mantener esto al
  día es un trabajo full-time de un equipo dedicado. La estrategia correcta
  es la que ya está documentada — usar esta suite para el monitoreo
  interno continuo y remediable, y correr un Nessus/OpenVAS real
  periódicamente (o antes de una auditoría externa) para la cobertura
  profunda de CVEs que un set curado nunca va a igualar.
- **Compliance formal contra benchmarks completos** (CIS Level 1/2, DISA
  STIG): miles de reglas, muchas de bajísimo impacto real para 110 equipos.
  Mejor cerrar los ítems puntuales de alto impacto (sección 3.7) que perseguir
  el checklist completo.
- **Escaneo de aplicaciones web** (SQLi/XSS, OWASP Top 10): ya
  correctamente fuera de alcance en `COBERTURA_LIMITES.md`. Requiere un
  motor completamente distinto (crawling, fuzzing de parámetros) que no
  tiene sinergia con el resto de la suite.
- **Motor de plugins genérico/extensible**: Nessus permite escribir
  plugins arbitrarios en NASL. Para una suite de uso interno con un fleet
  conocido y estable, una lista curada bien mantenida (secciones 3.3/3.4)
  da el 90% del valor con una fracción del esfuerzo de construir un motor
  de plugins real.

---

## 5. Orden sugerido

1. **Ahora** (bajo esfuerzo, alto impacto): 3.4 (fingerprint de
   appliances propios), 3.5 (rank de severidad), 3.6 (diff entre
   escaneos) — los tres son lógica nueva sobre datos que el JSON ya tiene.
2. **Corto plazo**: 3.1 (integrar patch-audit credenciado — el de mayor
   impacto real) y 3.3 (ampliar reglas de versión, con el JSON externo
   para no depender de recompilar).
3. **Mediano plazo**: 3.2 (UDP/SNMP), 3.7 (ítems CIS puntuales), 3.9
   (certificados).
4. **Si el apetito de riesgo lo permite** (requiere la misma revisión
   ética que ya tiene `credential_audit_tool`): 3.8.
5. **No construir**: sección 4 completa — apoyarse en un Nessus/OpenVAS
   real para eso, con esta suite como capa de monitoreo y remediación
   continua entre auditorías externas.

---

*Documento de trabajo interno, complementario a `COBERTURA_LIMITES.md` y
`PLAN_ADMINISTRACION.md`. Basado en la revisión de código de agosto 2026
(ver también las correcciones aplicadas esa misma sesión a los 5 bugs
críticos y 6 de severidad alta detectados en `ip_audit_tool`,
`hardening_tool`, `credential_audit_tool` y `remote_patch_tool`).*
