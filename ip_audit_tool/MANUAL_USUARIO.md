# Manual de Usuario — IP Security Audit Tool

Guía paso a paso para verificar que `IPSecurityAuditTool.exe` funciona
correctamente, con exactamente qué escribir en cada pregunta.

---

## 0. Antes de empezar

- Ubicación del ejecutable: `ip_audit_tool\dist\IPSecurityAuditTool.exe`
- Para esta primera prueba de verificación, use un objetivo **seguro y de
  su propiedad**: su propia PC (`127.0.0.1`) o su red local de casa/oficina
  (ej. `192.168.1.0/24`). No apunte a redes que no sean suyas.
- No necesita ser Administrador para esta prueba (responda "s" en la
  pregunta de MAC, ver paso 3).

---

## 1. Abrir la herramienta

Doble clic en `IPSecurityAuditTool.exe`.

Se abre una ventana de consola negra. Esto es normal — es una herramienta
de terminal, no tiene ventanas gráficas.

---

## 2. Primera pantalla (informativa, no requiere responder nada)

Verá algo como:

```
IP SECURITY AUDIT TOOL
Auditoria de seguridad de red - Uso exclusivo autorizado

No se recibieron argumentos: iniciando modo interactivo.
(Tambien puede usar esta herramienta desde una terminal con argumentos...)
```

Esto confirma que el `.exe` arrancó bien. Continúe al siguiente paso.

---

## 3. Preguntas del asistente — qué escribir en cada una

### Pregunta 1

```
Ingrese IP(s), rango CIDR o rango (ej: 192.168.1.0/24 o 192.168.1.10,192.168.1.20):
```

**Para verificar que funciona, escriba:**

```
127.0.0.1
```

y presione **Enter**. (Esto analiza su propia PC — es rápido, seguro y no
requiere permisos especiales. Si prefiere probar contra su red local,
escriba el rango CIDR de su router, ej. `192.168.1.0/24`.)

> Si no escribe nada y presiona Enter, la herramienta cancela con
> "No se ingreso ningun objetivo." — es el comportamiento esperado, vuelva
> a abrir el `.exe` e intente de nuevo.

### Pregunta 2

```
¿Omitir resolucion de MAC (no requiere ser Administrador)? [s/N]:
```

**Para esta prueba, escriba:**

```
s
```

y presione Enter. (Si no abrió el `.exe` como Administrador —clic derecho
→ "Ejecutar como administrador"—, responder "s" evita advertencias
innecesarias. Si sí lo abrió como Administrador y quiere probar la
detección de MAC, responda "n" o simplemente presione Enter, que también
es válido).

### Pregunta 3

```
Carpeta de salida para reportes [reportes]:
```

**Para esta prueba, simplemente presione Enter sin escribir nada**, para
aceptar el valor por defecto (`reportes`). Los reportes JSON/HTML se
guardarán en una carpeta llamada `reportes` junto al `.exe`.

### Pregunta 4 (aviso legal — siempre aparece)

```
AVISO LEGAL Y ETICO
Esta herramienta debe usarse UNICAMENTE sobre redes/equipos propios o con
autorizacion explicita por escrito...

¿Confirma que cuenta con autorizacion para escanear estos objetivos? [s/N]:
```

**Escriba:**

```
s
```

y presione Enter. (Si responde "n" o presiona Enter sin escribir nada, la
herramienta cancela la operación — es el comportamiento esperado de
seguridad, no un error.)

---

## 4. Ejecución del análisis

Tras confirmar, la herramienta empieza a trabajar sola, sin más preguntas:

```
1 objetivos a analizar, 34 puertos por host, 20 hilos.
Analizando hosts... ████████████████████████████████ 1/1 0:00:11
```

Espere a que la barra llegue a `1/1` (o al total de IPs si escaneó un
rango). Con `127.0.0.1` tarda aproximadamente 10-15 segundos.

---

## 5. Cómo saber que SÍ funcionó (checklist de verificación)

Al terminar debe ver, en este orden:

1. ✅ Una **tabla "Inventario de Activos"** con una fila para `127.0.0.1`,
   columna "Estado" en verde con el texto `Activo`.
2. ✅ Si se encontraron hallazgos, una **tabla "Hallazgos en 127.0.0.1"**
   con columnas Severidad / Categoría / Puerto / Título.
3. ✅ Una línea de resumen: `Resumen: 1/1 hosts activos, N hallazgos totales.`
4. ✅ Dos líneas confirmando los archivos generados:
   ```
   Reporte JSON: reportes\reporte_20260730_101421.json
   Reporte HTML: reportes\reporte_20260730_101421.html
   ```
5. ✅ Al final: `Presione Enter para salir...` — la ventana **ya no se
   cierra sola**; presione Enter cuando quiera cerrarla.

**Confirmación adicional (fuera de la consola):** abra la carpeta donde
está el `.exe`, entre a la carpeta `reportes` y verifique que existen los
dos archivos:

- `reporte_<fecha>_<hora>.json`
- `reporte_<fecha>_<hora>.html`

Haga doble clic en el `.html` — debe abrirse en su navegador mostrando un
informe con fondo oscuro, tabla de inventario y, si hubo hallazgos, tarjetas
por host con severidad coloreada (rojo = crítica/alta, ámbar = media, celeste = baja).

Si ve estos 5 puntos y los 2 archivos, **la herramienta funciona
correctamente**.

---

## 6. Resumen rápido de respuestas (para copiar mientras se prueba)

| # | Pregunta | Qué responder en la prueba |
|---|---|---|
| 1 | Ingrese IP(s), rango CIDR o rango | `127.0.0.1` |
| 2 | ¿Omitir resolución de MAC? [s/N] | `s` |
| 3 | Carpeta de salida para reportes [reportes] | (Enter, dejar vacío) |
| 4 | ¿Confirma que cuenta con autorización...? [s/N] | `s` |

---

## 7. Uso real (después de verificar que funciona)

Para auditar su propia red local en vez de solo su PC:

- Rango completo: `192.168.1.0/24` (ajuste al rango real de su router,
  visible en la configuración del router o ejecutando `ipconfig` en
  Windows y mirando "Puerta de enlace predeterminada").
- Varias IPs sueltas: `192.168.1.10,192.168.1.20,192.168.1.30`
- Desde archivo: prepare un `ips.txt` (vea `ips.example.txt`) y arrástrelo
  sobre el ícono de `IPSecurityAuditTool.exe` — se usa automáticamente
  como lista de objetivos sin pasar por las preguntas 1 y 3.

Para uso avanzado por línea de comandos (más opciones, sin preguntas),
abra `cmd` o PowerShell en la carpeta del `.exe` y ejecute, por ejemplo:

```bat
IPSecurityAuditTool.exe --targets 192.168.1.0/24 --output-dir reportes --threads 30
```

Vea `IPSecurityAuditTool.exe --help` para ver todas las opciones, y el
`README.md` para el detalle completo de cada parámetro.

---

## 8. Problemas comunes

| Síntoma | Causa probable | Solución |
|---|---|---|
| Windows Defender/SmartScreen bloquea el `.exe` | Comportamiento normal para ejecutables no firmados generados con PyInstaller | Clic en "Más información" → "Ejecutar de todas formas" |
| `Estado: Sin respuesta` para una IP que sí existe | El firewall del equipo objetivo bloquea ICMP (ping) y los puertos comunes probados | Pruebe con `--skip-mac` y confirme que la IP responde a `ping` manualmente, o revise el firewall del objetivo |
| Columna MAC siempre en `-` | No se ejecutó como Administrador, o falta Npcap | Clic derecho sobre el `.exe` → "Ejecutar como administrador", o instale [Npcap](https://npcap.com/); si no le interesa el dato MAC, ignore este aviso |
| `WARNING: No libpcap provider available` | Falta Npcap/WinPcap | Es solo una advertencia, no impide el resto del análisis; instale Npcap si necesita direcciones MAC vía ARP |
| La ventana se cierra sola | Versión antigua del `.exe` (antes de la corrección) | Use el `.exe` recompilado en `dist/`, que pausa siempre antes de cerrar |
| `No se resolvieron objetivos validos` | El texto ingresado en la Pregunta 1 no es una IP/CIDR válido (ej. tiene espacios o letras) | Revise el formato: `192.168.1.1` o `192.168.1.0/24`, sin espacios |

---

## 9. Recordatorio ético

Use esta herramienta solo sobre equipos y redes propios, o con
autorización explícita por escrito. El escaneo de redes de terceros sin
permiso puede ser ilegal.
