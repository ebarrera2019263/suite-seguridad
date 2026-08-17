# Manual de Usuario — IP Hardening Tool (local)

Guía paso a paso: qué escribir en cada pregunta y cómo verificar que la
herramienta funciona correctamente **antes** de aplicar cualquier cambio
real.

**Recuerde:** este `.exe` solo audita y corrige **el equipo en el que se
ejecuta**. No tiene ninguna función de red hacia otras máquinas.

---

## 0. Primera vez: verifique en modo solo-diagnóstico (recomendado)

Antes de aplicar ninguna corrección, abra una terminal (cmd/PowerShell)
en la carpeta del `.exe` y ejecute:

```bat
IPHardeningTool.exe --dry-run
```

Este modo **nunca pregunta si desea aplicar una corrección ni cambia
nada** — solo diagnostica y genera el reporte. Úselo para comprobar que
todo funciona y para ver qué encontraría antes de tocar la configuración
real. Cuando esté listo para corregir de verdad, ejecute el `.exe` sin
`--dry-run` (doble clic o desde terminal) y siga la Sección 1 en adelante.

---

## 1. Abrir la herramienta

Doble clic en `IPHardeningTool.exe` (o ejecútelo desde una terminal).

---

## 2. Privilegios de Administrador

Si no la abrió ya como Administrador, verá:

```
Se requieren privilegios de Administrador para diagnosticar y corregir la configuracion de este equipo.
¿Reiniciar ahora como Administrador (se pedira confirmacion de Windows/UAC)? [S/n]:
```

**Responda:**

```
s
```

(o simplemente presione Enter, "S" es la opción por defecto). Windows
mostrará su propio cuadro de **Control de Cuentas de Usuario (UAC)** —
haga clic en **"Sí"**. La ventana original se cierra y se abre una nueva
ya como Administrador; continúe en esa nueva ventana.

---

## 3. Aviso si está conectado por Escritorio Remoto

Si abrió la herramienta a través de una sesión RDP, verá un aviso
amarillo. **Léalo**: significa que más adelante, si aparecen hallazgos de
Firewall/RDP/WinRM, se le pedirá una confirmación reforzada (escribir la
palabra completa "confirmo") porque un cambio mal aplicado podría cortar
su propia sesión remota. Tenga a mano otra forma de acceder al equipo
(consola física, iDRAC/iLO, otra sesión) antes de confirmar esos cambios.

---

## 4. Aviso legal y confirmación de autorización

```
AVISO LEGAL Y ETICO
Esta herramienta MODIFICA la configuracion de seguridad de ESTE equipo...

¿Confirma que esta autorizado para modificar la configuracion de este equipo? [s/N]:
```

**Responda:**

```
s
```

---

## 5. Punto de restauración

```
¿Crear un punto de restauracion de Windows antes de continuar? [S/n]:
```

**Responda:**

```
s
```

(o Enter, "S" es la opción por defecto). Si el equipo no admite puntos de
restauración (frecuente en Windows Server), la herramienta lo indica y
continúa igual — no es un error bloqueante.

---

## 6. Diagnóstico automático (no requiere respuesta)

La herramienta ejecuta todas las verificaciones sola y muestra una tabla:

```
Diagnostico local — <nombre-del-equipo>
Severidad | Categoria | Hallazgo | Estado | Correccion
...
Resumen: 18 verificaciones, N hallazgos, 0 corregidos en esta sesion.
```

---

## 7. Confirmar cada corrección, una por una

Por cada hallazgo con corrección disponible, verá algo como:

```
Alta — Protocolo SMBv1 habilitado
  Detalle: SMBv1 esta habilitado en este equipo.
  Recomendacion: Deshabilitar SMBv1: es un protocolo obsoleto...
  ¿Aplicar esta correccion ahora? [s/N]:
```

**Para cada una, decida usted:**
- Escriba `s` + Enter para **aplicarla**.
- Presione Enter sin escribir nada (o escriba `n`) para **omitirla** — no
  se toca esa configuración.

No hay una respuesta "correcta" única aquí: depende de si esa
configuración es necesaria en su equipo (por ejemplo, si SMBv1 lo usa
algún sistema legado, no lo deshabilite todavía). Si tiene dudas sobre un
hallazgo puntual, escriba `n` y revíselo con calma leyendo la
"Recomendación" en el reporte HTML antes de decidir.

Si el hallazgo es de Firewall/RDP/WinRM **y** la sesión es remota (ver
paso 3), en vez de `[s/N]` verá:

```
Escriba EXACTAMENTE 'confirmo' para aplicar este cambio, o presione Enter para omitir:
```

Escriba la palabra `confirmo` completa solo si está seguro; cualquier
otra cosa (incluido Enter vacío) omite el cambio.

---

## 8. Cómo saber que SÍ funcionó (checklist de verificación)

Al terminar debe ver:

1. ✅ Un resumen: `Resumen: 18 verificaciones, N hallazgos, X corregidos en esta sesion.`
2. ✅ Si hubo hallazgos manuales (ej. software de acceso remoto de
   terceros, actualizaciones pendientes), una lista al final bajo
   "Hallazgos que requieren revisión manual".
3. ✅ Dos rutas de archivos generados:
   ```
   Reporte JSON: reportes_hardening\diagnostico_<fecha>.json
   Reporte HTML: reportes_hardening\diagnostico_<fecha>.html
   ```
4. ✅ Si aplicó al menos una corrección, una tercera ruta:
   ```
   Script de reversion: reportes_hardening\deshacer_<fecha>.ps1
   ```
5. ✅ Al final: `Presione Enter para salir...` — la ventana no se cierra
   sola.

Abra el `.html` generado en su navegador: debe verse un informe oscuro
con una tabla de verificaciones, columna "Estado" (OK/VULNERABLE) y
columna "Corrección" (Aplicada/Omitida/Manual/-).

---

## 9. Si algo salió mal después de aplicar una corrección

1. Abra la carpeta `reportes_hardening` y localice
   `deshacer_<fecha>.ps1` de la sesión correspondiente.
2. Ábralo con un editor de texto y revise los comandos (algunos están
   marcados como "NO recomendado" porque revierten a un estado menos
   seguro — solo úselos si de verdad necesita deshacer ese cambio
   puntual).
3. Ejecute ese `.ps1` como Administrador, o copie y pegue manualmente
   solo la línea que necesita revertir en una consola de PowerShell como
   Administrador.
4. Si creó un punto de restauración (paso 5), también puede usar
   "Restaurar sistema" de Windows para volver por completo al estado
   anterior.

---

## 10. Resumen rápido de respuestas

| # | Pregunta | Respuesta recomendada |
|---|---|---|
| 2 | ¿Reiniciar como Administrador? [S/n] | `s` (y "Sí" en el cuadro de UAC) |
| 4 | ¿Confirma que está autorizado...? [s/N] | `s` |
| 5 | ¿Crear punto de restauración? [S/n] | `s` |
| 7 | ¿Aplicar esta corrección ahora? [s/N] | `s` si quiere aplicarla, Enter/`n` para omitirla (revise una por una) |
| 7 (si sesión remota + cambio de alto impacto) | Escriba 'confirmo' | Solo si está seguro y tiene otra vía de acceso al equipo |

---

## 11. Recordatorio ético y de seguridad

- Use esta herramienta solo en equipos propios o con autorización
  explícita como administrador.
- Pruebe primero con `--dry-run` en cualquier equipo nuevo antes de
  aplicar correcciones reales.
- Revise cada hallazgo antes de responder `s`: usted conoce mejor que la
  herramienta si esa configuración es necesaria en su caso particular.
- Guarde el script `deshacer_<fecha>.ps1` de cada sesión hasta confirmar
  que todo sigue funcionando correctamente.
