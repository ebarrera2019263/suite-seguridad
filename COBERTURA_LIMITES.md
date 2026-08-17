# Límites de cobertura frente a un pentest de Kali

Estas herramientas cubren muy bien la superficie **Windows** (SMB, RDP,
TLS/SCHANNEL, cuentas, LLMNR/NetBIOS, WinRM, Defender, parches locales).
Pero un pentest real desde Kali (nmap NSE, Nessus, OpenVAS, testssl.sh)
escanea **todo** lo que responde en la red, incluidos equipos y servicios
que estas herramientas **no pueden remediar por diseño**. Para que la
auditoría salga limpia de verdad, estos puntos hay que cerrarlos por otra
vía. Es lo que queda fuera del alcance del código:

## 1. Servicios TLS que no usan el stack de Windows (SCHANNEL)

`hardening_tool` y `remote_patch_tool` endurecen TLS por SCHANNEL, que solo
gobierna IIS/HTTP.sys, RDP-TLS, WinRM-HTTPS y LDAPS. **No tocan**:

- **Apache / nginx / cualquier cosa con OpenSSL propio** → configurar
  `SSLProtocol`/`ssl_protocols` a TLS 1.2+1.3 y suites fuertes en el
  propio servicio, validar (`apachectl configtest` / `nginx -t`) y
  recargar.
- **Java / Tomcat / Elasticsearch / Jenkins (JSSE)** → endurecer en la
  config del runtime Java.
- **Node.js y apps embebidas** → en la propia app.

Un `ssl-enum-ciphers` / `testssl.sh` contra esos hosts seguirá mostrando
TLS 1.0/1.1 o RC4/3DES aunque toda la remediación Windows esté aplicada.

## 2. Servicios en equipos NO Windows (Linux / appliances / red)

El GPO solo alcanza equipos Windows unidos al dominio. Quedan fuera:

- **SSH débil en Linux / equipos de red** → endurecer
  `/etc/ssh/sshd_config` (KexAlgorithms/Ciphers/MACs modernos), validar
  `sshd -t`, `systemctl reload sshd`. (`hardening_tool` solo corrige el
  OpenSSH-para-Windows local).
- **FTP / vsFTPd en Linux** → deshabilitar o migrar a SFTP; el backdoor de
  vsFTPd 2.3.4 solo existe en un demonio Linux, no alcanzable por GPO.
- **PPTP (1723) en router/appliance** → migrar a IKEv2/SSTP; cerrar el
  puerto en el borde.
- **IPMI (623) en BMC/iDRAC/iLO** → deshabilitar cipher 0, contraseña BMC
  fuerte, firmware actualizado, y restringir 623 a la VLAN de gestión por
  ACL de red (CVE-2013-4786 es inherente al protocolo).
- **Webmin (10000) / Cockpit (9090)** → son consolas Linux; endurecer o
  restringir por firewall del propio host.

## 3. Certificados TLS (caducados / autofirmados)

Ninguna herramienta renueva certificados. Un `testssl.sh`/Nessus seguirá
marcando self-signed/expired en 443/636/5986 hasta que se emitan
certificados de una CA confiable:

- **AD CS + auto-enrollment por GPO** para emitir certificados de máquina
  desde una CA interna.
- Appliances / Linux → renovación manual o ACME (Let's Encrypt).

## 4. Fuerza bruta / credenciales por defecto en servicios no-Windows

`ip_audit_tool` marca exposición de MySQL/MSSQL/PostgreSQL/VNC, pero la
contramedida (bloqueo de cuenta) del GPO solo aplica a cuentas Windows/AD.
Para el resto: cambiar credenciales por defecto, contraseñas fuertes,
fail2ban / bloqueo a nivel de servicio, y restringir el listener a la
subred de gestión. `credential_audit_tool` valida la política pero **no
resetea contraseñas**.

## 5. Lo que ningún escáner de configuración cubre

Un pentest también evalúa cosas fuera del alcance total de esta suite:
nivel de parches del SO, vulnerabilidades de aplicaciones web (SQLi/XSS),
rutas de ataque de Active Directory (Kerberoasting, delegación), phishing
e ingeniería social, y acceso físico. Eso requiere el trabajo del equipo
de pentest, no una herramienta de hardening.

---

**Resumen práctico:** corré `ip_audit_tool` para tener el inventario de lo
que responde, aplicá `hardening_tool` + los GPO en la flota Windows, usá
`remote_patch_tool` para RDP/TLS puntuales, y para todo lo de las
secciones 1–4 de arriba (no-Windows, PKI, appliances) armá una checklist
de remediación manual. Así el re-scan de Kali baja a lo que realmente
queda, en vez de sorprenderte con hallazgos que la suite nunca iba a
cerrar.
