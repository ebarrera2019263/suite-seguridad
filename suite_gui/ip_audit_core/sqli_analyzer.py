"""Deteccion NO destructiva de inyeccion SQL (SQLi) en servicios web.

Enfoque: es un chequeo de tipo DAST *liviano* y seguro, al estilo de lo que
hacen escaneres de vulnerabilidades (Nessus, ZAP en modo pasivo, sqlmap en
deteccion): se envian unos pocos payloads de PRUEBA por parametros comunes de
la URL y se observa si la respuesta del servidor filtra un mensaje de error
de base de datos (deteccion 'error-based'). Un mensaje de error SQL en la
respuesta indica que la entrada del usuario llega sin sanitizar a una
consulta -> la aplicacion es candidata a SQL injection.

LIMITES ETICOS/TECNICOS (deliberados):
  - Solo peticiones GET con payloads que a lo sumo PROVOCAN UN ERROR (una
    comilla, un OR trivial). NO se extraen datos, NO se usan consultas
    apiladas (stacked queries), NO se ejecuta DROP/DELETE/UPDATE, NO se hace
    SQLi ciega basada en tiempo (que abusaria de SLEEP y podria degradar el
    servicio).
  - No reemplaza a un DAST completo (no rastrea formularios/JS ni prueba
    todos los parametros); su objetivo es marcar candidatos evidentes para
    revision manual con una herramienta especializada.

Uso permitido: solo sobre aplicaciones propias o con autorizacion escrita,
igual que el resto de la suite.
"""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

# Puertos donde tiene sentido hablar HTTP/HTTPS.
HTTP_PORTS = {80, 8080, 8000, 8888, 5000, 9090, 10000}
HTTPS_PORTS = {443, 8443, 5986}
WEB_PORTS = HTTP_PORTS | HTTPS_PORTS

# Nombres de parametro comunes: si la app usa alguno, el payload viaja por ahi.
_PROBE_PARAMS = [
    "id", "page", "user", "username", "search", "q", "query",
    "item", "cat", "category", "pid", "uid", "name", "product",
]

# Payloads benignos: buscan disparar un error de sintaxis SQL, nada mas.
_PAYLOADS = ["'", "\"", "'||'", "') OR ('1'='1"]

# Firmas de error de los motores SQL mas comunes. Si aparecen en la respuesta
# a un payload (y NO estaban en la respuesta base), es evidencia de SQLi.
_SQL_ERROR_SIGNATURES = [
    (re.compile(r"you have an error in your sql syntax", re.I), "MySQL/MariaDB"),
    (re.compile(r"warning:\s*mysqli?_", re.I), "MySQL (mysqli/PHP)"),
    (re.compile(r"unclosed quotation mark after the character string", re.I), "Microsoft SQL Server"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle"),
    (re.compile(r"pg_query\(\)|postgresql.*error|unterminated quoted string", re.I), "PostgreSQL"),
    (re.compile(r"sqlite3?\.OperationalError|sqlite_error|SQLITE_ERROR", re.I), "SQLite"),
    (re.compile(r"odbc.*drivers?.*error|microsoft ole db provider for sql server", re.I), "ODBC/OLE DB"),
    (re.compile(r"sql syntax.*error|syntax error at or near", re.I), "SQL generico"),
]


@dataclass
class SqliFindings:
    reachable: bool = False           # el servicio respondio como web
    http_server: Optional[str] = None  # header 'Server:' si lo hay
    vulnerable: bool = False
    dbms: Optional[str] = None         # motor SQL inferido por la firma de error
    param: Optional[str] = None        # parametro donde se disparo
    payload: Optional[str] = None
    evidence: Optional[str] = None     # fragmento del mensaje de error
    tested_requests: int = 0
    errors: List[str] = field(default_factory=list)


def _build_opener() -> urllib.request.OpenerDirector:
    # TLS sin verificar: en redes internas es comun el certificado autofirmado;
    # el objetivo aca es probar SQLi, no validar la cadena de confianza (eso lo
    # cubre el analizador TLS aparte).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def _fetch(opener, url: str, timeout_s: float) -> Optional[tuple]:
    """Devuelve (status, cuerpo_texto, header_server) o None si fallo la
    conexion. Un error HTTP (500/400) SI devuelve cuerpo: ahi suele venir el
    mensaje de error SQL, por eso se captura del HTTPError igualmente."""
    req = urllib.request.Request(url, headers={"User-Agent": "SuiteSeguridad-SQLiCheck/1.0"})
    try:
        resp = opener.open(req, timeout=timeout_s)
        body = resp.read(200_000).decode("utf-8", errors="replace")
        return resp.status, body, resp.headers.get("Server")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(200_000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, body, exc.headers.get("Server") if exc.headers else None
    except Exception:
        return None


def _match_sql_error(body: str, baseline: str) -> Optional[tuple]:
    """Devuelve (dbms, fragmento) si aparece una firma de error SQL que NO
    estaba en la respuesta base (para no marcar paginas que ya contienen esos
    textos por otro motivo)."""
    for pattern, dbms in _SQL_ERROR_SIGNATURES:
        m = pattern.search(body)
        if m and not pattern.search(baseline):
            start = max(0, m.start() - 40)
            fragment = body[start:m.end() + 60].strip().replace("\n", " ")
            return dbms, fragment[:200]
    return None


def analyze_sqli(ip: str, port: int, timeout_s: float = 4.0, max_requests: int = 24) -> SqliFindings:
    """Sondeo error-based no destructivo contra http(s)://ip:port/. Prueba
    payloads en parametros comunes y busca mensajes de error SQL en la
    respuesta. Corta apenas encuentra evidencia."""
    findings = SqliFindings()
    scheme = "https" if port in HTTPS_PORTS else "http"
    base = f"{scheme}://{ip}:{port}/"
    opener = _build_opener()

    # 1) Linea base: confirmar que hay un servidor web y guardar su respuesta
    #    "limpia" para comparar (evita falsos positivos).
    base_resp = _fetch(opener, base, timeout_s)
    findings.tested_requests += 1
    if base_resp is None:
        findings.errors.append(f"{scheme}://{ip}:{port}/ no respondio como servicio web")
        return findings
    _status, baseline_body, server = base_resp
    findings.reachable = True
    findings.http_server = server

    # 2) Probar cada parametro comun con cada payload, hasta encontrar
    #    evidencia o agotar el presupuesto de peticiones.
    for param in _PROBE_PARAMS:
        for payload in _PAYLOADS:
            if findings.tested_requests >= max_requests:
                return findings
            qs = urllib.parse.urlencode({param: payload})
            url = f"{base}?{qs}"
            resp = _fetch(opener, url, timeout_s)
            findings.tested_requests += 1
            if resp is None:
                continue
            _s, body, _srv = resp
            hit = _match_sql_error(body, baseline_body)
            if hit:
                findings.vulnerable = True
                findings.dbms, findings.evidence = hit
                findings.param = param
                findings.payload = payload
                return findings
    return findings
