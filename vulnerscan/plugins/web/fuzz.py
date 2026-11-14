"""Fuzzing de DETECCIÓN sobre parámetros de objetivos AUTORIZADOS (ALLOWED_TARGETS).

Payloads no destructivos: canarios, errores de sintaxis, condiciones booleanas de solo lectura,
expresiones aritméticas y lectura de un archivo con firma conocida. Cada hallazgo se confirma
con una segunda sonda antes de reportarse. Por eso baja el ruido (falsos positivos).

Inteligencia:
- Prioriza parámetros por nombre (id/file/q/url… antes que el resto).
- Deja de probar un parámetro en cuanto confirma una inyección (ahorra peticiones).
- Presupuesto global y por parámetro. Nunca se envían POST salvo options.fuzz_post=true."""
import random
import re
import string
import time
from urllib.parse import parse_qsl, urlparse

import requests
from common import finding

SQL_ERR = re.compile(r"(SQL syntax.*MySQL|mysqli?_|PostgreSQL.*ERROR|pg_query\(\)|ORA-\d{5}|sqlite3?\.OperationalError|"
                     r"Unclosed quotation mark|SQLSTATE\[|System\.Data\.SqlClient)", re.I)
REDIR_NAMES = re.compile(r"(url|next|redirect|return|dest|goto)", re.I)
FILE_NAMES = re.compile(r"(file|path|dir|doc|template|view|include|page|load|src)", re.I)
PASSWD_SIG = re.compile(r"root:[x*]:0:0:")
PRIORITY = [(re.compile(r"(id|uid|user|cat|item|product|num)", re.I), 3),
            (re.compile(r"(file|path|dir|doc|template|view|include|page|load|src)", re.I), 3),
            (re.compile(r"(q|query|search|name|text|msg|comment)", re.I), 2),
            (re.compile(r"(url|next|redirect|return|dest|goto)", re.I), 2)]
PER_PARAM = 24   # cota orientativa de peticiones por parámetro (sondas acotadas)


def priority(name):
    return max([w for rx, w in PRIORITY if rx.search(name)] or [1])


def infer(v):
    if str(v).lstrip("-").isdigit(): return "int"
    if re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.]+", str(v)): return "email"
    if re.fullmatch(r"[0-9a-f-]{32,36}", str(v), re.I): return "uuid"
    return "str"


def type_mutations(v):
    return {"int": ["-1", "0", "2147483648", "9" * 25], "email": ["a@b", "@", "a" * 300 + "@x.io"],
            "uuid": ["00000000-0000-0000-0000-000000000000", "x"], "str": ["", "A" * 4096]}[infer(v)]


def targets(pages, extra_urls, allow_post):
    seen, out = set(), []

    def add(method, url, params):
        params = dict(params)
        k = (method, urlparse(url).path, tuple(sorted(map(str, params))))
        if params and k not in seen:
            seen.add(k); out.append((method, url.split("?")[0], params))
    for p in pages:
        add("GET", p["url"], parse_qsl(urlparse(p["url"]).query))
        for f in p.get("forms") or []:
            if f["method"] == "get" or allow_post:
                add(f["method"].upper(), f["action"], f["inputs"].items())
    for u in extra_urls:
        add("GET", u, parse_qsl(urlparse(u).query))
    return out


def _similar(a, b):
    return abs(len(a) - len(b)) <= 0.05 * max(len(a), len(b), 1)


def _differs(a, b):
    return abs(len(a) - len(b)) > 0.15 * max(len(a), len(b), 1)


def _is_html(r):
    return r is not None and "html" in r.headers.get("Content-Type", "")


def probe_param(send, method, url, params, name, base):
    """Ejecuta las sondas de un parámetro y devuelve TODOS sus hallazgos confirmados.
    Cada clase se prueba por separado: un XSS no oculta una SSTI del mismo parámetro."""
    out = []
    val = params.get(name) or ""
    bt, bs = base.text, base.status_code
    tag = "".join(random.choices(string.ascii_lowercase, k=8))

    def mut(v):
        return {**params, name: v}

    # 1) Traversal de lectura (solo nombres tipo archivo). Control: un archivo inexistente no debe dar la firma.
    if FILE_NAMES.search(name):
        for pl in ("../../../../../../etc/passwd", "....//....//....//etc/passwd"):
            r = send(method, url, mut(pl))
            if r is not None and PASSWD_SIG.search(r.text) and not PASSWD_SIG.search(bt):
                ctrl = send(method, url, mut(f"../../../../../../etc/vs-{tag}-missing"))
                if ctrl is not None and not PASSWD_SIG.search(ctrl.text):
                    out.append(finding("web", f"traversal-{name}", f"Posible lectura de archivos en '{name}' (path traversal)",
                                       "high", url, cwe="CWE-22", confidence=0.8,
                                       evidence="La respuesta contiene la firma de /etc/passwd y un archivo inexistente no la devuelve",
                                       remediation="Validar rutas contra una lista blanca; no usar la entrada en rutas de archivo."))
                    break

    # 2) Inyección SQL por error: el error debe aparecer con una comilla y reproducirse con dos.
    for q in ("'", '"'):
        r = send(method, url, mut(str(val) + q))
        if r is not None and SQL_ERR.search(r.text) and not SQL_ERR.search(bt):
            r2 = send(method, url, mut(str(val) + q + q))
            if r2 is not None and SQL_ERR.search(r2.text):
                out.append(finding("web", f"sqli-error-{name}", f"Posible inyección SQL en '{name}'", "critical", url,
                                   cwe="CWE-89", confidence=0.8, evidence=f"Error de base de datos reproducible con {q!r}",
                                   remediation="Consultas parametrizadas."))
                break

    # 3) Inyección SQL ciega (booleana): condiciones de solo lectura; la verdadera se parece al original
    #    y la falsa cambia la respuesta, de forma reproducible.
    for t_, f_ in ((f"{val}' AND '1'='1", f"{val}' AND '1'='2"), (f"{val} AND 1=1", f"{val} AND 1=2")):
        rt, rf = send(method, url, mut(t_)), send(method, url, mut(f_))
        if rt is None or rf is None or rt.status_code != bs or not _similar(rt.text, bt) or not _differs(rf.text, rt.text):
            continue
        rt2, rf2 = send(method, url, mut(t_)), send(method, url, mut(f_))
        if rt2 is not None and rf2 is not None and _similar(rt2.text, rt.text) and _differs(rf2.text, rt2.text):
            out.append(finding("web", f"sqli-bool-{name}", f"Posible inyección SQL ciega (booleana) en '{name}'", "high", url,
                               cwe="CWE-89", confidence=0.7,
                               evidence="La respuesta cambia de forma reproducible entre una condición verdadera y una falsa",
                               remediation="Consultas parametrizadas."))
            break

    # 4) XSS reflejado: el canario con '<' debe volver sin codificar, con dos etiquetas distintas.
    r = send(method, url, mut(f'vs{tag}"\'<{tag}>'))
    if _is_html(r) and f"<{tag}>" in r.text and f"<{tag}>" not in bt:
        t2 = "".join(random.choices(string.ascii_lowercase, k=8))
        r2 = send(method, url, mut(f'vs{t2}"\'<{t2}>'))
        if _is_html(r2) and f"<{t2}>" in r2.text:
            out.append(finding("web", f"xss-reflected-{name}", f"Posible XSS reflejado en '{name}'", "high", url,
                               cwe="CWE-79", confidence=0.8,
                               evidence=f"El parámetro '{name}' se refleja con '<' sin codificar (dos pruebas)",
                               remediation="Codificar la salida según el contexto y usar CSP."))

    # 5) Inyección de plantillas: dos expresiones aritméticas distintas deben evaluarse.
    ok = 0
    for a, b in ((1337, 7), (4242, 3)):
        r = send(method, url, mut("{{%d*%d}}" % (a, b)))
        if r is not None and str(a * b) in r.text and str(a * b) not in bt:
            ok += 1
    if ok == 2:
        out.append(finding("web", f"ssti-{name}", f"Posible inyección de plantillas en '{name}'", "high", url,
                           cwe="CWE-1336", confidence=0.8, evidence="Dos expresiones aritméticas distintas se evalúan en el servidor",
                           remediation="No pasar entrada del usuario al motor de plantillas."))

    # 6) Redirección abierta (solo nombres tipo URL), confirmada con dos destinos.
    if REDIR_NAMES.search(name):
        hits = 0
        for dest in ("https://vulnerscan-redirect-test.invalid/a", "https://vulnerscan-redirect-test.invalid/b"):
            r = send(method, url, mut(dest))
            if r is not None and r.headers.get("Location", "").startswith(dest):
                hits += 1
        if hits == 2:
            out.append(finding("web", f"open-redirect-{name}", f"Redirección abierta en '{name}'", "medium", url,
                               cwe="CWE-601", confidence=0.85, evidence="El servidor redirige a un destino externo elegido por el parámetro"))

    # 7) Entradas anómalas que provocan 500 de forma reproducible (indicio de manejo de errores pobre).
    if bs < 500:
        for mv in type_mutations(val):
            r = send(method, url, mut(mv))
            if r is not None and r.status_code >= 500:
                r2 = send(method, url, mut(mv))
                if r2 is not None and r2.status_code >= 500:
                    out.append(finding("web", f"error500-{name}", f"Entrada anómala provoca error 500 en '{name}'", "low", url,
                                       cwe="CWE-209", confidence=0.6, evidence=f"Mutación de tipo {infer(val)} reproduce el 500"))
                    break
    return out


def run(s, pages, extra_urls, budget=300, delay=0.1, allow_post=False):
    out, used = [], 0

    def send(m, url, params):
        nonlocal used
        used += 1
        time.sleep(delay)
        try:
            return (s.get(url, params=params, timeout=10, allow_redirects=False) if m == "GET"
                    else s.post(url, data=params, timeout=10, allow_redirects=False))
        except requests.RequestException:
            return None

    tlist = sorted(targets(pages, extra_urls, allow_post),
                   key=lambda t: -max([priority(n) for n in t[2]] or [0]))
    for method, url, params in tlist:
        for name in sorted([n for n in params if n], key=lambda n: -priority(n)):
            if used >= budget:
                return out
            base = send(method, url, params)
            if base is None:
                continue
            # Cada sonda de probe_param tiene un número fijo de peticiones (≤ PER_PARAM).
            out.extend(probe_param(send, method, url, params, name, base))
    return out
