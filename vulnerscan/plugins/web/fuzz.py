"""Fuzzing guiado por tipo: muta cada parámetro según su tipo inferido. Payloads de DETECCIÓN
(canarios, errores de sintaxis), nunca destructivos. POST solo si options.fuzz_post=true."""
import random, re, string, time
from urllib.parse import parse_qsl, urlparse
import requests
from common import finding

SQL_ERR = re.compile(r"(SQL syntax.*MySQL|mysqli?_|PostgreSQL.*ERROR|pg_query\(\)|ORA-\d{5}|sqlite3?\.OperationalError|"
                     r"Unclosed quotation mark|SQLSTATE\[|System\.Data\.SqlClient)", re.I)
REDIR_NAMES = re.compile(r"(url|next|redirect|return|dest|goto)", re.I)

def infer(v):
    if v.lstrip("-").isdigit(): return "int"
    if re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.]+", v): return "email"
    if re.fullmatch(r"[0-9a-f-]{32,36}", v, re.I): return "uuid"
    return "str"

def type_mutations(v):
    return {"int": ["-1", "0", "2147483648", "9" * 25], "email": ["a@b", "@", "a" * 300 + "@x.io"],
            "uuid": ["00000000-0000-0000-0000-000000000000", "x"], "str": ["", "A" * 4096]}[infer(v)]

def targets(pages, extra_urls, allow_post):
    seen, out = set(), []
    def add(method, url, params):
        params = dict(params)
        k = (method, urlparse(url).path, tuple(sorted(map(str, params))))
        if params and k not in seen: seen.add(k); out.append((method, url.split("?")[0], params))
    for p in pages:
        add("GET", p["url"], parse_qsl(urlparse(p["url"]).query))
        for f in p["forms"]:
            if f["method"] == "get" or allow_post: add(f["method"].upper(), f["action"], f["inputs"].items())
    for u in extra_urls: add("GET", u, parse_qsl(urlparse(u).query))
    return out

def run(s, pages, extra_urls, budget=300, delay=0.1, allow_post=False):
    out, used = [], 0
    def send(m, url, params):
        nonlocal used
        used += 1; time.sleep(delay)
        try:
            return (s.get(url, params=params, timeout=10, allow_redirects=False) if m == "GET"
                    else s.post(url, data=params, timeout=10, allow_redirects=False))
        except requests.RequestException: return None
    for method, url, params in targets(pages, extra_urls, allow_post):
        for name, val in list(params.items()):
            if used >= budget: return out
            if not name: continue
            val = val or ""
            def mut(v): return {**params, name: v}
            base = send(method, url, params)
            if base is None: continue
            bt = base.text
            tag = "".join(random.choices(string.ascii_lowercase, k=8))
            r = send(method, url, mut(f'vs{tag}"\'<{tag}>'))
            if r is not None and "html" in r.headers.get("Content-Type", "") and f"<{tag}>" in r.text:
                out.append(finding("web", f"xss-reflected-{name}", f"Posible XSS reflejado en '{name}'", "high", url, cwe="CWE-79",
                    confidence=0.7, evidence=f"Parámetro {name} se refleja con '<' sin codificar", remediation="Codificar salida según contexto + CSP."))
            for q in ("'", '"', "\\"):
                r = send(method, url, mut(val + q))
                if r is not None and SQL_ERR.search(r.text) and not SQL_ERR.search(bt):
                    out.append(finding("web", f"sqli-error-{name}", f"Posible inyección SQL en '{name}'", "critical", url, cwe="CWE-89",
                        confidence=0.75, evidence=f"Error de BD al enviar {q!r}", remediation="Consultas parametrizadas."))
                    break
            r = send(method, url, mut("{{1337*7}}"))
            if r is not None and "9359" in r.text and "9359" not in bt:
                out.append(finding("web", f"ssti-{name}", f"Posible inyección de plantillas en '{name}'", "high", url, cwe="CWE-1336",
                    confidence=0.7, evidence="Expresión aritmética evaluada en servidor"))
            if REDIR_NAMES.search(name):
                dest = "https://vulnerscan-redirect-test.invalid/"
                r = send(method, url, mut(dest))
                if r is not None and r.headers.get("Location", "").startswith(dest):
                    out.append(finding("web", f"open-redirect-{name}", f"Redirección abierta en '{name}'", "medium", url, cwe="CWE-601", confidence=0.85))
            for mv in type_mutations(val):
                r = send(method, url, mut(mv))
                if r is not None and r.status_code >= 500 > base.status_code:
                    out.append(finding("web", f"error500-{name}", f"Entrada anómala provoca error 500 en '{name}'", "low", url, cwe="CWE-209",
                        confidence=0.5, evidence=f"Mutación de tipo {infer(val)}"))
                    break
    return out
