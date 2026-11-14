"""Prueba del addon de mitmproxy con flujos reales (mitmproxy.test.tflow). Ejecutar:
    python tests/test_proxy_addon.py   (requiere mitmproxy)"""
import json, os, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = [
    {"name": "bloquear listproducts", "match": {"host": "testphp.vulnweb.com", "method": "GET", "path_regex": "^/listproducts"},
     "block": True},
    {"name": "cabecera de prueba", "match": {"host": "localhost", "method": "GET"},
     "set_headers": {"X-Vulnerscan": "1"}, "remove_headers": ["Cookie"]},
    {"name": "fuera de alcance", "match": {"host": "otro-sitio.com"}, "set_headers": {"X-Bad": "1"}},
]
path = os.path.join(tempfile.mkdtemp(), "rules.json")
with open(path, "w") as fh:
    json.dump(RULES, fh)
os.environ["RULES"] = path
os.environ["ALLOWED_TARGETS"] = "testphp.vulnweb.com,localhost"
sys.path[:0] = [f"{ROOT}/plugins/proxy"]

from mitmproxy.test import tflow  # noqa: E402
import vulnerscan_addon as addon  # noqa: E402

FAILS = []


def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), name, "" if cond else extra)
    if not cond:
        FAILS.append(name)


def flow(host, path, method="GET", headers=None):
    f = tflow.tflow()
    f.request.method = method
    f.request.host = host
    f.request.port = 80
    f.request.scheme = "http"
    f.request.path = path
    f.request.headers.clear()
    f.request.headers["Host"] = host
    for k, v in (headers or {}).items():
        f.request.headers[k] = v
    return f


a = addon.Vulnerscan()
check("reglas válidas cargadas (fuera de alcance excluida)", len(addon.RULES) == 2, str([r.get("name") for r in addon.RULES]))

f = flow("testphp.vulnweb.com", "/listproducts?cat=1")
a.request(f)
check("regla block responde 403 sin enviar", f.response is not None and f.response.status_code == 403)

f = flow("testphp.vulnweb.com", "/otra")
a.request(f)
check("sin regla que coincida: nada cambia", f.response is None)

f = flow("localhost", "/app", headers={"Cookie": "sid=abc"})
a.request(f)
check("set_headers aplicado en alcance", f.request.headers.get("X-Vulnerscan") == "1")
check("remove_headers quita la cookie", "Cookie" not in f.request.headers)

f = flow("otro-sitio.com", "/x")
a.request(f)
check("regla fuera de alcance NO modifica el tráfico", "X-Bad" not in f.request.headers and f.response is None)

print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
sys.exit(1 if FAILS else 0)
