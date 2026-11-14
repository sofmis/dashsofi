"""Pruebas del renderizado SPA (Chromium) y de la comprobación de APIs. Ejecutar:
    CHROMIUM_PATH=/ruta/a/chrome python tests/test_web_render.py
Requiere playwright y un Chromium. Si no está disponible, la prueba se marca como SKIP.

Usa una mini SPA LOCAL (de prueba). Comprueba que: el JS genera enlaces que se visitan,
las llamadas GET de la página se ven como endpoints, las POST se bloquean (y nunca llegan
al servidor), los terceros se bloquean y los 200 con 'unauthorized' no son hallazgos."""
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [f"{ROOT}/plugins/web", f"{ROOT}/plugins"]

FAILS, HITS = [], {"post": 0}
PAGE = """<!doctype html><html><head><title>%s</title></head><body><div id=app></div>
<script>
setTimeout(function () {
  var nav = document.getElementById('app');
  nav.innerHTML = '<a href="/productos">Productos</a> <a href="/contacto">Contacto</a>';
}, 300);
fetch('/api/items');                                  // GET de la página (debe verse como endpoint)
fetch('/api/logout', {method: 'POST', body: '{}'});   // POST: debe bloquearse
</script>
<script src="http://tercero.invalid/analytics.js"></script>
</body></html>"""
ROUTES = {
    "/": "Inicio",
    "/productos": "Productos",
    "/productos/1": "Producto 1",
    "/contacto": "Contacto",
}


def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), name, "" if cond else extra)
    if not cond:
        FAILS.append(name)


class Spa(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ROUTES:
            if path == "/":
                return self._send(200, "text/html; charset=utf-8", PAGE % ROUTES[path])
            extra = "<a href='/productos/1'>Producto 1</a>" if path == "/productos" else ""
            return self._send(200, "text/html; charset=utf-8",
                              f"<html><head><title>{ROUTES[path]}</title></head>"
                              f"<body><a href='/'>inicio</a>{extra}<p>{ROUTES[path]}</p></body></html>")
        if path == "/api/items":
            return self._send(200, "application/json", json.dumps([{"id": 1, "name": "Taza"}]))
        if path == "/api/login-required":
            return self._send(200, "application/json", json.dumps({"error": "unauthorized"}))
        return self._send(404, "text/plain", "no existe")

    def do_POST(self):
        HITS["post"] += 1
        self._send(200, "application/json", "{}")


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def main():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError:
        print("SKIP playwright no instalado"); return 0
    import render, apiprobe, requests
    port = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Spa)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/"
    try:
        r = render.render_site(base, max_routes=30, timeout_ms=15000)
        urls = {x["url"].replace(base[:-1], "") for x in r["routes"]}
        check("JS genera enlaces y se visitan (productos)", "/productos" in urls, str(urls))
        check("JS genera enlaces y se visitan (contacto)", "/contacto" in urls, str(urls))
        check("rutas anidadas descubiertas (/productos/1)", "/productos/1" in urls, str(urls))
        check("llamada GET de la página vista como endpoint", any(u.endswith("/api/items") for u in r["api_urls"]),
              str(r["api_urls"]))
        check("POST bloqueada en el navegador", any(b.startswith("POST ") for b in r["blocked"]), str(r["blocked"]))
        check("POST nunca llegó al servidor", HITS["post"] == 0, f"hits={HITS['post']}")
        check("tercero bloqueado y registrado por host", any("tercero.invalid" in b for b in r["blocked"]),
              str(r["blocked"]))
        check("título y estado por ruta", any(x.get("title") == "Productos" and x.get("status") == 200
                                              for x in r["routes"]), str(r["routes"][:2]))
        small = render.render_site(base, max_routes=2, timeout_ms=15000)
        check("presupuesto de rutas respetado", len(small["routes"]) <= 2, str(len(small["routes"])))
        s = requests.Session()
        f = apiprobe.probe(s, [base + "api/items", base + "api/login-required"], "127.0.0.1")
        ids = [x["rule_id"] for x in f]
        check("API pública sin autenticación: hallazgo", any("api/items" in i for i in ids), str(ids))
        check("200 con 'unauthorized' NO es hallazgo", not any("login-required" in i for i in ids), str(ids))
    finally:
        srv.shutdown()
    print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
