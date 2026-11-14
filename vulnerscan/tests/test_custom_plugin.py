"""Pruebas del plugin de checks declarativos (custom). Ejecutar:  python tests/test_custom_plugin.py
Usa un servidor local de prueba y un directorio temporal de checks (CHECKS_DIR)."""
import os
import sys
import tempfile
import threading
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS = tempfile.mkdtemp()
os.environ["CHECKS_DIR"] = CHECKS
sys.path[:0] = [f"{ROOT}/plugins/custom", f"{ROOT}/plugins"]

import app as custom  # noqa: E402

FAILS, HITS = [], {"post": 0}


def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), name, "" if cond else extra)
    if not cond:
        FAILS.append(name)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _ok(self):
        body = b"Resultados para: hola"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._ok()

    def do_POST(self):
        HITS["post"] += 1
        self._ok()


WRITE = {
    "marcador-busqueda.yaml": """
id: marcador-busqueda
name: Página de búsqueda expuesta
protocol: http
severity: low
requests:
  - method: GET
    path: /search?q=prueba
    matchers:
      - {type: word, part: body, words: ["Resultados para"]}
""",
    "post-nunca.yaml": """
id: post-nunca
name: Intento de POST (no debe ejecutarse)
protocol: http
severity: high
requests:
  - method: POST
    path: /search
    matchers:
      - {type: status, status: [200]}
""",
    "tcp-cerrado.yaml": """
id: tcp-cerrado
name: Puerto cerrado
protocol: tcp
port: 1
severity: low
matchers:
  - {type: word, part: banner, words: ["SSH"]}
""",
    "roto.yaml": "id: [esto no es un check",
}


def main():
    for name, body in WRITE.items():
        with open(os.path.join(CHECKS, name), "w") as fh:
            fh.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    origin = f"http://127.0.0.1:{port}"
    try:
        out = custom.scan({"target": origin + "/search?q=hola", "options": {}})["findings"]
        ids = {f["rule_id"] for f in out}
        check("ruta con query en el objetivo: la comprobación encuentra el marcador",
              "marcador-busqueda" in ids, str(ids))
        check("POST nunca se ejecuta", "post-nunca" not in ids and HITS["post"] == 0, f"post={HITS['post']}")
        check("YAML roto se omite sin romper el escaneo", "roto" not in str(ids))
        check("puerto cerrado no produce hallazgo", "tcp-cerrado" not in ids)
        f = next((x for x in out if x["rule_id"] == "marcador-busqueda"), None)
        check("activo = origen (sin la ruta del objetivo)", f is not None and f["asset"] == origin, str(f and f["asset"]))
        check("hallazgo con evidencia y severidad", f is not None and f["evidence"].startswith("GET") and f["severity"] == "low")
        # Un check cuyo texto no existe en la respuesta no debe producir hallazgo.
        with open(os.path.join(CHECKS, "sin-coincidencia.yaml"), "w") as fh:
            fh.write("""
id: sin-coincidencia
name: Texto que no existe
protocol: http
severity: low
requests:
  - method: GET
    path: /search?q=prueba
    matchers:
      - {type: word, part: body, words: ["TEXTO-QUE-NO-EXISTE-XYZ"]}
""")
        out2 = custom.scan({"target": origin, "options": {}})["findings"]
        check("sin coincidencia: sin hallazgo", not any(x["rule_id"] == "sin-coincidencia" for x in out2))
    finally:
        srv.shutdown()
    print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
