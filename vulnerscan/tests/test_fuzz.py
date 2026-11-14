"""Pruebas del fuzzer de detección contra una app de PRUEBA local, vulnerable a propósito, y otra
segura. Ejecutar:  python tests/test_fuzz.py  (requiere requests y fastapi/common del plugin web).

Lo que se espera:
- App vulnerable: encuentra XSS reflejado, SQLi por error, SQLi ciega (booleana), traversal
  (simulado, no toca el sistema de archivos real), plantillas, open redirect y 500 reproducible.
- App segura: CERO hallazgos (cualquier alerta aquí es un falso positivo)."""
import os
import re
import sys
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import socket

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [f"{ROOT}/plugins/web", f"{ROOT}/plugins"]
import requests  # noqa: E402
import fuzz      # noqa: E402

FAILS = []


def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), name, "" if cond else extra)
    if not cond:
        FAILS.append(name)


def make_app(vulnerable):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            if u.path == "/search":
                v = q.get("q", "")
                return self._send(200, f"<html><body>Resultados para: {v if vulnerable else escape(v)}</body></html>")
            if u.path == "/item":
                v = q.get("id", "1")
                if vulnerable and ("'" in v or '"' in v):
                    return self._send(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server")
                return self._send(200, "<html><body>Producto OK " + "x" * 300 + "</body></html>")
            if u.path == "/filter":
                v = q.get("cat", "1")
                if vulnerable and re.search(r"AND 1=2|'1'='2", v):
                    return self._send(200, "<html><body>Sin resultados</body></html>")
                return self._send(200, "<html><body>Productos: " + "x" * 600 + "</body></html>")
            if u.path == "/view":
                v = q.get("file", "")
                if vulnerable and "passwd" in v and "../" in v:
                    return self._send(200, "root:x:0:0:root:/root:/bin/bash\n", "text/plain")
                return self._send(200, "Archivo no encontrado", "text/plain")
            if u.path == "/render":
                v = q.get("t", "")
                if vulnerable:
                    v = re.sub(r"\{\{(\d+)\*(\d+)\}\}", lambda m: str(int(m[1]) * int(m[2])), v)
                return self._send(200, f"<html><body>{v if vulnerable else escape(v)}</body></html>")
            if u.path == "/go":
                dest = q.get("next", "/")
                return self._send(302, "", headers={"Location": dest if vulnerable else "/"})
            if u.path == "/calc":
                n = q.get("n", "0")
                if vulnerable and not n.isdigit():
                    return self._send(500, "Error interno", "text/plain")
                return self._send(200 if n.isdigit() else 400, "ok", "text/plain")
            return self._send(404, "no existe", "text/plain")
    return H


def serve(vulnerable):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_app(vulnerable))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{port}"


def pages_for(base):
    paths = ["/search?q=hola", "/item?id=1", "/filter?cat=1", "/view?file=a.txt",
             "/render?t=hola", "/go?next=/home", "/calc?n=5"]
    return [{"url": base + p, "forms": []} for p in paths]


def names(findings):
    return sorted({f["rule_id"] for f in findings})


def main():
    vsrv, vbase = serve(True)
    ssrv, sbase = serve(False)
    try:
        s = requests.Session()
        v = fuzz.run(s, pages_for(vbase), [], budget=600, delay=0)
        got = names(v)
        print("hallazgos en app vulnerable:", got)
        for rid in ("xss-reflected-q", "sqli-error-id", "sqli-bool-cat", "traversal-file",
                    "ssti-t", "open-redirect-next", "error500-n"):
            check(f"detecta {rid}", rid in got, str(got))
        sev = {f["rule_id"]: f["severity"] for f in v}
        check("SQLi por error es crítica", sev.get("sqli-error-id") == "critical")
        check("cada hallazgo lleva confianza y evidencia",
              all(f.get("confidence") and f.get("evidence") for f in v))

        safe = fuzz.run(requests.Session(), pages_for(sbase), [], budget=600, delay=0)
        check("app segura: cero falsos positivos", safe == [], str(names(safe)))

        class Counting(requests.Session):
            n = 0

            def get(self, *a, **k):
                Counting.n += 1
                return super().get(*a, **k)

        Counting.n = 0
        fuzz.run(Counting(), pages_for(vbase), [], budget=10, delay=0)
        # El presupuesto se comprueba entre parámetros; cada parámetro hace como máximo ~PER_PARAM peticiones.
        check("presupuesto bajo: se detiene pronto",
              Counting.n <= 10 + fuzz.PER_PARAM + 2, f"peticiones={Counting.n}")
        check("presupuesto bajo: menos peticiones que sin límite", Counting.n < 600)
    finally:
        vsrv.shutdown(); ssrv.shutdown()
    print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
