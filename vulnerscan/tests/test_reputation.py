"""Pruebas offline de reputación de URLs. Ejecutar:  python tests/test_reputation.py

Usa servidores falsos para VirusTotal y Google Safe Browsing (forma de las respuestas
de sus APIs, no son las APIs reales). Además comprueba que el sitio analizado NO recibe
ninguna visita: esa es la garantía del análisis pasivo."""
import asyncio
import base64
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [f"{ROOT}/orchestrator"]
from app import reputation as rep  # noqa: E402

FAILS = []
TARGET_HITS = {"n": 0}      # visitas recibidas por el "sitio analizado"
SEEN = {"vt_key": None, "gsb_key": None}


def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), name, "" if cond else extra)
    if not cond:
        FAILS.append(name)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Target(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        TARGET_HITS["n"] += 1
        self.send_response(200); self.end_headers(); self.wfile.write(b"hola")


class Api(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):   # VirusTotal: /api/v3/urls/{id}
        uid = urlparse(self.path).path.rsplit("/", 1)[-1]
        SEEN["vt_key"] = self.headers.get("x-apikey")
        url = base64.urlsafe_b64decode(uid + "=" * (-len(uid) % 4)).decode()
        if "malo" in url:
            return self._send(200, {"data": {"attributes": {"last_analysis_stats":
                {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 20}}}})
        if "limpio" in url:
            return self._send(200, {"data": {"attributes": {"last_analysis_stats":
                {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 10}}}})
        return self._send(404, {"error": {"code": "NotFoundError"}})
    def do_POST(self):  # Google Safe Browsing: /v4/threatMatches:find?key=
        q = parse_qs(urlparse(self.path).query)
        SEEN["gsb_key"] = (q.get("key") or [None])[0]
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        url = body["threatInfo"]["threatEntries"][0]["url"]
        if SEEN["gsb_key"] != "k2":
            return self._send(403, {"error": {"message": "API key not valid"}})
        if "malo" in url:
            return self._send(200, {"matches": [{"threatType": "MALWARE", "url": url}]})
        return self._send(200, {})


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", free_port()), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def run(coro):
    return asyncio.run(coro)


def test_validation():
    check("acepta URL sin esquema y usa https por defecto", rep.validate_url("ejemplo.com") == "https://ejemplo.com")
    check("respeta http si se escribe", rep.validate_url("http://ejemplo.com") == "http://ejemplo.com")
    check("acepta https", rep.validate_url("https://ejemplo.com/a?b=1") == "https://ejemplo.com/a?b=1")
    for bad, name in [("", "vacía"), ("http://", "sin host"), ("ftp://x.com", "esquema ftp"),
                      ("http://x.com/a b", "con espacios"), ("http://" + "a" * 2100, "demasiado larga")]:
        try:
            rep.validate_url(bad)
            check(f"rechaza URL {name}", False)
        except ValueError:
            check(f"rechaza URL {name}", True)


def test_heuristics():
    check("IP como host", any("IP" in r for r in rep.heuristics("http://192.168.0.1/login")))
    check("punycode", any("Unicode" in r for r in rep.heuristics("http://xn--pypal-4ve.com")))
    check("arroba", any("@" in r for r in rep.heuristics("http://banco.com@evil.com")))
    check("TLD de alto abuso", any(".zip" in r for r in rep.heuristics("http://x.evil.zip")))
    check("URL limpia sin señales", rep.heuristics("https://www.wikipedia.org") == [])


def test_verdict_rules():
    vt = lambda mal, sus=0: {"source": "VirusTotal", "status": "ok", "malicious": mal, "suspicious": sus}
    gsb = lambda n: {"source": "Google Safe Browsing", "status": "ok", "matches": n}
    off = {"source": "VirusTotal", "status": "sin_clave"}
    check("maligna por GSB", rep.verdict([vt(0), gsb(1)], [])[0] == "maligna")
    check("maligna por 3+ motores", rep.verdict([vt(3), gsb(0)], [])[0] == "maligna")
    check("sospechosa con 1 motor", rep.verdict([vt(1), gsb(0)], [])[0] == "sospechosa")
    check("sospechosa por señales", rep.verdict([off, gsb(0)], ["IP", "@"])[0] == "sospechosa")
    check("sin detecciones", rep.verdict([vt(0), gsb(0)], [])[0] == "sin detecciones")
    check("sin datos sin claves", rep.verdict([off], [])[0] == "sin datos")


def test_end_to_end():
    tsrv, tport = serve(Target)
    asrv, aport = serve(Api)
    rep.VT_BASE = f"http://127.0.0.1:{aport}/api/v3"
    rep.GSB_BASE = f"http://127.0.0.1:{aport}/v4"
    target = f"http://127.0.0.1:{tport}/"          # sitio "analizado": no debe recibir nada
    try:
        r = run(rep.analyze(f"http://malo.example.com/x", vt_key="k1", gsb_key="k2"))
        check("e2e: URL maligna", r["verdict"] == "maligna" and r["confidence"] == "alta", str(r["verdict"]))
        check("e2e: clave de VT enviada", SEEN["vt_key"] == "k1")
        check("e2e: clave de GSB enviada", SEEN["gsb_key"] == "k2")
        r = run(rep.analyze("https://limpio.example.org", vt_key="k1", gsb_key="k2"))
        check("e2e: URL limpia", r["verdict"] == "sin detecciones", r["verdict"])
        r = run(rep.analyze(target, vt_key="k1", gsb_key="k2"))
        check("e2e: sin informe previo queda como sin_informe", r["sources"][0]["status"] == "sin_informe")
        r = run(rep.analyze("https://limpio.example.org", vt_key="", gsb_key=""))
        check("sin claves: sin datos, nunca veredicto inventado", r["verdict"] == "sin datos"
              and all(s["status"] == "sin_clave" for s in r["sources"]))
        r = run(rep.analyze("https://limpio.example.org", vt_key="mala", gsb_key="mala"))
        check("clave rechazada se reporta como error", r["sources"][1]["status"] == "error"
              and "rechazada" in r["sources"][1]["detail"], str(r["sources"][1]))
        check("el sitio analizado NO recibió visitas", TARGET_HITS["n"] == 0, f"visitas={TARGET_HITS['n']}")
    finally:
        tsrv.shutdown(); asrv.shutdown()


def test_network_failure():
    rep.VT_BASE = "http://127.0.0.1:1/api/v3"          # puerto cerrado
    rep.GSB_BASE = "http://127.0.0.1:1/v4"
    r = run(rep.analyze("https://ejemplo.com", vt_key="k1", gsb_key="k2"))
    check("sin conexión: error explícito, sin veredicto", r["verdict"] == "sin datos"
          and all(s["status"] == "error" for s in r["sources"]))


if __name__ == "__main__":
    test_validation(); test_heuristics(); test_verdict_rules(); test_end_to_end(); test_network_failure()
    print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
    sys.exit(1 if FAILS else 0)
