"""Interceptación y modificación de peticiones al vuelo (mitmproxy).

- mitmweb (UI en :8081) permite pausar, inspeccionar y editar peticiones a mano (filtro, p. ej. ~u /api).
- rules.json aplica reglas automáticas: cambiar/quitar cabeceras, cambiar parámetros, reemplazar cuerpo
  o BLOQUEAR el tráfico (block, responde 403). Solo actúa sobre hosts de ALLOWED_TARGETS.
- Cada respuesta se registra en /logs/flows.jsonl.
"""
import json
import os
import time

from mitmproxy import http

import rules as R

ALLOWED = [x.strip().lower() for x in os.getenv("ALLOWED_TARGETS", "").split(",") if x.strip()]
RULES_PATH = os.getenv("RULES", "/rules/rules.json")


def _load():
    try:
        with open(RULES_PATH) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[vulnerscan] no se pudieron leer las reglas: {e}")
        return []
    valid, notes = R.load_rules(data, ALLOWED)
    for n in notes:
        print(f"[vulnerscan] {n}")
    print(f"[vulnerscan] {len(valid)} regla(s) activa(s); alcance: {ALLOWED or 'vacío (nada se modifica)'}")
    return valid


RULES = _load()


class Vulnerscan:
    def request(self, flow: http.HTTPFlow):
        rq = flow.request
        host = rq.pretty_host
        for r in RULES:
            if not R.match_rule(r, host, rq.method, rq.path):
                continue
            if r.get("block"):
                flow.response = http.Response.make(403, b"Bloqueado por una regla de vulnerscan\n",
                                                   {"Content-Type": "text/plain"})
                return
            for k in r.get("remove_headers") or []:
                rq.headers.pop(k, None)
            for k, v in (r.get("set_headers") or {}).items():
                rq.headers[k] = v
            for k, v in (r.get("set_query") or {}).items():
                rq.query[k] = v
            rb = r.get("replace_body")
            if rb and rq.content:
                rq.set_text(rq.get_text().replace(rb["from"], rb["to"]))

    def response(self, flow: http.HTTPFlow):
        os.makedirs("/logs", exist_ok=True)
        with open("/logs/flows.jsonl", "a") as fh:
            fh.write(json.dumps({"t": time.time(), "method": flow.request.method, "url": flow.request.pretty_url,
                                 "status": flow.response.status_code}) + "\n")


addons = [Vulnerscan()]
