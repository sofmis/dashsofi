"""Interceptar y modificar peticiones al vuelo. mitmweb (UI en :8081) permite pausar/editar a mano
(filtro de intercepción, p. ej. ~u /api); rules.json aplica reglas automáticas. Registra flujos en /logs."""
import json, os, re, time
from mitmproxy import http

RULES = json.load(open(os.getenv("RULES", "/rules/rules.json")))

class Vulnerscan:
    def request(self, flow: http.HTTPFlow):
        rq = flow.request
        for r in RULES:
            m = r.get("match", {})
            if m.get("host") and m["host"] not in rq.pretty_host: continue
            if m.get("method") and rq.method != m["method"]: continue
            if m.get("path_regex") and not re.search(m["path_regex"], rq.path): continue
            for k, v in (r.get("set_headers") or {}).items(): rq.headers[k] = v
            for k, v in (r.get("set_query") or {}).items(): rq.query[k] = v
            rb = r.get("replace_body")
            if rb and rq.content: rq.set_text(rq.get_text().replace(rb["from"], rb["to"]))

    def response(self, flow: http.HTTPFlow):
        os.makedirs("/logs", exist_ok=True)
        with open("/logs/flows.jsonl", "a") as fh:
            fh.write(json.dumps({"t": time.time(), "method": flow.request.method, "url": flow.request.pretty_url,
                                 "status": flow.response.status_code}) + "\n")

addons = [Vulnerscan()]
