"""Motor de checks declarativos (YAML). Sin código arbitrario: solo peticiones seguras + matchers."""
import glob, re, socket
from urllib.parse import urlparse
import requests, yaml
from fastapi import FastAPI
from common import finding

app = FastAPI()
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

def load():
    for f in glob.glob("/checks/*.y*ml"):
        try:
            d = yaml.safe_load(open(f))
            if isinstance(d, dict) and d.get("protocol") in ("http", "tcp") and d.get("id"): yield d
        except Exception: continue

def matcher_ok(m, status, headers, body):
    part = {"body": body, "header": "\n".join(f"{k}: {v}" for k, v in headers.items()), "banner": body}.get(m.get("part", "body"), body)
    t = m.get("type")
    if t == "status": return status in m.get("status", [])
    if t == "word": return all(w in part for w in m.get("words", []))
    if t == "regex": return all(re.search(r, part) for r in m.get("regex", []))
    return False

def evaluate(matchers, cond, *a):
    res = [matcher_ok(m, *a) for m in matchers]
    return bool(res) and (all(res) if cond == "and" else any(res))

def run_http(chk, base, s):
    for rq in chk.get("requests", []):
        m = str(rq.get("method", "GET")).upper()
        if m not in SAFE_METHODS or not str(rq.get("path", "/")).startswith("/"): continue
        try: r = s.request(m, base.rstrip("/") + rq["path"], headers=rq.get("headers"), timeout=8, allow_redirects=False)
        except requests.RequestException: continue
        if evaluate(rq.get("matchers", []), rq.get("matchers-condition", "and"), r.status_code, r.headers, r.text[:200000]):
            return f"{m} {rq['path']} → {r.status_code}"

def run_tcp(chk, host):
    try:
        with socket.create_connection((host, int(chk["port"])), timeout=6) as c:
            if chk.get("send"): c.sendall(str(chk["send"]).encode())
            c.settimeout(4); banner = c.recv(4096).decode(errors="replace")
    except Exception: return None
    return banner[:200] if evaluate(chk.get("matchers", []), chk.get("matchers-condition", "and"), 0, {}, banner) else None

@app.post("/scan")
def scan(req: dict):
    target = req["target"]
    u = urlparse(target if "://" in target else "//" + target)
    host, base = u.hostname, (target if "://" in target else f"https://{target}")
    s, out = requests.Session(), []
    for chk in load():
        ev = run_http(chk, base, s) if chk["protocol"] == "http" else run_tcp(chk, host)
        if ev:
            out.append(finding("custom", chk["id"], chk.get("name", chk["id"]), chk.get("severity", "info"), base, cwe=chk.get("cwe"),
                               evidence=ev, remediation=chk.get("remediation", ""), confidence=float(chk.get("confidence", 0.85))))
    return {"findings": out, "meta": {}}
