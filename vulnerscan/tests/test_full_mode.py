"""Modo completo: aislamiento de escaneos entre usuarios y permisos. Requiere PostgreSQL de PRUEBA.
    DATABASE_URL=postgresql://vs:vs@127.0.0.1:5433/vs python tests/test_full_mode.py"""
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.getenv("DATABASE_URL"):
    print("SKIP: define DATABASE_URL"); sys.exit(0)
os.environ.update({"MODE": "full", "ENABLE_ACTIVE_SCANS": "true", "API_KEY": "clave-admin-prueba",
                   "MAIL_DEV": "1", "PUBLIC_URL": "http://testserver", "ALLOWED_TARGETS": "localhost,127.0.0.1",
                   "PLUGIN_WEB": "http://127.0.0.1:9", "PLUGIN_CUSTOM": "http://127.0.0.1:9"})
sys.path[:0] = [f"{ROOT}/orchestrator"]
from fastapi.testclient import TestClient  # noqa: E402
from app import main, mailer  # noqa: E402

FAILS = []
def check(n, c, x=""):
    print(("PASS" if c else "FAIL"), n, "" if c else x)
    if not c: FAILS.append(n)

STRONG = "Clave-muy-segura-2026"
RUN = str(int(time.time()))
def new_user(c, email):
    c.post("/api/auth/register", json={"email": email, "password": STRONG})
    tok = [m for m in mailer.RECENT if "verify=" in m["body"] and m["to"] == email][-1]
    t = re.search(r"verify=([A-Za-z0-9_-]+)", tok["body"]).group(1)
    c.post("/api/auth/verify", json={"token": t})
    c.post("/api/auth/login", json={"email": email, "password": STRONG})

import psycopg  # noqa: E402
with psycopg.connect(os.environ["DATABASE_URL"], autocommit=True) as _c:
    _c.execute("DELETE FROM signups")   # límite de registros por IP: se vacía solo en la base de PRUEBA

ADMIN = {"X-API-Key": "clave-admin-prueba"}
with TestClient(main.app) as admin, TestClient(main.app) as ana, TestClient(main.app) as beto, TestClient(main.app) as sin:
    new_user(ana, f"ana-{RUN}@ejemplo.com"); new_user(beto, f"beto-{RUN}@ejemplo.com")
    sin.post("/api/auth/register", json={"email": f"sin-{RUN}@ejemplo.com", "password": STRONG})
    sin.post("/api/auth/login", json={"email": f"sin-{RUN}@ejemplo.com", "password": STRONG})
    r = sin.post("/api/scans", json={"target": "localhost", "authorized": True})
    check("sin confirmar: no puede escanear (403)", r.status_code == 403, str(r.status_code))
    r = ana.post("/api/scans", json={"target": "localhost", "authorized": False})
    check("sin autorización: rechazado (400)", r.status_code == 400, str(r.status_code))
    r = ana.post("/api/scans", json={"target": "https://fuera-de-alcance.com", "authorized": True})
    check("fuera de alcance: rechazado (403)", r.status_code == 403, str(r.status_code))
    r = ana.post("/api/scans", json={"target": "http://127.0.0.1:9/x", "authorized": True})
    check("ana crea escaneo (202)", r.status_code == 202, r.text)
    jid = r.json()["id"]
    for _ in range(60):
        j = ana.get(f"/api/scans/{jid}").json()
        if j["status"] in ("done", "failed"): break
        time.sleep(1)
    check("ana ve su escaneo", j["status"] in ("done", "failed") and j["id"] == jid)
    check("beto NO puede leer el escaneo de ana (404)", beto.get(f"/api/scans/{jid}").status_code == 404)
    check("historial de beto no incluye el de ana", all(s["id"] != jid for s in beto.get("/api/scans").json()))
    check("historial de ana lo incluye", any(s["id"] == jid for s in ana.get("/api/scans").json()))
    check("administrador (API key) NO ve escaneos de usuarios (privacidad)", admin.get(f"/api/scans/{jid}", headers=ADMIN).status_code == 404)
    check("sin sesión ni clave: 401", TestClient(main.app).get("/api/scans").status_code == 401)
    check("reputación también disponible en modo completo",
          ana.get("/api/reputation", params={"url": "https://ejemplo.com"}).status_code == 200)
print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
sys.exit(1 if FAILS else 0)
