"""Pruebas de la Fase A (cuentas, reputación con cuota, aislamiento y modo público) contra PostgreSQL REAL.

Requiere una base de PRUEBA vacía. Ejecutar:
    DATABASE_URL=postgresql://vs:vs@127.0.0.1:5433/vs ALLOW_DB_RESET=1 python tests/test_saas.py
ALLOW_DB_RESET=1 borra el esquema 'public' de esa base (por seguridad no corre sin la variable)."""
import asyncio
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.getenv("ALLOW_DB_RESET") != "1" or not os.getenv("DATABASE_URL"):
    print("SKIP: define DATABASE_URL (base de prueba) y ALLOW_DB_RESET=1")
    sys.exit(0)
os.environ.setdefault("MODE", "public")
os.environ["ENABLE_ACTIVE_SCANS"] = "false"
os.environ["API_KEY"] = ""
os.environ["MAIL_DEV"] = "1"
os.environ["REP_DAILY_LIMIT"] = "3"
os.environ["PUBLIC_URL"] = "http://testserver"
sys.path[:0] = [f"{ROOT}/orchestrator"]

import psycopg  # noqa: E402

with psycopg.connect(os.environ["DATABASE_URL"], autocommit=True) as c:
    c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")

from fastapi.testclient import TestClient  # noqa: E402
from app import accounts, main, mailer, rep_store, reputation  # noqa: E402


FAILS = []
CALLS = {"n": 0}
STRONG = "Clave-muy-segura-2026"


def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), name, "" if cond else extra)
    if not cond:
        FAILS.append(name)


def last_token(kind):
    for m in reversed(list(mailer.RECENT)):
        mm = re.search(kind + r"=([A-Za-z0-9_-]+)", m["body"])
        if mm:
            return mm.group(1)
    return None


async def fake_analyze(url, vt_key=None, gsb_key=None):
    CALLS["n"] += 1
    mal = "malo" in url
    return {"url": url, "verdict": "maligna" if mal else "sin detecciones", "confidence": "alta" if mal else "media",
            "sources": [{"source": "VirusTotal", "status": "ok", "malicious": 5 if mal else 0, "suspicious": 0,
                         "detail": "fake"},
                        {"source": "Google Safe Browsing", "status": "ok", "matches": 0, "detail": "fake"}],
            "heuristics": [], "note": "fake"}


reputation.analyze = fake_analyze
main.reputation.analyze = fake_analyze


def register_verify(client, email, pw=STRONG):
    r = client.post("/api/auth/register", json={"email": email, "password": pw})
    assert r.status_code == 202, r.text
    tok = last_token("verify")
    v = client.post("/api/auth/verify", json={"token": tok})
    assert v.status_code == 200, v.text
    return tok


def main_tests():
    a = TestClient(main.app)
    b = TestClient(main.app)

    # --- registro y validaciones
    r = a.post("/api/auth/register", json={"email": "ana@ejemplo.com", "password": "123"})
    check("contraseña corta rechazada", r.status_code == 400, r.text)
    r = a.post("/api/auth/register", json={"email": "no-es-correo", "password": STRONG})
    check("correo inválido rechazado", r.status_code == 400, r.text)
    r = a.post("/api/auth/register", json={"email": "ana@ejemplo.com", "password": "password12"})
    check("contraseña común rechazada", r.status_code == 400, r.text)
    r = a.post("/api/auth/register", json={"email": "ana@ejemplo.com", "password": STRONG})
    check("registro responde genérico (202)", r.status_code == 202 and "confirmar" in r.json()["message"], r.text)
    r2 = a.post("/api/auth/register", json={"email": "ana@ejemplo.com", "password": STRONG})
    check("mismo correo: misma respuesta (no revela cuentas)", r2.status_code == 202 and r2.json() == r.json())
    vtok = last_token("verify")
    check("correo de verificación generado", vtok is not None)
    with psycopg.connect(os.environ["DATABASE_URL"]) as c:
        stored = c.execute("SELECT pw_hash, verify_hash FROM users WHERE email='ana@ejemplo.com'").fetchone()
    check("contraseña guardada con hash (no en claro)", STRONG not in stored[0] and stored[0].startswith("scrypt$"))
    check("token de verificación guardado solo como hash", vtok not in stored[1])

    # --- login antes de verificar
    r = a.post("/api/auth/login", json={"email": "ana@ejemplo.com", "password": STRONG})
    check("login correcto aunque no esté verificada", r.status_code == 200 and r.json()["verified"] is False, r.text)
    check("cookie de sesión HttpOnly", "vs_session" in r.headers.get("set-cookie", "") and "httponly" in r.headers.get("set-cookie", "").lower())
    r = a.get("/api/reputation", params={"url": "https://ejemplo.com"})
    check("sin verificar: reputación bloqueada (403)", r.status_code == 403, str(r.status_code))
    r = a.post("/api/scans", json={"target": "localhost", "authorized": True})
    check("escaneo activo desactivado en modo público (403)", r.status_code == 403, str(r.status_code))

    # --- verificación y reputación
    r = a.post("/api/auth/verify", json={"token": "token-falso"})
    check("token de verificación falso rechazado", r.status_code == 400)
    r = a.post("/api/auth/verify", json={"token": vtok})
    check("verificación con token válido", r.status_code == 200)
    r = a.post("/api/auth/verify", json={"token": vtok})
    check("token de verificación de un solo uso", r.status_code == 400)
    me = a.get("/api/auth/me").json()
    check("me: verificada", me["verified"] is True and me["email"] == "ana@ejemplo.com")

    CALLS["n"] = 0
    r1 = a.get("/api/reputation", params={"url": "https://malo.example.com/x"}).json()
    check("reputación: veredicto y primera consulta real", r1["verdict"] == "maligna" and r1["cached"] is False and CALLS["n"] == 1)
    check("reputación: indica consultas restantes", r1["remaining"] == 2, str(r1.get("remaining")))
    r2 = a.get("/api/reputation", params={"url": "https://malo.example.com/x"}).json()
    check("misma URL: resultado desde caché (sin nueva consulta externa)", r2["cached"] is True and CALLS["n"] == 1)
    check("caché gasta cuota igualmente", r2["remaining"] == 1)
    a.get("/api/reputation", params={"url": "https://limpio.example.org"})
    r = a.get("/api/reputation", params={"url": "https://otra.example.net"})
    check("cuota diaria: el 4.º intento se bloquea (429)", r.status_code == 429, str(r.status_code))
    r = a.get("/api/reputation", params={"url": "ftp://no-valida"})
    check("URL inválida: 400 antes de gastar cuota", r.status_code == 400, str(r.status_code))
    hist = a.get("/api/reputation/history").json()
    check("historial del usuario con sus consultas", len(hist) == 3 and hist[0]["url"] == "https://limpio.example.org", str(hist))

    # --- aislamiento entre usuarios
    register_verify(b, "beto@ejemplo.com")
    b.post("/api/auth/login", json={"email": "beto@ejemplo.com", "password": STRONG})
    check("otro usuario no ve el historial ajeno", b.get("/api/reputation/history").json() == [])
    rb = b.get("/api/reputation", params={"url": "https://malo.example.com/x"}).json()
    check("cuota propia por usuario (beto tiene su límite)", rb["remaining"] == 2, str(rb.get("remaining")))
    check("caché compartida no revela quién consultó", rb["cached"] is True)

    # --- fuerza bruta
    register_verify(a, "carla@ejemplo.com")
    c2 = TestClient(main.app)
    codes = [c2.post("/api/auth/login", json={"email": "carla@ejemplo.com", "password": "mala-clave-xyz"}).status_code
             for _ in range(9)]
    check("8 fallos seguidos: 401; luego bloqueo 429", codes[:8] == [401] * 8 and codes[8] == 429, str(codes))
    r = c2.post("/api/auth/login", json={"email": "carla@ejemplo.com", "password": STRONG})
    check("cuenta bloqueada temporalmente aun con clave correcta", r.status_code == 429)

    # --- recuperación de contraseña
    d = TestClient(main.app)
    register_verify(d, "dani@ejemplo.com", pw="Primera-clave-2026")
    d.post("/api/auth/login", json={"email": "dani@ejemplo.com", "password": "Primera-clave-2026"})
    r = d.post("/api/auth/forgot", json={"email": "dani@ejemplo.com"})
    check("olvido de contraseña: respuesta genérica", r.status_code == 200 and "enlace" in r.json()["message"])
    r = d.post("/api/auth/forgot", json={"email": "nadie@ejemplo.com"})
    check("olvido de contraseña para correo inexistente: misma respuesta", r.status_code == 200)
    rtok = last_token("reset")
    check("enlace de recuperación generado", rtok is not None)
    r = d.post("/api/auth/reset", json={"token": rtok, "password": "Segunda-clave-2026"})
    check("restablecer contraseña con enlace válido", r.status_code == 200, r.text)
    check("sesión anterior cerrada tras restablecer", d.get("/api/auth/me").status_code == 401)
    check("enlace de recuperación de un solo uso", d.post("/api/auth/reset", json={"token": rtok, "password": "Tercera-clave-2026"}).status_code == 400)
    r = TestClient(main.app).post("/api/auth/login", json={"email": "dani@ejemplo.com", "password": "Segunda-clave-2026"})
    check("nueva contraseña funciona", r.status_code == 200)

    # --- cierre de sesión y cookies
    a.post("/api/auth/logout")
    check("tras cerrar sesión: 401", a.get("/api/auth/me").status_code == 401)

    # --- cabeceras de seguridad y página pública
    page = TestClient(main.app).get("/")
    check("raíz sirve la página pública en modo público", page.status_code == 200 and "¿Es maligna esta URL?" in page.text
          and "Ver tu historial" not in page.text and "id=\"sec-app\"" in page.text)
    check("cabecera Content-Security-Policy", "default-src 'self'" in page.headers.get("content-security-policy", ""))
    check("cabecera X-Frame-Options DENY", page.headers.get("x-frame-options") == "DENY")
    check("cabecera nosniff", page.headers.get("x-content-type-options") == "nosniff")
    check("fondo servido", TestClient(main.app).get("/assets/bg.jpg").status_code == 200)

    # --- límite de registros por IP
    codes = [TestClient(main.app).post("/api/auth/register",
             json={"email": f"masivo{i}@ejemplo.com", "password": STRONG}).status_code for i in range(10)]
    check("registros masivos desde una IP: se bloquean (429)", 429 in codes, str(codes))

    # --- cuentas distintas no comparten sesión
    check("sesión inválida no da acceso", TestClient(main.app).get("/api/reputation/history").status_code == 401)


def new_tests():
    """Correo caído (no deja cuentas a medias) y límite global de consultas reales."""
    import time
    ts = str(int(time.time()))
    with psycopg.connect(os.environ["DATABASE_URL"], autocommit=True) as c:
        c.execute("DELETE FROM signups")
        c.execute("DELETE FROM rep_global")
    real_send = mailer.send

    def caido(*a, **k):
        raise RuntimeError("SMTP caído")
    mailer.send = caido
    cl = TestClient(main.app)
    email = f"fallo-{ts}@ejemplo.com"
    r = cl.post("/api/auth/register", json={"email": email, "password": STRONG})
    check("correo caído: registro responde 503 con mensaje claro",
          r.status_code == 503 and "correo" in r.json()["detail"], r.text)
    with psycopg.connect(os.environ["DATABASE_URL"]) as c:
        row = c.execute("SELECT 1 FROM users WHERE email=%s", (email,)).fetchone()
    check("correo caído: la cuenta NO queda creada", row is None)
    mailer.send = real_send
    r = cl.post("/api/auth/register", json={"email": email, "password": STRONG})
    check("tras recuperar el correo, puede registrarse (202)", r.status_code == 202, r.text)

    # --- límite global de consultas reales (no caché)
    rep_store.REP_GLOBAL_DAILY = 2
    rep_store.REP_DAILY = 10
    g = TestClient(main.app)
    register_verify(g, f"gamma-{ts}@ejemplo.com")
    g.post("/api/auth/login", json={"email": f"gamma-{ts}@ejemplo.com", "password": STRONG})
    u1, u2, u3 = (f"https://g{ts}-{i}.example.org/" for i in range(3))
    check("límite global: 1.ª consulta real", g.get("/api/reputation", params={"url": u1}).status_code == 200)
    check("límite global: 2.ª consulta real", g.get("/api/reputation", params={"url": u2}).status_code == 200)
    r = g.get("/api/reputation", params={"url": u3})
    check("límite global: 3.ª consulta real se bloquea (429)", r.status_code == 429, str(r.status_code))
    r = g.get("/api/reputation", params={"url": u1})
    check("límite global: una URL en caché sigue funcionando", r.status_code == 200 and r.json()["cached"] is True)
    rep_store.REP_GLOBAL_DAILY = 400
    rep_store.REP_DAILY = 3


def store_isolation():
    from app import store
    store.save({"id": "job-A", "user_id": 1, "target": "x", "type": "web", "status": "done", "created": 1.0})
    check("escaneo de A no lo lee B", store.get("job-A", 2) is None)
    check("escaneo de A lo lee A", store.get("job-A", 1) is not None)
    check("listado de B no incluye escaneos de A", store.list_summaries(2) == [])


if __name__ == "__main__":
    main_tests()
    new_tests()
    store_isolation()
    print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
    sys.exit(1 if FAILS else 0)
