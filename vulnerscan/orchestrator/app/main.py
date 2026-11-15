"""Orquestador: API, cuentas y páginas.

MODE=public  → instalación pública (Fase A): cuentas, reputación de URLs e historial. El escaneo
               activo queda DESACTIVADO (ENABLE_ACTIVE_SCANS=false).
MODE=full    → instalación completa (local o Fase B): además, escaneos activos sobre ALLOWED_TARGETS.
API_KEY (opcional) da acceso de administrador por cabecera X-API-Key; en una instalación pública debe
quedar vacía."""
import asyncio
import hmac
import os
import re
import time
import uuid

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from . import accounts, rep_store, reputation, store
from .dispatch import run_plan
from .enrich import enrich
from .normalize import normalize
from .prioritize import fix_first, prioritize
from .scope import detect_type, in_scope

MODE = os.getenv("MODE", "full").lower()
ENABLE_ACTIVE = os.getenv("ENABLE_ACTIVE_SCANS", "true" if MODE == "full" else "false").lower() == "true"
API_KEY = os.getenv("API_KEY", "")
COOKIE = "vs_session"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/")
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"    # detrás de Render/Fly: usar X-Forwarded-For

FRONT = next((p for p in (os.getenv("FRONTEND_DIR", ""), "frontend",
                          os.path.join(os.path.dirname(__file__), "..", "frontend"), "/srv/frontend")
              if p and os.path.isdir(p)), "frontend")

app = FastAPI(title="vulnerscan", docs_url=None, redoc_url=None)
JOBS: dict = {}          # caché en memoria de escaneos recientes; la fuente de verdad es PostgreSQL
SEM = asyncio.Semaphore(2)
store.init()

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if COOKIE_SECURE:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp


app.add_middleware(SecurityHeaders)


@app.exception_handler(accounts.AuthError)
async def _auth_error(request, exc):
    return JSONResponse({"detail": exc.msg}, status_code=exc.status)


def client_ip(request: Request):
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "0.0.0.0")[:64]


def current_user(request: Request):
    if API_KEY and hmac.compare_digest(request.headers.get("x-api-key", "").encode(), API_KEY.encode()):
        return {"id": 0, "email": "administrador", "verified": True}
    u = accounts.user_from_session(request.cookies.get(COOKIE))
    if u:
        return {"id": u["id"], "email": u["email"], "verified": u["verified"]}
    raise HTTPException(401, "Inicia sesión para continuar")


def verified_user(user=Depends(current_user)):
    if not user["verified"]:
        raise HTTPException(403, "Confirma tu correo (te enviamos un enlace) para usar esta función")
    return user


def require_active():
    if not ENABLE_ACTIVE:
        raise HTTPException(403, "El escaneo activo no está disponible en esta instalación")


# ---------------------------------------------------------------- cuentas
class Credentials(BaseModel):
    email: str = ""
    password: str = ""


class TokenIn(BaseModel):
    token: str = ""


class ResetIn(BaseModel):
    token: str = ""
    password: str = ""


class ForgotIn(BaseModel):
    email: str = ""


@app.get("/api/health")
def health():
    return {"ok": True, "mode": MODE, "active_scans": ENABLE_ACTIVE}


@app.post("/api/auth/register", status_code=202)
def register(body: Credentials, request: Request):
    return {"message": accounts.register(body.email, body.password, client_ip(request), PUBLIC_URL)}


@app.post("/api/auth/verify")
def verify(body: TokenIn):
    accounts.verify_email(body.token)
    return {"ok": True, "message": "Correo confirmado. Ya puedes usar todas las funciones."}


@app.post("/api/auth/login")
def login(body: Credentials, request: Request):
    tok, verified = accounts.login(body.email, body.password, client_ip(request))
    resp = JSONResponse({"email": body.email.strip().lower(), "verified": verified})
    resp.set_cookie(COOKIE, tok, httponly=True, samesite="lax", secure=COOKIE_SECURE,
                    max_age=accounts.SESSION_DAYS * 86400, path="/")
    return resp


@app.post("/api/auth/logout")
def logout(request: Request):
    accounts.logout(request.cookies.get(COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return {"email": user["email"], "verified": user["verified"], "admin": user["id"] == 0}


@app.post("/api/auth/forgot")
def forgot(body: ForgotIn):
    return {"message": accounts.forgot(body.email, PUBLIC_URL)}


@app.post("/api/auth/reset")
def reset(body: ResetIn):
    accounts.reset_password(body.token, body.password)
    return {"ok": True, "message": "Contraseña actualizada. Inicia sesión de nuevo."}


# ---------------------------------------------------------------- reputación (abierta a usuarios verificados)
@app.get("/api/reputation")
async def reputation_check(url: str, user=Depends(verified_user)):
    """¿Es maligna esta URL? Análisis pasivo: no se contacta el sitio analizado."""
    try:
        u = reputation.validate_url(url)
    except ValueError as e:
        raise HTTPException(400, str(e))
    remaining = rep_store.take_quota(user["id"])
    cached = rep_store.cache_get(u)
    if cached:
        res = {**cached, "cached": True}
    else:
        rep_store.take_global()          # límite diario de toda la página (cuota de VirusTotal/Google)
        res = {**(await reputation.analyze(u)), "cached": False}
        if any(s["status"] == "ok" for s in res["sources"]):
            rep_store.cache_put(u, res)
    rep_store.history_add(user["id"], u, res["verdict"])
    res["remaining"] = remaining
    return res


@app.get("/api/reputation/history")
def reputation_history(user=Depends(verified_user)):
    return rep_store.history_list(user["id"])


# ---------------------------------------------------------------- escaneo activo (solo MODE=full o ENABLE_ACTIVE_SCANS)
class ScanRequest(BaseModel):
    target: str
    authorized: bool = False
    modules: list[str] | None = None
    options: dict = {}


@app.post("/api/scans", status_code=202)
async def create_scan(req: ScanRequest, user=Depends(verified_user)):
    require_active()
    if not req.authorized:
        raise HTTPException(400, "Debes confirmar que tienes autorización para auditar este objetivo")
    ttype = detect_type(req.target)
    if not ttype:
        raise HTTPException(400, "Objetivo no reconocido (IP/CIDR, dominio, URL, repo git o image:<ref>)")
    if ttype in ("network", "host", "web", "osaudit") and not in_scope(req.target):
        raise HTTPException(403, "Objetivo fuera de ALLOWED_TARGETS")
    jid = uuid.uuid4().hex[:12]
    JOBS[jid] = {"id": jid, "user_id": user["id"], "target": req.target, "type": ttype, "status": "queued",
                 "progress": [], "errors": [], "findings": [], "fix_first": [], "meta": {}, "created": time.time()}
    for old in sorted(JOBS, key=lambda k: JOBS[k]["created"])[:-50]:
        JOBS.pop(old, None)
    store.save(JOBS[jid])
    asyncio.create_task(run_job(jid, req, ttype))
    return {"id": jid}


async def run_job(jid, req, ttype):
    job = JOBS[jid]
    async with SEM:
        try:
            job["status"] = "running"
            store.save(job)
            raw, errors = await run_plan(req.target, ttype, req.modules, req.options, job)
            job["errors"] = errors
            job["progress"].append("normalizando y enriqueciendo (NVD / KEV / EPSS)")
            findings = prioritize(await enrich(normalize(raw)))
            job["findings"], job["fix_first"] = findings, fix_first(findings)
            job["status"] = "done"
        except Exception as e:
            job["status"], job["errors"] = "failed", job["errors"] + [str(e)]
        finally:
            store.save(job)


@app.get("/api/scans")
def list_scans(user=Depends(current_user)):
    return store.list_summaries(user["id"])


@app.get("/api/scans/{jid}")
def get_scan(jid: str, user=Depends(current_user)):
    job = JOBS.get(jid)
    if job is not None and job.get("user_id") == user["id"]:
        return job
    job = store.get(jid, user["id"])
    if job is None:
        raise HTTPException(404)
    return job


class CheckIn(BaseModel):
    yaml: str


@app.post("/api/checks")
def add_check(body: CheckIn, user=Depends(verified_user)):
    """Checks declarativos (YAML) aportados por usuarios. No ejecutan código arbitrario."""
    require_active()
    if len(body.yaml) > 20000:
        raise HTTPException(413, "Demasiado grande")
    try:
        doc = yaml.safe_load(body.yaml)
    except yaml.YAMLError as e:
        raise HTTPException(400, f"YAML inválido: {e}")
    if not isinstance(doc, dict) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,60}", str(doc.get("id", ""))):
        raise HTTPException(400, "Falta 'id' válido (a-z, 0-9, guiones)")
    if doc.get("protocol") not in ("http", "tcp") or doc.get("severity") not in ("info", "low", "medium", "high", "critical"):
        raise HTTPException(400, "protocol (http|tcp) y severity requeridos")
    with open(f"/checks/{doc['id']}.yaml", "w") as fh:
        fh.write(body.yaml)
    return {"saved": doc["id"]}


# ---------------------------------------------------------------- páginas
@app.get("/", include_in_schema=False)
def root():
    return FileResponse(os.path.join(FRONT, "public.html" if MODE == "public" else "index.html"))


app.mount("/", StaticFiles(directory=FRONT, html=True), name="ui")
