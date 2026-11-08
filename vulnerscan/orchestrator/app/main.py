import asyncio, hmac, os, re, time, uuid
import yaml
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .dispatch import run_plan
from .enrich import enrich
from .normalize import normalize
from .prioritize import fix_first, prioritize
from .scope import detect_type, in_scope

API_KEY = os.environ["API_KEY"]
app = FastAPI(title="vulnerscan", docs_url=None, redoc_url=None)
JOBS: dict = {}          # producción: PostgreSQL + cola de trabajos
SEM = asyncio.Semaphore(2)

def auth(x_api_key: str = Header(default="")):
    if not hmac.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(401, "API key inválida")

class ScanRequest(BaseModel):
    target: str
    authorized: bool = False
    modules: list[str] | None = None
    options: dict = {}

@app.get("/api/health")
def health(): return {"ok": True}

@app.post("/api/scans", status_code=202, dependencies=[Depends(auth)])
async def create_scan(req: ScanRequest):
    if not req.authorized:
        raise HTTPException(400, "Debes confirmar que tienes autorización para auditar este objetivo")
    ttype = detect_type(req.target)
    if not ttype: raise HTTPException(400, "Objetivo no reconocido (IP/CIDR, dominio, URL, repo git o image:<ref>)")
    if ttype in ("network", "host", "web", "osaudit") and not in_scope(req.target):
        raise HTTPException(403, "Objetivo fuera de ALLOWED_TARGETS")
    jid = uuid.uuid4().hex[:12]
    JOBS[jid] = {"id": jid, "target": req.target, "type": ttype, "status": "queued", "progress": [],
                 "errors": [], "findings": [], "fix_first": [], "created": time.time()}
    for old in sorted(JOBS, key=lambda k: JOBS[k]["created"])[:-50]: JOBS.pop(old, None)
    asyncio.create_task(run_job(jid, req, ttype))
    return {"id": jid}

async def run_job(jid, req, ttype):
    job = JOBS[jid]
    async with SEM:
        try:
            job["status"] = "running"
            raw, errors = await run_plan(req.target, ttype, req.modules, req.options, job)
            job["errors"] = errors
            job["progress"].append("normalizando y enriqueciendo (NVD / KEV / EPSS)")
            findings = prioritize(await enrich(normalize(raw)))
            job["findings"], job["fix_first"] = findings, fix_first(findings)
            job["status"] = "done"
        except Exception as e:
            job["status"], job["errors"] = "failed", job["errors"] + [str(e)]

@app.get("/api/scans", dependencies=[Depends(auth)])
def list_scans():
    return [{k: j[k] for k in ("id", "target", "type", "status", "created")} for j in JOBS.values()]

@app.get("/api/scans/{jid}", dependencies=[Depends(auth)])
def get_scan(jid: str):
    if jid not in JOBS: raise HTTPException(404)
    return JOBS[jid]

class CheckIn(BaseModel):
    yaml: str

@app.post("/api/checks", dependencies=[Depends(auth)])
def add_check(body: CheckIn):
    """Checks declarativos (YAML) aportados por usuarios. No ejecutan código arbitrario."""
    if len(body.yaml) > 20000: raise HTTPException(413, "Demasiado grande")
    try: doc = yaml.safe_load(body.yaml)
    except yaml.YAMLError as e: raise HTTPException(400, f"YAML inválido: {e}")
    if not isinstance(doc, dict) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,60}", str(doc.get("id", ""))):
        raise HTTPException(400, "Falta 'id' válido (a-z, 0-9, guiones)")
    if doc.get("protocol") not in ("http", "tcp") or doc.get("severity") not in ("info", "low", "medium", "high", "critical"):
        raise HTTPException(400, "protocol (http|tcp) y severity requeridos")
    with open(f"/checks/{doc['id']}.yaml", "w") as fh: fh.write(body.yaml)
    return {"saved": doc["id"]}

app.mount("/", StaticFiles(directory="frontend", html=True), name="ui")
