"""SAST (Semgrep), secretos (detect-secrets) y dependencias/imágenes por capa (Trivy).

Regla: si una herramienta falta, falla o devuelve algo que no se puede leer, el escaneo
falla con un error explícito. Nunca se devuelve "sin hallazgos" por un fallo silencioso
(eso sería un falso negativo)."""
import json, os, re, subprocess, tempfile
from fastapi import FastAPI, HTTPException
from common import finding

app = FastAPI()
SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info",
       "ERROR": "high", "WARNING": "medium", "INFO": "low"}


def sh(cmd, cwd=None, timeout=1800, ok=(0,)):
    """Ejecuta una herramienta y comprueba su código de salida."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError(f"herramienta no instalada en el plugin: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{cmd[0]} superó el tiempo máximo ({timeout} s)")
    if p.returncode not in ok:
        detail = (p.stderr or p.stdout or "").strip()[:300]
        raise RuntimeError(f"{cmd[0]} terminó con código {p.returncode}: {detail}")
    return p.stdout, p.stderr


def load_json(raw, what):
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise RuntimeError(f"{what}: salida no válida (se esperaba JSON)")


def clean_instr(s):
    """'/bin/sh -c #(nop) COPY x' -> 'COPY x'; '/bin/sh -c apt-get ...' -> 'RUN apt-get ...'."""
    s = re.sub(r"^/bin/sh -c #\(nop\)\s*", "", s or "")
    s = re.sub(r"^/bin/sh -c\s*", "RUN ", s)
    return re.sub(r"\s+", " ", s).strip()[:160]


def layer_map(data):
    """DiffID -> (índice 1-based, total de capas, instrucción).
    Las capas reales son las entradas del historial que NO son 'empty_layer' (ENV, CMD… no crean capa)."""
    cfg = (data.get("Metadata") or {}).get("ImageConfig") or {}
    diff_ids = (cfg.get("rootfs") or {}).get("diff_ids") or []
    real = [h for h in (cfg.get("history") or []) if not h.get("empty_layer")]
    out = {}
    for i, did in enumerate(diff_ids):
        instr = clean_instr(real[i].get("created_by", "")) if i < len(real) else ""
        out[did] = (i + 1, len(diff_ids), instr)
    return out


def parse_trivy(raw, label):
    data = load_json(raw, "trivy")
    layers = layer_map(data)
    out = []
    for res in data.get("Results") or []:
        tgt = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            cve = v.get("VulnerabilityID", "")
            cv = max([x.get("V3Score") or 0 for x in (v.get("CVSS") or {}).values()] or [0]) or None
            did = (v.get("Layer") or {}).get("DiffID", "")
            fix = v.get("FixedVersion")
            where = f"{v.get('PkgName')} {v.get('InstalledVersion')} en {tgt}"
            kw = {}
            if did in layers:
                idx, total, instr = layers[did]
                kw = {"layer_index": idx, "layer_total": total, "layer_instruction": instr}
                where += f" · capa {idx}/{total}" + (f": {instr}" if instr else "")
            elif did:
                where += f" · capa {did[:19]} (sin historial de la imagen)"
            out.append(finding("code", cve, f"{cve}: {v.get('PkgName')} {v.get('InstalledVersion')}",
                SEV.get(v.get("Severity"), "info"), f"{label}::{tgt}::{v.get('PkgName')}",
                cves=[cve] if cve.startswith("CVE-") else [], cvss=cv, evidence=where,
                remediation=f"Actualizar a {fix}" if fix else "Sin parche publicado: evaluar mitigaciones",
                confidence=0.85, **kw))
        for sct in res.get("Secrets") or []:
            out.append(finding("code", f"secret@{tgt}:{sct.get('StartLine')}", f"Secreto expuesto: {sct.get('Title', '')}",
                "high", f"{label}::{tgt}", cwe="CWE-798", evidence=f"{tgt}:{sct.get('StartLine')}", confidence=0.8,
                remediation="Rotar la credencial y moverla a un gestor de secretos."))
        for m in res.get("Misconfigurations") or []:
            out.append(finding("code", m.get("ID", "misconfig"), m.get("Title", "Mala configuración"),
                SEV.get(m.get("Severity"), "low"), f"{label}::{tgt}", evidence=m.get("Message", "")[:300],
                remediation=m.get("Resolution", ""), confidence=0.8))
    return out


def scan_repo(target):
    label = target
    with tempfile.TemporaryDirectory() as tmp:
        if target.startswith("/workspace/"):
            d = os.path.realpath(target)
            if not d.startswith("/workspace/"):
                raise HTTPException(400, "Ruta no permitida")
        else:
            if not re.fullmatch(r"https://[\w.-]+/[\w./-]+", target):
                raise HTTPException(400, "URL de repo no válida")
            d = os.path.join(tmp, "repo")
            sh(["git", "clone", "--depth", "1", "--", target, d], timeout=600)

        out = []
        # SAST: patrones inseguros (AST) con reglas de Semgrep Registry.
        o, _ = sh(["semgrep", "--config", "p/default", "--config", "p/owasp-top-ten",
                   "--json", "--quiet", "--metrics=off", "."], cwd=d)
        for r in load_json(o, "semgrep").get("results", []):
            cwe = (r["extra"].get("metadata", {}).get("cwe") or [None])
            cwe = cwe[0] if isinstance(cwe, list) else cwe
            out.append(finding("code", f"{r['check_id']}@{r['path']}:{r['start']['line']}",
                r["extra"]["message"][:160], SEV.get(r["extra"]["severity"], "low"),
                f"{label}::{r['path']}", cwe=cwe, confidence=0.6,
                evidence=f"{r['path']}:{r['start']['line']}",
                remediation="Revisar y corregir el patrón inseguro (SAST requiere triage)."))

        # Secretos: el valor nunca se almacena, solo ubicación y tipo.
        o, _ = sh(["detect-secrets", "scan", "--all-files", "."], cwd=d)
        for fn, items in load_json(o, "detect-secrets").get("results", {}).items():
            for it in items:
                p = fn.lstrip("./")
                out.append(finding("code", f"secret@{p}:{it['line_number']}", f"Posible secreto: {it['type']}",
                    "high", f"{label}::{p}", cwe="CWE-798", evidence=f"{p}:{it['line_number']}", confidence=0.6))

        # Dependencias obsoletas (lockfiles, requirements, go.sum…) y Dockerfile mal configurado.
        o, _ = sh(["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig", d])
        for f in parse_trivy(o, label):
            f["asset"] = f["asset"].replace(d + "/", "")
            out.append(f)
        return out


def scan_image(target):
    ref = target.removeprefix("image:")
    if not re.fullmatch(r"[\w][\w./:@-]*", ref):
        raise HTTPException(400, "Referencia de imagen no válida")
    o, _ = sh(["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig", ref])
    return parse_trivy(o, ref)


@app.post("/scan")
def scan(req: dict):
    t = req["target"]
    try:
        if (req.get("options") or {}).get("type") == "container":
            found = scan_image(t)
        else:
            found = scan_repo(t)
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    return {"findings": found, "meta": {}}
