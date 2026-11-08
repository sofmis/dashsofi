"""SAST (Semgrep), secretos (detect-secrets) y dependencias/imágenes por capa (Trivy)."""
import json, os, re, subprocess, tempfile
from fastapi import FastAPI, HTTPException
from common import finding

app = FastAPI()
SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info",
       "ERROR": "high", "WARNING": "medium", "INFO": "low"}

def sh(cmd, cwd=None, timeout=1800):
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)
    return p.stdout, p.stderr

def parse_trivy(raw, label):
    out = []
    try: data = json.loads(raw)
    except Exception: return out
    for res in data.get("Results") or []:
        tgt = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            cve = v.get("VulnerabilityID", "")
            cv = max([x.get("V3Score") or 0 for x in (v.get("CVSS") or {}).values()] or [0]) or None
            layer = (v.get("Layer") or {}).get("DiffID", "")
            fix = v.get("FixedVersion")
            out.append(finding("code", cve, f"{cve}: {v.get('PkgName')} {v.get('InstalledVersion')}", SEV.get(v.get("Severity"), "info"),
                f"{label}::{tgt}::{v.get('PkgName')}", cves=[cve] if cve.startswith("CVE-") else [], cvss=cv,
                evidence=f"{v.get('PkgName')} {v.get('InstalledVersion')} en {tgt}" + (f" · capa {layer[:19]}" if layer else ""),
                remediation=f"Actualizar a {fix}" if fix else "Sin parche publicado: evaluar mitigaciones", confidence=0.85))
        for sct in res.get("Secrets") or []:
            out.append(finding("code", f"secret@{tgt}:{sct.get('StartLine')}", f"Secreto expuesto: {sct.get('Title','')}", "high",
                f"{label}::{tgt}", cwe="CWE-798", evidence=f"{tgt}:{sct.get('StartLine')}", confidence=0.8,
                remediation="Rotar la credencial y moverla a un gestor de secretos."))
        for m in res.get("Misconfigurations") or []:
            out.append(finding("code", m.get("ID", "misconfig"), m.get("Title", "Mala configuración"), SEV.get(m.get("Severity"), "low"),
                f"{label}::{tgt}", evidence=m.get("Message", "")[:300], remediation=m.get("Resolution", ""), confidence=0.8))
    return out

def scan_repo(target):
    label = target
    with tempfile.TemporaryDirectory() as tmp:
        if target.startswith("/workspace/"):
            d = os.path.realpath(target)
            if not d.startswith("/workspace/"): raise HTTPException(400, "Ruta no permitida")
        else:
            if not re.fullmatch(r"https://[\w.-]+/[\w./-]+", target): raise HTTPException(400, "URL de repo no válida")
            d = os.path.join(tmp, "repo"); sh(["git", "clone", "--depth", "1", "--", target, d], timeout=600)
        out = []
        o, _ = sh(["semgrep", "--config", "p/default", "--config", "p/owasp-top-ten", "--json", "--quiet", "--metrics=off", "."], cwd=d)
        try:
            for r in json.loads(o).get("results", []):
                cwe = (r["extra"].get("metadata", {}).get("cwe") or [None]); cwe = cwe[0] if isinstance(cwe, list) else cwe
                out.append(finding("code", f"{r['check_id']}@{r['path']}:{r['start']['line']}", r["extra"]["message"][:160],
                    SEV.get(r["extra"]["severity"], "low"), f"{label}::{r['path']}", cwe=cwe, confidence=0.6,
                    evidence=f"{r['path']}:{r['start']['line']}", remediation="Revisar y corregir el patrón inseguro (SAST requiere triage)."))
        except Exception: pass
        o, _ = sh(["detect-secrets", "scan", "--all-files", "."], cwd=d)
        try:
            for fn, items in json.loads(o).get("results", {}).items():
                for it in items:   # nunca se almacena el valor del secreto
                    p = fn.lstrip("./")
                    out.append(finding("code", f"secret@{p}:{it['line_number']}", f"Posible secreto: {it['type']}", "high",
                        f"{label}::{p}", cwe="CWE-798", evidence=f"{p}:{it['line_number']}", confidence=0.6))
        except Exception: pass
        o, _ = sh(["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig", d])
        for f in parse_trivy(o, label):
            f["asset"] = f["asset"].replace(d + "/", "")
            out.append(f)
        return out

def scan_image(target):
    ref = target.removeprefix("image:")
    if not re.fullmatch(r"[\w][\w./:@-]*", ref): raise HTTPException(400, "Referencia de imagen no válida")
    o, _ = sh(["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig", ref])
    return parse_trivy(o, ref)

@app.post("/scan")
def scan(req: dict):
    t = req["target"]
    return {"findings": scan_image(t) if req["options"].get("type") == "container" else scan_repo(t), "meta": {}}
