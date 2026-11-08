"""Cliente OSV.dev: cruza (paquete, versión, ecosistema) con vulnerabilidades.

El ecosistema por distribución hace que OSV evalúe la versión corregida real
(con backports del distribuidor), de modo que los hallazgos son "confirmados".
"""
import re
import time

import requests

from common import finding
from cvss import base_score

BATCH = "https://api.osv.dev/v1/querybatch"
DETAIL = "https://api.osv.dev/v1/vulns/{}"
BATCH_MAX = 900                 # límite OSV: 1000 consultas por lote
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_detail_cache = {}              # id -> dict (persistente en el proceso)

_LABEL = {"negligible": "low", "low": "low", "moderate": "medium", "medium": "medium",
          "important": "high", "high": "high", "critical": "critical"}


def _severity_from_cvss(score):
    if score is None:
        return None
    return ("critical" if score >= 9 else "high" if score >= 7 else
            "medium" if score >= 4 else "low" if score > 0 else "info")


def _detail(session, vid):
    if vid in _detail_cache:
        return _detail_cache[vid]
    data = {}
    try:
        r = session.get(DETAIL.format(vid), timeout=20)
        if r.status_code == 200:
            data = r.json()
    except requests.RequestException:
        data = {}
    _detail_cache[vid] = data
    return data


def _best_cvss(vuln):
    best = None
    for s in vuln.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            sc = base_score(s.get("score"))
            if sc is not None and (best is None or sc > best):
                best = sc
    return best


def _label_severity(vuln, name):
    """Severidad cualitativa del feed (Ubuntu/RedHat usan database_specific)."""
    cands = [(vuln.get("database_specific") or {}).get("severity")]
    for a in vuln.get("affected") or []:
        if (a.get("package") or {}).get("name") == name:
            cands.append((a.get("ecosystem_specific") or {}).get("severity"))
            cands.append((a.get("database_specific") or {}).get("severity"))
    best = None
    for c in cands:
        s = _LABEL.get(str(c).strip().lower()) if c else None
        if s and (best is None or SEV_RANK[s] > SEV_RANK[best]):
            best = s
    return best


def _fixed_versions(vuln, name, eco_prefix):
    fixed = []
    for a in vuln.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("name") != name:
            continue
        if eco_prefix and not str(pkg.get("ecosystem", "")).startswith(eco_prefix):
            continue
        for rng in a.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed.append(ev["fixed"])
    # conserva orden, sin duplicados
    seen, out = set(), []
    for v in fixed:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _cves(vuln):
    ids = [vuln.get("id", "")] + (vuln.get("aliases") or [])
    return sorted({x for x in ids if re.fullmatch(r"CVE-\d{4}-\d+", x or "")})


def query_batch(session, triples):
    """triples: [(name, version, ecosystem)]. Devuelve [[vuln_id,...] por índice]."""
    ids_per = [[] for _ in triples]
    for i in range(0, len(triples), BATCH_MAX):
        chunk = triples[i:i + BATCH_MAX]
        body = {"queries": [{"version": v, "package": {"name": n, "ecosystem": e}}
                            for (n, v, e) in chunk]}
        for attempt in range(3):
            try:
                r = session.post(BATCH, json=body, timeout=40)
            except requests.RequestException:
                time.sleep(2 * (attempt + 1))
                continue
            if r.status_code in (429, 503):
                time.sleep(3 * (attempt + 1))
                continue
            r.raise_for_status()
            for j, res in enumerate(r.json().get("results", [])):
                ids_per[i + j] = [v["id"] for v in (res.get("vulns") or [])]
            break
    return ids_per


def scan_packages(packages, ecosystem, asset, reliable=True):
    """packages: [(name, version, arch)]. Devuelve lista de findings."""
    eco_prefix = ecosystem.split(":", 1)[0]
    triples = [(n, v, ecosystem) for (n, v, _a) in packages]
    conf = 0.9 if reliable else 0.7
    out = []
    with requests.Session() as s:
        s.headers.update({"User-Agent": "vulnerscan-osaudit/0.1"})
        ids_per = query_batch(s, triples)
        for (name, version, _arch), vids in zip(packages, ids_per):
            for vid in vids:
                v = _detail(s, vid)
                if not v or v.get("withdrawn"):
                    continue
                cvss = _best_cvss(v)
                sev = _severity_from_cvss(cvss) or _label_severity(v, name) or "info"
                cves = _cves(v)
                fixed = _fixed_versions(v, name, eco_prefix)
                remediation = (f"Actualizar {name} a {fixed[0]} o posterior"
                               if fixed else f"Aplicar la actualización de seguridad de {name} del distribuidor")
                summary = v.get("summary") or (v.get("details") or "")[:140] or vid
                out.append(finding(
                    "osaudit", vid, f"{vid}: {name} {version}", sev, asset,
                    cves=cves, cvss=cvss, evidence=f"{name} {version} — {summary}"[:400],
                    remediation=remediation, confidence=conf,
                    package=name, installed_version=version, fixed_versions=fixed,
                    advisory=vid, ecosystem=ecosystem))
    return out
