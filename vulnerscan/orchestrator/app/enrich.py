"""Enriquecimiento: NVD (CPE→CVE), CISA KEV y EPSS (FIRST.org). Todo vía API, con caché."""
import asyncio, os, time, httpx
from .common_sev import severity_from_cvss

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"
NVD_KEY = os.getenv("NVD_API_KEY", "")
_nvd, _kev, _epss = {}, (0, set()), {}

def cpe23(cpe):
    if cpe.startswith("cpe:2.3:"): return cpe
    p = cpe.split(":")                      # cpe:/a:vendor:product:version
    return f"cpe:2.3:{p[1].lstrip('/')}:{p[2]}:{p[3]}:{p[4]}:*:*:*:*:*:*:*" if len(p) >= 5 else None

async def nvd_by_cpe(c, cpe):
    if cpe in _nvd: return _nvd[cpe]
    res = []
    for attempt in range(3):
        r = await c.get(NVD, params={"cpeName": cpe}, headers={"apiKey": NVD_KEY} if NVD_KEY else {})
        if r.status_code in (403, 429, 503):
            await asyncio.sleep(6 * (attempt + 1)); continue
        if r.status_code == 200:
            for v in r.json().get("vulnerabilities", []):
                cve = v["cve"]
                if cve.get("vulnStatus") == "Rejected": continue
                score = None
                for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if cve.get("metrics", {}).get(k):
                        score = cve["metrics"][k][0]["cvssData"]["baseScore"]; break
                desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
                res.append({"id": cve["id"], "cvss": score, "desc": desc})
        break
    _nvd[cpe] = res
    await asyncio.sleep(0.7 if NVD_KEY else 6.2)   # límites públicos de NVD
    return res

async def expand(c, f):
    cpe = cpe23(f["cpe"])
    out = [f]
    if not cpe: return out
    for v in sorted(await nvd_by_cpe(c, cpe), key=lambda x: -(x["cvss"] or 0))[:25]:
        out.append({**f, "rule_id": v["id"], "title": f"{v['id']} afecta a {f['evidence'] or f['cpe']}",
                    "severity": severity_from_cvss(v["cvss"]), "cves": [v["id"]], "cvss": v["cvss"], "cpe": None,
                    "evidence": f"Detectado por versión ({f['cpe']}). {v['desc'][:300]}",
                    "confidence": 0.55,   # por versión: puede estar parcheado por el distribuidor (backport)
                    "remediation": "Verificar versión real/backports y actualizar el componente."})
    return out

async def get_kev(c):
    global _kev
    if time.time() - _kev[0] > 86400:
        try:
            r = await c.get(KEV); r.raise_for_status()
            _kev = (time.time(), {v["cveID"] for v in r.json()["vulnerabilities"]})
        except Exception: pass
    return _kev[1]

async def get_epss(c, cves):
    todo = [x for x in cves if x not in _epss]
    for i in range(0, len(todo), 50):
        chunk = todo[i:i + 50]
        try:
            r = await c.get(EPSS, params={"cve": ",".join(chunk)}); r.raise_for_status()
            for d in r.json().get("data", []): _epss[d["cve"]] = float(d["epss"])
        except Exception: pass
        for x in chunk: _epss.setdefault(x, 0.0)
    return _epss

async def enrich(findings):
    async with httpx.AsyncClient(timeout=30, headers={"User-Agent": "vulnerscan/0.1"}) as c:
        out = []
        for f in findings:
            out.extend(await expand(c, f) if f.get("cpe") and not f.get("cves") else [f])
        cves = sorted({x for f in out for x in f.get("cves", [])})
        kev, eps = await get_kev(c), await get_epss(c, cves)
        for f in out:
            f["kev"] = any(x in kev for x in f.get("cves", []))
            f["epss"] = max([eps.get(x, 0) for x in f.get("cves", [])] or [0])
        return out
