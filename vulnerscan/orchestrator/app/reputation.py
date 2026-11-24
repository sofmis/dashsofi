"""Reputación de URLs: análisis PASIVO. Nunca se contacta el sitio analizado.

Fuentes:
- VirusTotal (API v3): solo se consultan informes ya existentes. NO se envía la URL a
  analizar (eso haría que VirusTotal visite el sitio).
- Google Safe Browsing (v4): consulta de coincidencias con listas de amenazas.
- Señales locales de la propia URL (IP como host, punycode, '@', subdominios, TLD de alto abuso).

Sin API key una fuente aparece como "sin clave": nunca se inventa un veredicto.
Un veredicto "sin detecciones" NO garantiza que la URL sea segura."""
import base64
import os
import re
from urllib.parse import urlparse

import httpx

VT_BASE = os.getenv("VT_BASE", "https://www.virustotal.com/api/v3")
GSB_BASE = os.getenv("GSB_BASE", "https://safebrowsing.googleapis.com/v4")
TIMEOUT = 15
MAX_LEN = 2048
NOTE = ("Análisis pasivo: la URL no se visita. Un resultado 'sin detecciones' no garantiza "
        "que el sitio sea seguro; combina el resultado con tu criterio.")
SUSPICIOUS_TLD = {"zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "ga"}


def validate_url(url):
    """Acepta URLs con o sin esquema. Devuelve la URL normalizada o lanza ValueError."""
    u = (url or "").strip()
    if not u:
        raise ValueError("Escribe una URL")
    if len(u) > MAX_LEN:
        raise ValueError("URL demasiado larga")
    if any(c.isspace() for c in u):
        raise ValueError("La URL no puede tener espacios")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", u, re.I):
        u = "https://" + u          # casi todos los sitios usan https; VirusTotal guarda reportes por URL exacta
    p = urlparse(u)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("URL no válida (usa http:// o https://)")
    return u


def heuristics(u):
    """Señales débiles calculadas sin red. Ayudan, pero no bastan para decidir."""
    p = urlparse(u)
    host = (p.hostname or "").lower()
    reasons = []
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        reasons.append("el host es una IP, no un dominio")
    if "xn--" in host:
        reasons.append("dominio con caracteres Unicode codificados (posible suplantación)")
    if "@" in (p.netloc or ""):
        reasons.append("contiene '@' (puede ocultar el destino real)")
    if host.count(".") >= 4:
        reasons.append("muchos subdominios")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLD:
        reasons.append(f"extensión de dominio de alto abuso (.{tld})")
    if len(u) > 200:
        reasons.append("URL muy larga")
    return reasons


async def check_vt(c, u, key):
    if not key:
        return {"source": "VirusTotal", "status": "sin_clave", "detail": "Falta VT_API_KEY en .env"}
    uid = base64.urlsafe_b64encode(u.encode()).decode().rstrip("=")
    try:
        r = await c.get(f"{VT_BASE}/urls/{uid}", headers={"x-apikey": key}, timeout=TIMEOUT)
    except httpx.HTTPError as e:
        return {"source": "VirusTotal", "status": "error", "detail": f"sin conexión ({type(e).__name__})"}
    if r.status_code == 404:
        return {"source": "VirusTotal", "status": "sin_informe",
                "detail": "sin análisis previo en VirusTotal (no se envía la URL para no visitar el sitio)"}
    if r.status_code in (401, 403):
        return {"source": "VirusTotal", "status": "error", "detail": "clave rechazada por VirusTotal"}
    if r.status_code == 429:
        return {"source": "VirusTotal", "status": "error", "detail": "límite de consultas de VirusTotal alcanzado"}
    if r.status_code != 200:
        return {"source": "VirusTotal", "status": "error", "detail": f"respuesta HTTP {r.status_code}"}
    try:
        st = ((r.json().get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    except ValueError:
        return {"source": "VirusTotal", "status": "error", "detail": "respuesta ilegible"}
    mal, sus = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
    harm, und = int(st.get("harmless", 0)), int(st.get("undetected", 0))
    return {"source": "VirusTotal", "status": "ok", "malicious": mal, "suspicious": sus,
            "harmless": harm, "undetected": und,
            "detail": f"{mal} motores la marcan como maliciosa · {sus} como sospechosa · {harm} la consideran limpia"}


async def check_gsb(c, u, key):
    if not key:
        return {"source": "Google Safe Browsing", "status": "sin_clave", "detail": "Falta GSB_API_KEY en .env"}
    body = {"client": {"clientId": "vulnerscan", "clientVersion": "0.2"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                           "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": u}]}}
    try:
        r = await c.post(f"{GSB_BASE}/threatMatches:find", params={"key": key}, json=body, timeout=TIMEOUT)
    except httpx.HTTPError as e:
        return {"source": "Google Safe Browsing", "status": "error", "detail": f"sin conexión ({type(e).__name__})"}
    if r.status_code in (400, 401, 403):
        return {"source": "Google Safe Browsing", "status": "error", "detail": "clave rechazada por Google"}
    if r.status_code != 200:
        return {"source": "Google Safe Browsing", "status": "error", "detail": f"respuesta HTTP {r.status_code}"}
    try:
        matches = r.json().get("matches") or []
    except ValueError:
        return {"source": "Google Safe Browsing", "status": "error", "detail": "respuesta ilegible"}
    types = sorted({m.get("threatType", "?") for m in matches})
    return {"source": "Google Safe Browsing", "status": "ok", "matches": len(matches), "types": types,
            "detail": ("coincidencias: " + ", ".join(types)) if matches else "sin coincidencias en las listas"}


def verdict(sources, reasons):
    ok = [s for s in sources if s["status"] == "ok"]
    mal = sum(s.get("malicious", 0) for s in ok if s["source"] == "VirusTotal")
    sus = sum(s.get("suspicious", 0) for s in ok if s["source"] == "VirusTotal")
    gsb = sum(s.get("matches", 0) for s in ok if s["source"] == "Google Safe Browsing")
    if gsb > 0 or mal >= 3:
        return "maligna", "alta"
    if 1 <= mal <= 2 or sus > 0 or len(reasons) >= 2:
        return "sospechosa", "media"
    if ok:
        return "sin detecciones", "media" if len(ok) == 2 else "baja"
    return "sin datos", "ninguna"


async def analyze(url, vt_key=None, gsb_key=None):
    u = validate_url(url)
    vt_key = os.getenv("VT_API_KEY", "") if vt_key is None else vt_key
    gsb_key = os.getenv("GSB_API_KEY", "") if gsb_key is None else gsb_key
    reasons = heuristics(u)
    async with httpx.AsyncClient(headers={"User-Agent": "vulnerscan-reputation/0.2"}) as c:
        sources = [await check_vt(c, u, vt_key), await check_gsb(c, u, gsb_key)]
    label, conf = verdict(sources, reasons)
    return {"url": u, "verdict": label, "confidence": conf, "sources": sources,
            "heuristics": reasons, "note": NOTE}
