"""Endpoints de API descubiertos al renderizar: ¿devuelven datos JSON sin autenticación?

Solo GET, solo mismo origen, presupuesto limitado. Es un hallazgo de exposición para revisión
humana (¿deberían ser públicos estos datos?), no una prueba de explotación.
Se descartan respuestas que son errores disfrazados de 200 (login, unauthorized, forbidden)."""
import requests
from common import finding

ERROR_WORDS = ("unauthorized", "forbidden", "not authenticated", "login required", "invalid token", "no autorizado")


def probe(s, endpoints, origin, budget=20, timeout=8):
    out, checked = [], 0
    for url in endpoints:
        if checked >= budget:
            break
        checked += 1
        try:
            r = s.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        ct = r.headers.get("Content-Type", "")
        body = r.text[:2000].lower()
        if r.status_code != 200 or "json" not in ct or len(r.content) < 3:
            continue
        if any(w in body for w in ERROR_WORDS):
            continue
        out.append(finding(
            "web", f"api-open@{url}", "Endpoint de API accesible sin autenticación", "low", url,
            evidence=f"GET {url} → 200 {ct.split(';')[0]} ({len(r.content)} bytes)",
            remediation="Confirmar que estos datos deben ser públicos; si no, exigir autenticación.",
            cwe="CWE-306", confidence=0.6))
    return out
