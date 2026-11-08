import re
from common import finding

HDRS = [("content-security-policy", "Falta Content-Security-Policy", "medium", "CWE-693"),
        ("x-content-type-options", "Falta X-Content-Type-Options: nosniff", "low", "CWE-693"),
        ("referrer-policy", "Falta Referrer-Policy", "low", "CWE-200")]
CPE = {"apache": "cpe:/a:apache:http_server:{v}", "nginx": "cpe:/a:nginx:nginx:{v}"}

def passive(pages, base):
    out = []
    if pages:
        h = {k.lower(): v for k, v in pages[0]["headers"].items()}
        for name, title, sev, cwe in HDRS:
            if name not in h:
                out.append(finding("web", f"missing-{name}", title, sev, base, cwe=cwe, confidence=0.9,
                                   evidence="Cabecera ausente en la página principal", remediation=f"Configurar {name}."))
        if "frame-ancestors" not in h.get("content-security-policy", "") and "x-frame-options" not in h:
            out.append(finding("web", "missing-clickjacking", "Sin protección contra clickjacking", "medium", base, cwe="CWE-1021", confidence=0.85,
                               remediation="X-Frame-Options o CSP frame-ancestors."))
        if base.startswith("https") and "strict-transport-security" not in h:
            out.append(finding("web", "missing-hsts", "Falta HSTS", "medium", base, cwe="CWE-319", confidence=0.9))
        m = re.match(r"(apache|nginx)/(\d+(?:\.\d+)+)", h.get("server", ""), re.I)
        if m:
            out.append(finding("web", "server-banner", "Versión del servidor revelada", "info", base, cwe="CWE-200",
                               evidence=h["server"], cpe=CPE[m[1].lower()].format(v=m[2]), confidence=0.8))
    for p in pages:
        for c in p["cookies"]:
            low, name = c.lower(), c.split("=")[0]
            miss = [f for f, ok in (("Secure", "secure" in low), ("HttpOnly", "httponly" in low), ("SameSite", "samesite" in low)) if not ok]
            if miss:
                out.append(finding("web", f"cookie-flags-{name}", f"Cookie '{name}' sin {', '.join(miss)}", "low", base,
                                   cwe="CWE-1004", confidence=0.9, evidence=p["url"]))
    return out
