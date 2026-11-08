"""Priorización: lo explotado activamente (KEV) y lo probable (EPSS) va primero; CVSS solo desempata."""
W = {"info": 0, "low": 2, "medium": 5, "high": 8, "critical": 10}

def score(f):
    cvss = f["cvss"] if f.get("cvss") is not None else W[f["severity"]]
    s = 15 * cvss / 10 + 30 * f.get("epss", 0) + (50 if f.get("kev") else 0)
    return round(s * (0.6 + 0.4 * f.get("confidence", 0.7)), 1)

def tier(f):
    e, c = f.get("epss", 0), f.get("cvss") or W[f["severity"]]
    if f.get("kev"): return "P0", "Explotada activamente (CISA KEV)"
    if e >= 0.2 or (e >= 0.05 and c >= 7): return "P1", f"Alta probabilidad de explotación (EPSS {e:.0%})"
    if f["severity"] in ("critical", "high"): return "P2", "Severidad alta sin señales de explotación activa"
    return ("P3", "Severidad media/baja") if f["severity"] in ("medium", "low") else ("P4", "Informativo")

def prioritize(findings):
    for f in findings:
        f["priority_score"] = score(f)
        f["priority"], f["reason"] = tier(f)
        f["verification"] = "confirmado" if f.get("confidence", 0) >= 0.8 else "potencial (requiere verificación)"
    return sorted(findings, key=lambda f: (-f["priority_score"]))

def fix_first(findings, n=3):
    return [f for f in findings if f["priority"] in ("P0", "P1", "P2")][:n]
