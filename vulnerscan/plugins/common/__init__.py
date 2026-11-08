SEVERITIES = ["info", "low", "medium", "high", "critical"]

def severity_from_cvss(score):
    if score is None: return "info"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"

def finding(plugin, rule_id, title, severity, asset, **kw):
    f = {"plugin": plugin, "rule_id": rule_id, "title": title, "severity": severity, "asset": asset,
         "port": None, "cves": [], "cvss": None, "cwe": None, "evidence": "", "remediation": "",
         "cpe": None, "confidence": 0.7}
    f.update(kw)
    return f
