def severity_from_cvss(s):
    if s is None: return "info"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "info"
