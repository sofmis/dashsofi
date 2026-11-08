"""Normalización + deduplicación: un mismo fallo reportado por varios plugins se fusiona."""
from collections import defaultdict
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def key(f):
    ident = ",".join(sorted(f.get("cves") or [])) or f["rule_id"]
    return (f["asset"].lower().rstrip("/"), f.get("port"), ident.lower())

def normalize(raw):
    groups = defaultdict(list)
    for f in raw: groups[key(f)].append(f)
    out = []
    for items in groups.values():
        m = dict(max(items, key=lambda x: (RANK[x["severity"]], x.get("confidence", 0))))
        m["sources"] = sorted({i["plugin"] for i in items})
        m["cves"] = sorted({c for i in items for c in i.get("cves", [])})
        scores = [i["cvss"] for i in items if i.get("cvss") is not None]
        m["cvss"] = max(scores) if scores else None
        ev = []
        for i in items:
            if i.get("evidence") and i["evidence"] not in ev: ev.append(i["evidence"])
        m["evidence"] = " | ".join(ev)[:1500]
        m["confidence"] = round(min(0.99, m.get("confidence", 0.7) + 0.15 * (len({i["plugin"] for i in items}) - 1)), 2)
        out.append(m)
    return out
