"""Fuente nativa de Microsoft (MSRC / Security Update Guide, CVRF v3.0).

Más preciso que el CPE genérico para los parches del SO/Office: usa los
documentos CVRF mensuales de Microsoft, que listan por producto (build) los CVE
y los KB que los corrigen.

Heurística para evitar falsos positivos sin reconstruir la cadena de
supersedencia: solo se consideran los boletines de meses POSTERIORES al último
hotfix instalado en el host; si para su producto existe una actualización de
seguridad cuyo KB no está instalado, se marca como parche faltante (potencial,
confianza 0.5, a confirmar con Windows Update/WSUS).
"""
import re

import requests

UPDATES = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
HDRS = {"Accept": "application/json", "User-Agent": "vulnerscan-osaudit/0.1"}

# build RTM -> subcadenas de nombre de producto en el ProductTree de MSRC.
BUILD_TO_PRODUCT = {
    "19045": ["Windows 10 Version 22H2"],
    "19044": ["Windows 10 Version 21H2"],
    "19043": ["Windows 10 Version 21H1"],
    "19042": ["Windows 10 Version 20H2"],
    "22631": ["Windows 11 Version 23H2"],
    "22621": ["Windows 11 Version 22H2"],
    "22000": ["Windows 11 Version 21H2"],
    "17763": ["Windows Server 2019", "Windows 10 Version 1809"],
    "20348": ["Windows Server 2022"],
    "14393": ["Windows Server 2016", "Windows 10 Version 1607"],
    "26100": ["Windows 11 Version 24H2", "Windows Server 2025"],
}
_KB = re.compile(r"(\d{6,8})")   # nº de artículo KB (6-8 dígitos), con o sin prefijo "KB"


def kb_digits(s):
    """'KB5031234' / 'Security Update 5031234' -> '5031234'."""
    m = _KB.search(str(s or ""))
    return m.group(1) if m else None


def installed_kb_set(hotfixes):
    out = set()
    for h in hotfixes or []:
        d = kb_digits(h.get("HotFixID") if isinstance(h, dict) else h)
        if d:
            out.add(d)
    return out


def resolve_product_ids(doc, hints):
    """ProductIDs del ProductTree cuyo nombre contiene alguna pista (x64 por defecto)."""
    ids = set()
    tree = (doc.get("ProductTree") or {}).get("FullProductName") or []
    hints_l = [h.lower() for h in hints]
    for prod in tree:
        val = str(prod.get("Value", "")).lower()
        if any(h in val for h in hints_l) and "x64" in val:
            ids.add(str(prod.get("ProductID")))
    # si no hay variante x64 explícita, acepta cualquier coincidencia
    if not ids:
        for prod in tree:
            val = str(prod.get("Value", "")).lower()
            if any(h in val for h in hints_l):
                ids.add(str(prod.get("ProductID")))
    return ids


def _affected_ids(vuln):
    out = set()
    for ps in vuln.get("ProductStatuses") or []:
        if ps.get("Type") == 3:            # 3 = Known Affected
            out.update(str(x) for x in (ps.get("ProductID") or []))
    return out


def _cvss_for(vuln, pids):
    best = None
    for s in vuln.get("CVSSScoreSets") or []:
        sp = {str(x) for x in (s.get("ProductID") or [])}
        if not sp or sp & pids:
            try:
                v = float(s.get("BaseScore"))
            except (TypeError, ValueError):
                continue
            if best is None or v > best[0]:
                best = (v, s.get("Vector"))
    return best or (None, None)


def _fix_kbs(vuln, pids):
    kbs = set()
    for r in vuln.get("Remediations") or []:
        if r.get("Type") != 2:             # 2 = Vendor Fix
            continue
        rp = {str(x) for x in (r.get("ProductID") or [])}
        if rp and not (rp & pids):
            continue
        d = kb_digits((r.get("Description") or {}).get("Value"))
        if d:
            kbs.add(d)
    return kbs


def parse_cvrf(doc, product_ids, installed_kbs):
    """-> [{cve, cvss, vector, kb, title}] de CVE cuyo KB no está instalado."""
    out = []
    pids = {str(x) for x in product_ids}
    if not pids:
        return out
    for v in doc.get("Vulnerability") or []:
        cve = v.get("CVE")
        if not cve or not (_affected_ids(v) & pids):
            continue
        kbs = _fix_kbs(v, pids)
        if not kbs or (kbs & installed_kbs):   # sin parche, o ya instalado
            continue
        cvss, vector = _cvss_for(v, pids)
        out.append({"cve": cve, "cvss": cvss, "vector": vector,
                    "kb": sorted(kbs)[0], "title": (v.get("Title") or {}).get("Value") or cve})
    return out


def _month_key(iso):
    m = re.match(r"(\d{4})-(\d{2})", str(iso or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


def list_updates_after(session, after_key, months_max):
    """IDs/URLs de CVRF con fecha posterior a after_key=(año,mes), más recientes primero."""
    r = session.get(UPDATES, headers=HDRS, timeout=30)
    r.raise_for_status()
    rows = []
    for u in r.json().get("value", []):
        k = _month_key(u.get("CurrentReleaseDate") or u.get("InitialReleaseDate"))
        url = u.get("CvrfUrl") or (UPDATES.rsplit("/", 1)[0] + "/cvrf/" + str(u.get("ID")))
        if k and (after_key is None or k > after_key):
            rows.append((k, url))
    rows.sort(reverse=True)
    return [url for _k, url in rows[:months_max]]


def scan(build, hotfixes, last_patch_date=None, months_max=3, session=None):
    """Devuelve (findings_dicts, nota). Defensivo: cualquier fallo -> ([], nota)."""
    hints = BUILD_TO_PRODUCT.get(str(build or ""))
    if not hints:
        return [], f"MSRC: build {build} sin mapeo de producto; omitido."
    installed = installed_kb_set(hotfixes)
    after = _month_key(last_patch_date) if last_patch_date else None
    close = False
    if session is None:
        session = requests.Session()
        close = True
    try:
        urls = list_updates_after(session, after, months_max)
        seen, found = set(), []
        for url in urls:
            r = session.get(url, headers=HDRS, timeout=45)
            if r.status_code != 200:
                continue
            doc = r.json()
            pids = resolve_product_ids(doc, hints)
            for f in parse_cvrf(doc, pids, installed):
                if f["cve"] in seen:
                    continue
                seen.add(f["cve"])
                found.append(f)
        note = (f"MSRC: {len(found)} parche(s) de seguridad no detectado(s) en {len(urls)} boletín(es)."
                if found else "MSRC: sin parches de seguridad faltantes detectados.")
        return found, note
    except requests.RequestException as e:
        return [], f"MSRC no disponible ({type(e).__name__}); se usa el cotejo CPE/NVD."
    finally:
        if close:
            session.close()
