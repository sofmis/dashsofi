"""Plugin de auditoría de SO autenticada (SSH/WinRM).

Recoge inventario de paquetes (solo lectura) y lo coteja con OSV.dev usando el
ecosistema de la distribución, cuya versión corregida ya contempla backports.
Resultado: hallazgos "confirmados" con CVE/CVSS listos para KEV/EPSS.
"""
import datetime as _dt
import re
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException

from common import finding
import collectors
import distro
import osv
import winmatch
import msrc


def _sev_from_cvss(s):
    if s is None:
        return "info"
    return ("critical" if s >= 9 else "high" if s >= 7 else
            "medium" if s >= 4 else "low" if s > 0 else "info")

app = FastAPI()
HOST_RE = re.compile(r"^[A-Za-z0-9.\-_]{1,253}$")
_TODAY = None  # inyectable en tests


def _today():
    return _TODAY or _dt.date.today()


def parse_target(target):
    """ssh:[user@]host[:port] | winrm:[user@]host[:port] -> (scheme, user, host, port)."""
    scheme, _, rest = target.partition(":")
    scheme = scheme.lower()
    if scheme not in ("ssh", "winrm") or not rest:
        raise HTTPException(400, "Objetivo debe empezar por ssh: o winrm:")
    u = urlparse("//" + rest if "//" not in rest else rest)
    user = u.username
    host = u.hostname
    port = u.port
    if not host or not HOST_RE.match(host):
        raise HTTPException(400, "Host no válido en el objetivo")
    return scheme, user, host, port


def _eol_finding_linux(osrel, asset):
    oid = (osrel.get("ID") or "").lower()
    vid = osrel.get("VERSION_ID") or ""
    table = distro.LINUX_EOL.get(oid, {})
    end = table.get(vid) or table.get(re.match(r"\d+", vid).group(0) if re.match(r"\d+", vid) else vid)
    if end and end < _today().isoformat():
        return finding("osaudit", f"eol-{oid}-{vid}", f"Sistema sin soporte: {oid} {vid}",
                       "high", asset, evidence=f"Fin de mantenimiento: {end}. No recibe parches de seguridad.",
                       remediation="Actualizar a una versión con soporte.", confidence=0.95)
    return None


def _windows_findings(data, asset, cve_max=60):
    out = []
    os_info = data.get("os") or {}
    build = str(os_info.get("BuildNumber") or "")
    caption = os_info.get("Caption") or "Windows"
    name, end = distro.WINDOWS_EOL.get(build, (None, None))
    if end and end < _today().isoformat():
        out.append(finding("osaudit", f"eol-win-{build}", f"Windows sin soporte: {name or caption}",
                           "high", asset, evidence=f"Build {build}. Fin de soporte: {end}.",
                           remediation="Actualizar a una versión de Windows con soporte.", confidence=0.9))
    # Postura de actualización: antigüedad del último hotfix.
    dates = sorted(h.get("InstalledOn") for h in data.get("hotfixes") or [] if h.get("InstalledOn"))
    if not dates:
        out.append(finding("osaudit", "win-no-hotfix", "Sin hotfixes registrados",
                           "low", asset, evidence="Get-HotFix no devolvió actualizaciones.",
                           remediation="Verificar Windows Update.", confidence=0.6))
    else:
        last = dates[-1]
        age = (_today() - _dt.date.fromisoformat(last)).days
        if age > 60:
            out.append(finding("osaudit", "win-stale-updates",
                               f"Actualizaciones de Windows atrasadas (~{age} días)", "medium", asset,
                               evidence=f"Último hotfix instalado: {last}.",
                               remediation="Aplicar las actualizaciones pendientes de Windows Update.", confidence=0.7))
    # Software de terceros -> CPE (el orquestador lo expande a CVE vía NVD).
    out += _windows_software_cpe(data.get("software") or [], asset, cve_max)
    return out


def _windows_software_cpe(software, asset, cve_max):
    """Emite findings con CPE (sin CVE) para software conocido; dedupe por producto+versión."""
    out, seen = [], set()
    for s in software:
        if len(out) >= cve_max:
            break
        name = s.get("DisplayName")
        ver = s.get("DisplayVersion")
        hit = winmatch.software_to_cpe(name, ver, s.get("Publisher"))
        if not hit:
            continue
        cpe, vendor, product = hit
        if cpe in seen:
            continue
        seen.add(cpe)
        out.append(finding(
            "osaudit", f"sw-{product}-{winmatch.clean_version(ver) or 'x'}",
            f"{name} {ver or ''}".strip(), "info", asset,
            cpe=cpe, confidence=0.55, package=name, installed_version=ver or "",
            evidence=f"{name} {ver or ''} ({vendor}:{product})".strip(),
            remediation="Verificar versión real y aplicar las actualizaciones del fabricante."))
    return out


def _msrc_findings(data, os_info, asset, meta, months=3):
    """Parches de seguridad de Windows faltantes según MSRC (CVRF). Defensivo."""
    try:
        hotfixes = data.get("hotfixes") or []
        last = max([h.get("InstalledOn") for h in hotfixes if h.get("InstalledOn")] or [None])
        res, note = msrc.scan(os_info.get("BuildNumber"), hotfixes,
                              last_patch_date=last, months_max=months)
    except Exception as e:
        meta["msrc_note"] = f"MSRC error: {type(e).__name__}"
        return []
    meta["msrc_note"] = note
    out = []
    for f in res:
        out.append(finding(
            "osaudit", f"msrc-{f['cve']}", f"{f['cve']}: {f.get('title', f['cve'])}"[:140],
            _sev_from_cvss(f.get("cvss")), asset, cves=[f["cve"]], cvss=f.get("cvss"),
            confidence=0.5, advisory=f["cve"],
            evidence=f"MSRC: KB{f['kb']} (actualización de seguridad) no detectado. {f.get('title', '')}"[:400],
            remediation=f"Instalar KB{f['kb']} vía Windows Update/WSUS y verificar."))
    return out


@app.post("/scan")
def scan(req: dict):
    target = req["target"]
    o = req.get("options", {}) or {}
    scheme, user_t, host, port_t = parse_target(target)
    username = o.get("username") or user_t
    port = int(o.get("port") or port_t or (5985 if scheme == "winrm" else 22))
    if not username:
        raise HTTPException(400, "Falta 'username' en options")
    asset = f"{scheme}://{host}"
    meta = {"scheme": scheme, "host": host}
    findings = []

    if scheme == "ssh":
        try:
            inv = collectors.collect_linux(
                host, port, username,
                password=o.get("password"), key=o.get("key"),
                key_passphrase=o.get("key_passphrase"),
                known_host_key=o.get("known_host_key"),
                timeout=int(o.get("timeout") or 20))
        except Exception as e:
            raise HTTPException(502, f"SSH: {type(e).__name__}: {str(e)[:200]}")
        osrel = inv["os_release"]
        meta.update({"os": osrel.get("PRETTY_NAME") or osrel.get("ID"),
                     "packages": len(inv["packages"]), "pkg_format": inv["pkg_format"],
                     "kernel": inv.get("kernel")})
        meta["inventory"] = [{"name": n, "version": v} for (n, v, _a) in inv["packages"][:3000]]
        eco, reliable, note = distro.linux_ecosystem(osrel)
        meta["ecosystem"] = eco
        if note:
            meta["note"] = note
        eolf = _eol_finding_linux(osrel, asset)
        if eolf:
            findings.append(eolf)
        if eco and inv["packages"]:
            findings += osv.scan_packages(inv["packages"], eco, asset, reliable=reliable)
        elif not eco:
            findings.append(finding("osaudit", "no-ecosystem",
                                    "Inventario recogido sin cotejo de CVE", "info", asset,
                                    evidence=note or "Distribución sin ecosistema OSV.",
                                    confidence=0.5))
    else:  # winrm
        if not o.get("password"):
            raise HTTPException(400, "WinRM requiere 'password' en options")
        try:
            data = collectors.collect_windows(
                host, port, username, o["password"],
                use_ssl=bool(o.get("use_ssl")),
                transport=o.get("transport", "ntlm"),
                cert_validation=bool(o.get("cert_validation")),
                timeout=int(o.get("timeout") or 30))
        except Exception as e:
            raise HTTPException(502, f"WinRM: {type(e).__name__}: {str(e)[:200]}")
        os_info = data.get("os") or {}
        meta.update({"os": os_info.get("Caption"), "build": os_info.get("BuildNumber"),
                     "hotfixes": len(data.get("hotfixes") or []),
                     "software": len(data.get("software") or [])})
        meta["inventory_sw"] = [{"name": s.get("DisplayName"), "version": s.get("DisplayVersion"),
                                 "publisher": s.get("Publisher")}
                                for s in (data.get("software") or [])[:3000]]
        meta["note"] = ("Windows: EOL + postura de actualización + cotejo CVE del software "
                        "reconocido (CPE/NVD) + parches del SO vía MSRC.")
        findings += _windows_findings(data, asset, cve_max=int(o.get("win_cve_max") or 60))
        if o.get("msrc", True):
            findings += _msrc_findings(data, os_info, asset, meta, months=int(o.get("msrc_months") or 3))

    return {"findings": findings, "meta": meta}
