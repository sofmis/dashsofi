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


def _windows_findings(data, asset):
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
        meta["note"] = ("Windows: cotejo básico (EOL + postura de actualización). "
                        "El cotejo de software por CVE requiere MSRC/NVD (siguiente iteración).")
        findings += _windows_findings(data, asset)

    return {"findings": findings, "meta": meta}
