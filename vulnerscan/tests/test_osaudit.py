"""Pruebas del módulo de auditoría de SO autenticada (osaudit).

Sin red ni Docker: se simulan las respuestas de OSV y no se usan paramiko/winrm
(los colectores se importan de forma perezosa). Ejecutar:

    pip install fastapi requests pyyaml
    python tests/test_osaudit.py
"""
import datetime
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("ALLOWED_TARGETS", "10.0.0.0/24,example.com")
sys.path[:0] = [f"{ROOT}/plugins", f"{ROOT}/plugins/osaudit", f"{ROOT}/orchestrator/app"]

import scope, normalize, prioritize          # orquestador
import distro, cvss, osv                      # ayudantes osaudit
import app as oa                              # app FastAPI osaudit
from fastapi import HTTPException

FAILS = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        FAILS.append(name)


def test_cvss():
    cases = {"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
             "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
             "CVSS:2.0/AV:N/AC:L/Au:N/C:P": None}
    check("cvss base scores", all(cvss.base_score(v) == e for v, e in cases.items()))


def test_scope():
    check("detect ssh", scope.detect_type("ssh:root@10.0.0.5:22") == "osaudit")
    check("detect winrm", scope.detect_type("winrm:admin@10.0.0.9") == "osaudit")
    check("host_of ssh", scope.host_of("ssh:root@10.0.0.5:2222") == "10.0.0.5")
    check("host_of winrm //", scope.host_of("winrm://admin@10.0.0.9:5985") == "10.0.0.9")
    check("in_scope allow ip", scope.in_scope("ssh:root@10.0.0.5") is True)
    check("in_scope deny ip", scope.in_scope("ssh:root@192.168.1.5") is False)
    check("in_scope allow domain", scope.in_scope("winrm:adm@host.example.com") is True)


def test_parse_target():
    check("parse ssh", oa.parse_target("ssh:bob@h.example.com:2200") == ("ssh", "bob", "h.example.com", 2200))
    check("parse winrm", oa.parse_target("winrm:10.0.0.9") == ("winrm", None, "10.0.0.9", None))
    for bad in ("http:foo", "ssh:bad host!", "ssh:"):
        try:
            oa.parse_target(bad)
            check(f"reject {bad!r}", False)
        except HTTPException:
            check(f"reject {bad!r}", True)


def test_eol():
    oa._TODAY = datetime.date(2026, 11, 8)
    f = oa._eol_finding_linux({"ID": "ubuntu", "VERSION_ID": "18.04"}, "ssh://h")
    check("linux EOL flagged", bool(f) and f["severity"] == "high")
    check("linux non-EOL none", oa._eol_finding_linux({"ID": "debian", "VERSION_ID": "12"}, "ssh://h") is None)
    wf = oa._windows_findings({"os": {"BuildNumber": "9600"},
                               "hotfixes": [{"HotFixID": "KB1", "InstalledOn": "2020-01-01"}]}, "winrm://h")
    rules = {x["rule_id"] for x in wf}
    check("win EOL flagged", any(r.startswith("eol-win") for r in rules))
    check("win stale flagged", "win-stale-updates" in rules)
    wf2 = oa._windows_findings({"os": {"BuildNumber": "19045"}, "hotfixes": []}, "winrm://h")
    check("win no-hotfix flagged", any(x["rule_id"] == "win-no-hotfix" for x in wf2))


def _fake_osv():
    class R:
        def __init__(s, j): s._j = j; s.status_code = 200
        def json(s): return s._j
        def raise_for_status(s): pass

    class S:
        headers = types.SimpleNamespace(update=lambda *a, **k: None)
        def __enter__(s): return s
        def __exit__(s, *a): return False
        def post(s, url, json=None, timeout=None):
            res = [{"vulns": [{"id": "CVE-2024-0001"}]} if q["package"]["name"] == "libc6" else {}
                   for q in json["queries"]]
            return R({"results": res})
        def get(s, url, timeout=None):
            return R({"id": "CVE-2024-0001", "aliases": ["CVE-2024-0001"], "summary": "Fallo en libc6",
                      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                      "affected": [{"package": {"name": "libc6", "ecosystem": "Ubuntu:22.04:LTS"},
                                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.35-0ubuntu3.8"}]}]}]})
    return S


def test_osv_and_pipeline():
    osv.requests.Session = lambda: _fake_osv()()
    pkgs = [("libc6", "2.35-0ubuntu3.6", "amd64"), ("bash", "5.1-6ubuntu1", "amd64")]
    found = osv.scan_packages(pkgs, "Ubuntu:22.04:LTS", "ssh://h", reliable=True)
    check("osv one finding", len(found) == 1)
    g = found[0]
    check("osv cve/cvss", g["cves"] == ["CVE-2024-0001"] and g["cvss"] == 9.8 and g["severity"] == "critical")
    check("osv fixed in remediation", "2.35-0ubuntu3.8" in g["remediation"])
    check("osv confidence", g["confidence"] == 0.9)
    raw = found + [oa._eol_finding_linux({"ID": "ubuntu", "VERSION_ID": "18.04"}, "ssh://h")]
    pri = prioritize.prioritize(normalize.normalize(raw))
    check("pipeline ok", len(pri) == 2 and all("priority" in x and "verification" in x for x in pri))
    check("confirmed verification", any(x["verification"].startswith("confirmado") for x in pri))


if __name__ == "__main__":
    for fn in (test_cvss, test_scope, test_parse_target, test_eol, test_osv_and_pipeline):
        fn()
    print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
    sys.exit(1 if FAILS else 0)
