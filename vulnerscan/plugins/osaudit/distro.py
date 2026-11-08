"""Mapeo de la identidad del SO (os-release / Windows) al ecosistema OSV.

OSV expone bases por distribución cuya *versión corregida* ya contempla los
backports del distribuidor. Por eso un hallazgo aquí es "confirmado" y no
"potencial por versión" como el cotejo NVD/CPE.
"""
import re

# ---- Linux: os-release -> ecosistema OSV --------------------------------
# Cobertura fiable en OSV: Debian, Ubuntu, Alpine, Rocky Linux, AlmaLinux.
# RHEL/CentOS/SUSE se marcan como "best-effort" (ecosistema aproximado).
_RELIABLE = {"Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux"}


def _major(version_id):
    m = re.match(r"\d+", version_id or "")
    return m.group(0) if m else ""


def _major_minor(version_id):
    m = re.match(r"\d+\.\d+", version_id or "")
    return m.group(0) if m else _major(version_id)


def linux_ecosystem(osrel):
    """(ecosystem|None, reliable:bool, note:str). osrel = dict de /etc/os-release."""
    oid = (osrel.get("ID") or "").lower()
    like = (osrel.get("ID_LIKE") or "").lower()
    vid = osrel.get("VERSION_ID") or ""

    if oid == "ubuntu":
        mm = _major_minor(vid)
        # LTS = versiones .04 de año par (18.04, 20.04, 22.04, 24.04...).
        try:
            yr, mo = (int(x) for x in mm.split("."))
            lts = mo == 4 and yr % 2 == 0
        except ValueError:
            lts = False
        return (f"Ubuntu:{mm}:LTS" if lts else f"Ubuntu:{mm}", True, "")
    if oid == "debian" or "debian" in like and oid not in ("ubuntu",):
        mj = _major(vid)
        return ((f"Debian:{mj}", True, "") if mj else
                (None, False, "Debian sin VERSION_ID numérico (testing/sid): sin ecosistema OSV"))
    if oid == "alpine":
        return (f"Alpine:v{_major_minor(vid)}", True, "")
    if oid == "rocky":
        return (f"Rocky Linux:{_major(vid)}", True, "")
    if oid in ("almalinux", "alma"):
        return (f"AlmaLinux:{_major(vid)}", True, "")
    # best-effort para familia RHEL / SUSE
    if oid in ("rhel", "centos", "redhat", "ol", "oracle") or "rhel" in like or "fedora" in like:
        return ("Red Hat", False,
                "RHEL/CentOS/Oracle: cotejo OSV aproximado; para precisión usa el feed OVAL del fabricante")
    if oid in ("sles", "sled", "opensuse-leap", "opensuse", "suse") or "suse" in like:
        return ("SUSE", False, "SUSE: cotejo OSV aproximado")
    return (None, False, f"Distribución '{oid or 'desconocida'}' sin mapeo a ecosistema OSV")


def is_reliable_ecosystem(eco):
    return bool(eco) and eco.split(":", 1)[0] in _RELIABLE


# ---- Fin de soporte (EOL) -----------------------------------------------
# Un SO sin soporte no recibe parches: es un hallazgo por sí mismo.
# Fechas de fin de mantenimiento estándar (no ESM/pago). AAAA-MM-DD.
LINUX_EOL = {
    "ubuntu": {"18.04": "2023-05-31", "20.04": "2025-05-29", "21.10": "2022-07-14",
               "22.10": "2023-07-20", "23.04": "2024-01-25", "23.10": "2024-07-11"},
    "debian": {"9": "2022-06-30", "10": "2024-06-30", "11": "2026-08-31"},
    "alpine": {"3.14": "2023-05-01", "3.15": "2023-11-01", "3.16": "2024-05-23",
               "3.17": "2024-11-22", "3.18": "2025-05-09"},
    "centos": {"7": "2024-06-30", "8": "2021-12-31"},
    "rocky": {"8": "2029-05-31"},
}

# Windows: build RTM -> (nombre, fecha fin de soporte). Solo hitos finalizados
# o próximos; informativo, no exhaustivo.
WINDOWS_EOL = {
    "7601": ("Windows 7 / Server 2008 R2", "2020-01-14"),
    "9200": ("Windows 8 / Server 2012", "2023-10-10"),
    "9600": ("Windows 8.1 / Server 2012 R2", "2023-10-10"),
    "10240": ("Windows 10 1507", "2017-05-09"),
    "14393": ("Windows 10 1607 / Server 2016", "2027-01-12"),
    "15063": ("Windows 10 1703", "2018-10-09"),
    "17134": ("Windows 10 1803", "2019-11-12"),
    "17763": ("Windows 10 1809 / Server 2019", "2029-01-09"),
    "18362": ("Windows 10 1903", "2020-12-08"),
    "19041": ("Windows 10 2004", "2021-12-14"),
    "19042": ("Windows 10 20H2", "2023-05-09"),
    "19044": ("Windows 10 21H2", "2024-06-11"),
}
