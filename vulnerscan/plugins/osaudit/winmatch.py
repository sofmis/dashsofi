"""Software de Windows -> CPE (para que el orquestador expanda CPE->CVE vía NVD).

Mapa conservador: solo productos conocidos con una correspondencia CPE fiable.
El software no reconocido queda como inventario (sin cotejo), para no inventar
CVE a partir de nombres ambiguos (menos falsos positivos).
"""
import re

# clave: subcadena en minúsculas del DisplayName -> "vendor:product" (CPE 2.3)
# El orden importa: la primera coincidencia gana (poner lo específico antes).
_MAP = [
    ("google chrome", "google:chrome"),
    ("microsoft edge", "microsoft:edge"),
    ("mozilla firefox", "mozilla:firefox"),
    ("mozilla thunderbird", "mozilla:thunderbird"),
    ("adobe acrobat reader", "adobe:acrobat_reader"),
    ("adobe acrobat", "adobe:acrobat"),
    ("7-zip", "7-zip:7-zip"),
    ("notepad++", "notepad-plus-plus:notepad-plus-plus"),
    ("vlc media player", "videolan:vlc_media_player"),
    ("wireshark", "wireshark:wireshark"),
    ("putty", "putty:putty"),
    ("filezilla", "filezilla:filezilla"),
    ("winrar", "rarlab:winrar"),
    ("oracle vm virtualbox", "oracle:vm_virtualbox"),
    ("virtualbox", "oracle:vm_virtualbox"),
    ("libreoffice", "libreoffice:libreoffice"),
    ("openvpn", "openvpn:openvpn"),
    ("openssl", "openssl:openssl"),
    ("nodejs", "nodejs:node.js"),
    ("node.js", "nodejs:node.js"),
    ("git version", "git:git"),
    ("postgresql", "postgresql:postgresql"),
    ("mysql", "oracle:mysql"),
    ("nginx", "nginx:nginx"),
    ("apache http server", "apache:http_server"),
    ("python", "python:python"),
    ("zoom", "zoom:meetings"),
    ("teamviewer", "teamviewer:teamviewer"),
]
_VER = re.compile(r"\d+(?:\.\d+){0,3}")


def clean_version(dv):
    if not dv:
        return None
    m = _VER.search(str(dv))
    return m.group(0) if m else None


def software_to_cpe(name, version, publisher=None):
    """Devuelve (cpe23, vendor, product) o None si el software no está mapeado."""
    n = (name or "").lower()
    for needle, vp in _MAP:
        if needle in n:
            ver = clean_version(version) or "*"
            vendor, product = vp.split(":", 1)
            return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*", vendor, product
    return None
