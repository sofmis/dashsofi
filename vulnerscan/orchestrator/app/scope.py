"""Control de alcance: falla cerrado. Solo se escanea lo que esté en ALLOWED_TARGETS."""
import ipaddress, os, re, socket
from urllib.parse import urlparse

ALLOWED = [x.strip().lower() for x in os.getenv("ALLOWED_TARGETS", "").split(",") if x.strip()]
MAX_HOSTS = int(os.getenv("MAX_HOSTS", "256"))
REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)

def detect_type(t: str):
    t = t.strip()
    if t.startswith(("ssh:", "winrm:")): return "osaudit"
    if t.startswith("image:"): return "container"
    if t.startswith("/workspace/") or t.endswith(".git"): return "repo"
    if "://" in t:
        return "repo" if (urlparse(t).hostname or "").lower() in REPO_HOSTS else "web"
    try:
        ipaddress.ip_network(t, strict=False); return "network"
    except ValueError:
        pass
    return "host" if DOMAIN_RE.match(t) or t == "localhost" else None

def host_of(t: str) -> str:
    t = t.strip()
    if t.startswith(("ssh:", "winrm:")):
        rest = t.split(":", 1)[1]
        return (urlparse("//" + rest.lstrip("/")).hostname or "").lower()
    if "://" in t: return (urlparse(t).hostname or "").lower()
    try:
        ipaddress.ip_network(t, strict=False); return t
    except ValueError:
        return t.split("/")[0].lower()

def in_scope(target: str) -> bool:
    h = host_of(target)
    try:
        net = ipaddress.ip_network(h, strict=False)
    except ValueError:
        try: net = ipaddress.ip_network(socket.gethostbyname(h) + "/32")
        except OSError: net = None
    if net is not None and net.num_addresses > MAX_HOSTS:
        return False
    for rule in ALLOWED:
        try:
            rn = ipaddress.ip_network(rule, strict=False)
            if net is not None and net.version == rn.version and net.subnet_of(rn): return True
        except ValueError:
            if h == rule or h.endswith("." + rule): return True
    return False
