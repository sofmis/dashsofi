import nmap
from fastapi import FastAPI
from common import finding

app = FastAPI()
DEFAULT_PORTS = "1-1024,1433,1521,2375,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017"
RISKY = {"telnet": ("high", "Telnet expuesto (credenciales en texto plano)"),
         "ms-wbt-server": ("high", "RDP expuesto a la red"),
         "microsoft-ds": ("medium", "SMB expuesto a la red"),
         "ftp": ("medium", "FTP expuesto (texto plano)"),
         "vnc": ("high", "VNC expuesto"),
         "redis": ("high", "Redis expuesto (a menudo sin autenticación)"),
         "memcached": ("high", "Memcached expuesto"),
         "mongodb": ("high", "MongoDB expuesto"),
         "docker": ("critical", "API de Docker expuesta")}

def parse_ports(spec):
    out = []
    for p in spec.split(","):
        a, _, b = p.partition("-")
        out += range(int(a), int(b or a) + 1)
    return out

def scapy_syn(host, ports):
    """Pre-filtro SYN sigiloso con Scapy (requiere NET_RAW). Nunca completa el handshake."""
    from scapy.all import IP, TCP, sr, conf
    conf.verb = 0
    ans, _ = sr(IP(dst=host) / TCP(dport=ports, flags="S"), timeout=2, retry=1)
    return sorted(r[TCP].dport for _, r in ans if r.haslayer(TCP) and int(r[TCP].flags) & 0x12 == 0x12)

@app.post("/scan")
def scan(req: dict):
    target, o = req["target"], req.get("options", {})
    ports, meta, findings = o.get("ports", DEFAULT_PORTS), {"http_urls": []}, []
    if o.get("scapy_prefilter") and "/" not in target:
        try:
            op = scapy_syn(target, parse_ports(ports)); meta["scapy_open"] = op
            if not op: return {"findings": [], "meta": meta}
            ports = ",".join(map(str, op))
        except Exception as e:
            meta["scapy_error"] = str(e)
    nm = nmap.PortScanner()
    nm.scan(hosts=target, ports=ports, arguments="-sV --version-light -T4 -Pn")
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, d in nm[host][proto].items():
                if d["state"] != "open": continue
                name, banner = d.get("name", ""), " ".join(x for x in (d.get("product"), d.get("version")) if x)
                cpe = (d.get("cpe") or "").split()[0] if d.get("cpe") else None
                if cpe and cpe.count(":") < 4: cpe = None       # sin versión no sirve para NVD
                findings.append(finding("network", f"service-{name}-{port}", f"Servicio {name} en {port}/{proto}", "info",
                                        host, port=port, evidence=f"{name} {banner}".strip(), cpe=cpe, confidence=0.9))
                if name in RISKY:
                    sev, title = RISKY[name]
                    findings.append(finding("network", f"exposed-{name}", title, sev, host, port=port,
                                            evidence=f"Puerto {port}/{proto} abierto", confidence=0.85,
                                            remediation="Restringir con firewall/VPN y exigir autenticación fuerte."))
                if "http" in name:
                    scheme = "https" if d.get("tunnel") == "ssl" or name == "https" else "http"
                    meta["http_urls"].append(f"{scheme}://{host}:{port}")
    return {"findings": findings, "meta": meta}
