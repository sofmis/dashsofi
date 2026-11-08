"""Recolección de inventario autenticada (solo lectura).

SSH (Linux): lee /etc/os-release y la base de paquetes (dpkg/rpm/apk) con
comandos sin privilegios. WinRM (Windows): versión de SO, hotfixes y software
instalado vía PowerShell. Nunca se ejecutan comandos de escritura ni se
registran las credenciales.
"""
import io
import json

# Comandos de solo lectura. Ninguno modifica el sistema ni requiere root.
OS_RELEASE = "cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null"
PKG_CMDS = {
    "deb": r"dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' 2>/dev/null",
    "rpm": r"rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null",
    # DB canónica de apk: líneas P:<nombre> y V:<versión>.
    "apk": r"grep -E '^[PV]:' /lib/apk/db/installed 2>/dev/null",
}
MAX_PACKAGES = 8000


def parse_os_release(text):
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _pkg_format(osrel):
    oid = (osrel.get("ID") or "").lower()
    like = (osrel.get("ID_LIKE") or "").lower()
    blob = oid + " " + like
    if oid == "alpine" or "alpine" in blob:
        return "apk"
    if any(x in blob for x in ("debian", "ubuntu")):
        return "deb"
    if any(x in blob for x in ("rhel", "fedora", "centos", "suse", "rocky", "alma", "oracle")):
        return "rpm"
    return None


def _parse_packages(fmt, raw):
    pkgs = []
    if fmt == "apk":
        name = None
        for line in raw.splitlines():
            if line.startswith("P:"):
                name = line[2:].strip()
            elif line.startswith("V:") and name:
                pkgs.append((name, line[2:].strip(), ""))
                name = None
        return pkgs
    for line in raw.splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            arch = parts[2] if len(parts) > 2 else ""
            pkgs.append((parts[0].strip(), parts[1].strip(), arch.strip()))
    return pkgs


# ------------------------------- SSH -------------------------------------
def collect_linux(host, port, username, password=None, key=None,
                  key_passphrase=None, known_host_key=None, timeout=20):
    import paramiko

    client = paramiko.SSHClient()
    if known_host_key:
        # Fijación opcional de clave de host (recomendado). Formato: "ssh-ed25519 AAAA...".
        from paramiko.hostkeys import HostKeyEntry
        entry = HostKeyEntry.from_line(f"{host} {known_host_key.strip()}")
        client.get_host_keys().add(host, entry.key.get_name(), entry.key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        # Sin fijación: se acepta la clave presentada (como nmap/ssh en primer uso).
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    pkey = None
    if key:
        pkey = _load_key(key, key_passphrase)
    try:
        client.connect(hostname=host, port=port, username=username,
                       password=password or None, pkey=pkey, timeout=timeout,
                       banner_timeout=timeout, auth_timeout=timeout,
                       allow_agent=False, look_for_keys=False)
        osrel = parse_os_release(_run(client, OS_RELEASE, timeout))
        fmt = _pkg_format(osrel)
        raw = _run(client, PKG_CMDS[fmt], timeout, maxbytes=8_000_000) if fmt else ""
        pkgs = _parse_packages(fmt, raw)[:MAX_PACKAGES] if fmt else []
        return {"os_release": osrel, "pkg_format": fmt, "packages": pkgs,
                "kernel": _run(client, "uname -r 2>/dev/null", timeout).strip()[:120]}
    finally:
        client.close()


def _load_key(key_text, passphrase):
    import paramiko
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey, paramiko.DSSKey):
        try:
            return cls.from_private_key(io.StringIO(key_text), password=passphrase or None)
        except paramiko.SSHException:
            continue
    raise ValueError("Clave privada no reconocida (formatos: OpenSSH/PEM ed25519, ecdsa, rsa)")


def _run(client, cmd, timeout, maxbytes=2_000_000):
    _, stdout, _ = client.exec_command(cmd, timeout=timeout)
    data = stdout.read(maxbytes)
    return data.decode("utf-8", "replace")


# ------------------------------ WinRM ------------------------------------
# Un único script PowerShell de solo lectura que devuelve un JSON con SO,
# hotfixes y software instalado (claves de desinstalación del registro).
_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture
$hf = Get-HotFix | Select-Object HotFixID,@{n='InstalledOn';e={$_.InstalledOn.ToString('yyyy-MM-dd')}}
$paths='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
       'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$sw = Get-ItemProperty $paths | Where-Object { $_.DisplayName } |
      Select-Object DisplayName,DisplayVersion,Publisher
[pscustomobject]@{ os=$os; hotfixes=@($hf); software=@($sw) } | ConvertTo-Json -Depth 4 -Compress
"""


def collect_windows(host, port, username, password, use_ssl=False,
                    transport="ntlm", cert_validation=False, timeout=30):
    import winrm

    scheme = "https" if use_ssl else "http"
    session = winrm.Session(
        f"{scheme}://{host}:{port}/wsman",
        auth=(username, password),
        transport=transport,
        server_cert_validation="validate" if (use_ssl and cert_validation) else "ignore",
        read_timeout_sec=timeout + 10, operation_timeout_sec=timeout,
    )
    r = session.run_ps(_PS)
    if r.status_code != 0:
        raise RuntimeError("WinRM: " + (r.std_err.decode("utf-8", "replace")[:300] or "error"))
    try:
        data = json.loads(r.std_out.decode("utf-8", "replace") or "{}")
    except json.JSONDecodeError:
        raise RuntimeError("WinRM: respuesta no interpretable")
    os_info = data.get("os") or {}
    hotfixes = data.get("hotfixes") or []
    software = data.get("software") or []
    if isinstance(hotfixes, dict):
        hotfixes = [hotfixes]
    if isinstance(software, dict):
        software = [software]
    return {"os": os_info, "hotfixes": hotfixes, "software": software}
