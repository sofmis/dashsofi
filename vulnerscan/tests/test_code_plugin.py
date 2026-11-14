"""Pruebas offline del plugin de código (Trivy / Semgrep / detect-secrets).

No necesita Docker ni las herramientas instaladas: se simulan sus salidas.
Ejecutar:  python tests/test_code_plugin.py   (requiere fastapi)"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [f"{ROOT}/plugins", f"{ROOT}/plugins/code"]

import app as code                      # noqa: E402  (plugin de código)
from fastapi import HTTPException      # noqa: E402

FAILS = []


def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), name, "" if cond else extra)
    if not cond:
        FAILS.append(name)


def image_fixture():
    """Imagen con 3 capas reales; ENV/CMD no crean capa (empty_layer)."""
    import json
    return json.dumps({
        "Metadata": {"ImageConfig": {
            "rootfs": {"diff_ids": ["sha256:aaa", "sha256:bbb", "sha256:ccc"]},
            "history": [
                {"created_by": "/bin/sh -c #(nop) ADD file:xyz in /"},
                {"created_by": "/bin/sh -c #(nop)  ENV PATH=/usr/bin", "empty_layer": True},
                {"created_by": "/bin/sh -c apt-get update && apt-get install -y curl"},
                {"created_by": "/bin/sh -c #(nop)  CMD [\"nginx\"]", "empty_layer": True},
                {"created_by": "COPY app/ /srv"}]}},
        "Results": [{"Target": "nginx:1.21 (debian 11.3)",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2023-0001", "PkgName": "curl", "InstalledVersion": "7.74.0",
                 "FixedVersion": "7.88.1", "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": 8.1}},
                 "Layer": {"DiffID": "sha256:bbb"}},
                {"VulnerabilityID": "CVE-2023-0002", "PkgName": "zlib", "InstalledVersion": "1.2.11",
                 "Severity": "LOW", "Layer": {}}],
            "Secrets": [{"StartLine": 12, "Title": "AWS Access Key"}],
            "Misconfigurations": [{"ID": "DS002", "Title": "Usuario root", "Severity": "HIGH",
                                   "Message": "USER no definido", "Resolution": "Usar USER no root"}]}]})


def test_layers():
    out = code.parse_trivy(image_fixture(), "nginx:1.21")
    by = {f["rule_id"]: f for f in out}
    curl = by["CVE-2023-0001"]
    check("capa: índice y total", curl["layer_index"] == 2 and curl["layer_total"] == 3, str(curl.get("layer_index")))
    check("capa: instrucción del Dockerfile", "RUN apt-get update" in curl["evidence"], curl["evidence"])
    check("capa: texto 'capa 2/3'", "capa 2/3" in curl["evidence"], curl["evidence"])
    check("capa: severidad y CVSS", curl["severity"] == "high" and curl["cvss"] == 8.1)
    check("capa: versión corregida", "7.88.1" in curl["remediation"])
    zl = by["CVE-2023-0002"]
    check("sin capa conocida no inventa capa", "capa" not in zl["evidence"], zl["evidence"])


def test_secret_and_misconfig():
    out = code.parse_trivy(image_fixture(), "nginx:1.21")
    sec = [f for f in out if f["rule_id"].startswith("secret@")]
    mis = [f for f in out if f["rule_id"] == "DS002"]
    check("secreto: severidad alta", len(sec) == 1 and sec[0]["severity"] == "high")
    check("secreto: no guarda el valor", "AKIA" not in str(sec), str(sec))
    check("mala configuración detectada", len(mis) == 1 and mis[0]["severity"] == "high")


def test_fs_without_metadata():
    import json
    raw = json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-9999", "PkgName": "requests", "InstalledVersion": "2.19.0",
         "Severity": "CRITICAL"}]}]})
    out = code.parse_trivy(raw, "/workspace/app")
    check("fs sin Metadata funciona", len(out) == 1 and out[0]["severity"] == "critical")
    check("fs sin capas: sin campos de capa", "layer_index" not in out[0])


def test_invalid_output_is_error():
    try:
        code.parse_trivy("esto no es json", "x")
        check("salida inválida se reporta como error", False)
    except RuntimeError as e:
        check("salida inválida se reporta como error", "salida no válida" in str(e), str(e))


def test_tool_failures_are_errors():
    try:
        code.sh(["false"])
        check("código de salida distinto de 0 falla", False)
    except RuntimeError as e:
        check("código de salida distinto de 0 falla", "código 1" in str(e), str(e))
    try:
        code.sh(["herramienta-que-no-existe-xyz"])
        check("herramienta ausente se reporta", False)
    except RuntimeError as e:
        check("herramienta ausente se reporta", "no instalada" in str(e), str(e))


def test_endpoint_maps_errors_to_502():
    real = code.sh

    def boom(*a, **k):
        raise RuntimeError("trivy terminó con código 2: DB no disponible")
    code.sh = boom
    try:
        code.scan({"target": "image:nginx:1.21", "options": {"type": "container"}})
        check("error de herramienta llega como 502", False)
    except HTTPException as e:
        check("error de herramienta llega como 502", e.status_code == 502 and "código 2" in str(e.detail), str(e.detail))
    finally:
        code.sh = real


def test_input_guards():
    for target, label in [("/workspace/../etc", "ruta fuera de /workspace"), ("http://example.com/x", "URL no https")]:
        try:
            code.scan_repo(target)
            check(f"rechaza {label}", False)
        except HTTPException as e:
            check(f"rechaza {label}", e.status_code == 400, str(e.status_code))


if __name__ == "__main__":
    for fn in (test_layers, test_secret_and_misconfig, test_fs_without_metadata,
               test_invalid_output_is_error, test_tool_failures_are_errors,
               test_endpoint_maps_errors_to_502, test_input_guards):
        fn()
    print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
    sys.exit(1 if FAILS else 0)
