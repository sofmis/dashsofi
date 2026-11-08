"""Cálculo del Base Score CVSS v3.0/3.1 a partir del vector.

OSV suele traer la severidad como vector (`CVSS:3.1/AV:N/...`) y a veces una
etiqueta cualitativa. Convertir el vector a número permite reutilizar la misma
priorización (EPSS/KEV/CVSS) que el resto del orquestador.
"""
import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope sin cambios
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # Scope cambiado


def _roundup(x):
    # "Roundup" oficial: redondea hacia arriba a 1 decimal (v3.0 y v3.1).
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score(vector):
    """Devuelve el Base Score (float) o None si el vector no es CVSS v3."""
    if not vector or "CVSS:3" not in vector:
        return None
    m = {}
    for part in vector.split("/"):
        k, _, val = part.partition(":")
        if val:
            m[k] = val
    try:
        scope_changed = m.get("S") == "C"
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_changed else 1.0) * (impact + expl), 10)
    return _roundup(raw)
