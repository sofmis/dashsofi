"""Reglas del proxy de interceptación (lógica pura, sin mitmproxy: fácil de probar).

Reglas de seguridad:
- Una regla solo se aplica a hosts de ALLOWED_TARGETS (alcance). Las que apuntan a otro host se
  descartan al cargar y se anota el motivo.
- Solo se aceptan acciones conocidas; cualquier clave desconocida invalida la regla (se avisa).
- Acciones: set_headers, remove_headers, set_query, replace_body, block (corta el tráfico y devuelve 403).
"""
import re

ACTIONS = {"set_headers", "remove_headers", "set_query", "replace_body", "block"}
KEYS = ACTIONS | {"match", "name"}


def in_scope_host(host, allowed):
    h = (host or "").lower().split(":")[0]
    for a in allowed:
        a = a.lower()
        if h == a or h.endswith("." + a):
            return True
    return False


def load_rules(data, allowed):
    """Valida las reglas. Devuelve (reglas válidas, avisos)."""
    if not isinstance(data, list):
        return [], ["rules.json debe contener una lista de reglas"]
    rules, notes = [], []
    for i, r in enumerate(data):
        label = f"regla {i}" + (f" ({r.get('name')})" if isinstance(r, dict) and r.get("name") else "")
        if not isinstance(r, dict):
            notes.append(f"{label}: no es un objeto"); continue
        unknown = set(r) - KEYS
        if unknown:
            notes.append(f"{label}: claves desconocidas {sorted(unknown)} (regla ignorada)"); continue
        m = r.get("match") or {}
        host = (m.get("host") or "").lower()
        if not host:
            notes.append(f"{label}: falta match.host (regla ignorada)"); continue
        if not in_scope_host(host, allowed):
            notes.append(f"{label}: {host} no está en ALLOWED_TARGETS (regla ignorada)"); continue
        if m.get("path_regex"):
            try:
                re.compile(m["path_regex"])
            except re.error as e:
                notes.append(f"{label}: path_regex inválida ({e}) (regla ignorada)"); continue
        if not any(k in r for k in ACTIONS):
            notes.append(f"{label}: no define ninguna acción (regla ignorada)"); continue
        rules.append(r)
    return rules, notes


def match_rule(rule, host, method, path):
    m = rule.get("match") or {}
    if not in_scope_host(host, [m.get("host", "")]):
        return False
    if m.get("method") and (method or "").upper() != m["method"].upper():
        return False
    if m.get("path_regex") and not re.search(m["path_regex"], path or ""):
        return False
    return True
