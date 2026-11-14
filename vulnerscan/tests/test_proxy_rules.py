"""Pruebas de las reglas del proxy (lógica pura). Ejecutar:  python tests/test_proxy_rules.py"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [f"{ROOT}/plugins/proxy"]
import rules as R  # noqa: E402

FAILS = []
ALLOWED = ["testphp.vulnweb.com", "localhost"]


def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), name, "" if cond else extra)
    if not cond:
        FAILS.append(name)


def rule(host, **acts):
    return {"match": {"host": host}, **acts}


def main():
    ok, notes = R.load_rules([rule("testphp.vulnweb.com", set_headers={"X-Test": "1"})], ALLOWED)
    check("regla válida en alcance se acepta", len(ok) == 1 and not notes, str(notes))

    ok, notes = R.load_rules([rule("otro-sitio.com", set_headers={"X": "1"})], ALLOWED)
    check("regla fuera de alcance se descarta", ok == [] and any("no está en ALLOWED_TARGETS" in n for n in notes), str(notes))

    ok, notes = R.load_rules([rule("api.localhost", block=True)], ALLOWED)
    check("subdominio de un host permitido sí cuenta", len(ok) == 1, str(notes))

    ok, notes = R.load_rules([{"match": {"host": "localhost"}, "eval": "rm -rf /"}], ALLOWED)
    check("claves desconocidas invalidan la regla (no se ejecuta nada)", ok == [] and any("desconocidas" in n for n in notes),
          str(notes))

    ok, notes = R.load_rules([{"match": {"host": "localhost"}, "set_headers": {"X": "1"}, "bogus": 1}], ALLOWED)
    check("clave extra con acción válida también se rechaza", ok == [], str(notes))

    ok, notes = R.load_rules([{"match": {"host": "localhost", "path_regex": "("}, "block": True}], ALLOWED)
    check("regex inválida descarta la regla", ok == [] and any("path_regex inválida" in n for n in notes), str(notes))

    ok, notes = R.load_rules([{"match": {"host": "localhost"}}], ALLOWED)
    check("regla sin acción se descarta", ok == [] and any("no define ninguna acción" in n for n in notes), str(notes))

    ok, notes = R.load_rules([{"match": {}, "block": True}], ALLOWED)
    check("regla sin host se descarta", ok == [] and any("falta match.host" in n for n in notes), str(notes))

    ok, notes = R.load_rules({"no": "lista"}, ALLOWED)
    check("formato incorrecto se rechaza", ok == [] and notes, str(notes))

    ok, notes = R.load_rules([rule("localhost", block=True)], [])
    check("alcance vacío descarta todas las reglas", ok == [], str(notes))

    r = {"match": {"host": "testphp.vulnweb.com", "method": "GET", "path_regex": "^/listproducts"}, "block": True}
    check("match: host, método y ruta coinciden", R.match_rule(r, "testphp.vulnweb.com", "GET", "/listproducts?cat=1"))
    check("match: método distinto no coincide", not R.match_rule(r, "testphp.vulnweb.com", "POST", "/listproducts"))
    check("match: ruta distinta no coincide", not R.match_rule(r, "testphp.vulnweb.com", "GET", "/otra"))
    check("match: host no relacionado no coincide", not R.match_rule(r, "evil.com", "GET", "/listproducts"))
    check("match: host con puerto", R.match_rule(r, "testphp.vulnweb.com:80", "GET", "/listproducts"))

    example = os.path.join(ROOT, "plugins", "proxy", "rules.json")
    with open(example) as fh:
        ex_ok, ex_notes = R.load_rules(json.load(fh), ALLOWED)
    check("rules.json de ejemplo es válido", len(ex_ok) == 1 and not ex_notes, str(ex_notes))

    print("\n" + ("ALL PASS" if not FAILS else f"FAILURES: {FAILS}"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
