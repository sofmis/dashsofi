"""Renderizado con Chromium (ejecuta el JS como un usuario) para SPAs: React, Angular, APIs.

Recorre las rutas del MISMO origen (BFS) y descubre enlaces, endpoints XHR/fetch y librerías.
Reglas de seguridad (el renderizado ejecuta código de la página, así que se limita):
- Solo peticiones GET al mismo origen. Todo lo demás (POST/PUT/DELETE, terceros, analítica) se bloquea.
- No se envían formularios ni se pulsan botones: solo se navega por enlaces <a href> del mismo origen.
- Presupuesto de rutas y tiempos limitados.
Limitación conocida: rutas que solo existen tras pulsar botones o con history.pushState sin enlace
en el DOM no se descubren (no se simulan interacciones que puedan cambiar estado)."""
import os
from collections import deque
from urllib.parse import urldefrag, urlparse

UA = "vulnerscan/0.2 (+authorized-security-assessment)"
ALLOWED_TYPES = {"document", "script", "stylesheet", "image", "font", "xhr", "fetch", "other"}

JS = """() => ({jquery: (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) || null,
  angular: (document.querySelector('[ng-version]') || {getAttribute: () => null}).getAttribute('ng-version'),
  react: !!(window.__REACT_DEVTOOLS_GLOBAL_HOOK__ && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.size)})"""


def same_origin(url, origin):
    p = urlparse(url)
    return p.scheme in ("http", "https") and p.netloc == origin


def render_site(start, max_routes=30, timeout_ms=20000, executable_path=None):
    from playwright.sync_api import sync_playwright
    origin = urlparse(start).netloc
    api, blocked, routes, forms = set(), set(), [], []
    libs = {}
    queue, seen = deque([urldefrag(start)[0]]), set()
    exe = executable_path or os.getenv("CHROMIUM_PATH") or None
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"], executable_path=exe)
        ctx = b.new_context(user_agent=UA)

        def guard(route):
            req = route.request
            if req.method == "GET" and same_origin(req.url, origin) and req.resource_type in ALLOWED_TYPES:
                return route.continue_()
            # Solo se registra el host y el método, nunca la URL completa (puede llevar datos).
            blocked.add(f"{req.method} {urlparse(req.url).netloc}")
            return route.abort()

        ctx.route("**/*", guard)
        page = ctx.new_page()
        page.on("request", lambda r: api.add(urldefrag(r.url)[0])
                if r.resource_type in ("xhr", "fetch") and r.method == "GET" and same_origin(r.url, origin) else None)

        while queue and len(routes) < max_routes:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception as e:
                routes.append({"url": url, "error": str(e).splitlines()[0][:160]})
                continue
            page.wait_for_timeout(400)
            if not libs:
                libs = page.evaluate(JS)
            for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)"):
                nxt = urldefrag(href)[0]
                if same_origin(nxt, origin) and nxt not in seen:
                    queue.append(nxt)
            forms.extend(page.eval_on_selector_all(
                "form", "fs => fs.map(f => ({method: (f.method || 'get').toLowerCase(), action: f.action}))"))
            routes.append({"url": url, "status": resp.status if resp else None, "title": page.title()[:120]})
        b.close()
    return {"routes": routes, "api_urls": sorted(api), "blocked": sorted(blocked), "libs": libs, "forms": forms}
