"""Chromium headless: ejecuta el JS como un usuario, descubre rutas SPA, endpoints XHR/fetch y librerías cliente."""
from urllib.parse import urlparse

JS = """() => ({jquery: (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) || null,
  angular: (document.querySelector('[ng-version]') || {getAttribute: () => null}).getAttribute('ng-version'),
  react: !!(window.__REACT_DEVTOOLS_GLOBAL_HOOK__ && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.size)})"""

def render(url, timeout_ms=25000):
    from playwright.sync_api import sync_playwright
    origin, api = urlparse(url).netloc, set()
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        page = b.new_context(user_agent="vulnerscan/0.1 (+authorized-security-assessment)").new_page()
        page.on("request", lambda r: api.add(r.url) if r.resource_type in ("xhr", "fetch") and urlparse(r.url).netloc == origin else None)
        page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        page.mouse.wheel(0, 4000); page.wait_for_timeout(800)
        links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        libs = page.evaluate(JS)
        b.close()
    return {"api_urls": sorted(api), "links": sorted({l for l in links if urlparse(l).netloc == origin}), "libs": libs}
