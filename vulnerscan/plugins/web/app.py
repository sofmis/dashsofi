import requests
from fastapi import FastAPI
from common import finding
import checks, crawler, fuzz, render

app = FastAPI()

@app.post("/scan")
def scan(req: dict):
    url, o = req["target"], req.get("options", {})
    if "://" not in url: url = "https://" + url
    s = requests.Session()
    s.headers["User-Agent"] = "vulnerscan/0.1 (+authorized-security-assessment)"
    pages = crawler.crawl(s, url, o.get("max_pages", 40), o.get("max_depth", 2))
    findings, meta, extra = checks.passive(pages, url), {"pages": len(pages)}, []
    if o.get("render", True):
        try:
            r = render.render(url)
            extra = r["api_urls"] + [l for l in r["links"] if "?" in l]
            meta["render"] = {"api_endpoints": len(r["api_urls"]), "libs": r["libs"]}
            jq = r["libs"].get("jquery")
            if jq:
                findings.append(finding("web", "lib-jquery", "jQuery detectado en el cliente", "info", url, evidence=f"jQuery {jq}",
                                        cpe=f"cpe:/a:jquery:jquery:{jq}", confidence=0.9))
        except Exception as e:
            meta["render_error"] = str(e)
    findings += fuzz.run(s, pages, extra, o.get("fuzz_budget", 300), o.get("delay", 0.1), o.get("fuzz_post", False))
    return {"findings": findings, "meta": meta}
