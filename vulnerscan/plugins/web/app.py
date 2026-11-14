from urllib.parse import urlparse
import requests
from fastapi import FastAPI
from common import finding
import apiprobe, checks, crawler, fuzz, render

app = FastAPI()


@app.post("/scan")
def scan(req: dict):
    url, o = req["target"], req.get("options", {})
    if "://" not in url:
        url = "https://" + url
    origin = urlparse(url).netloc
    s = requests.Session()
    s.headers["User-Agent"] = render.UA
    pages = crawler.crawl(s, url, o.get("max_pages", 40), o.get("max_depth", 2))
    findings, meta, extra = checks.passive(pages, url), {"pages": len(pages)}, []
    if o.get("render", True):
        try:
            r = render.render_site(url, max_routes=o.get("max_routes", 30))
            meta["render"] = {"routes": len(r["routes"]), "api_endpoints": len(r["api_urls"]),
                              "blocked_requests": r["blocked"], "libs": r["libs"],
                              "forms_seen": len(r["forms"]),
                              "route_errors": [x for x in r["routes"] if "error" in x][:5]}
            extra = r["api_urls"] + [x["url"] for x in r["routes"] if "?" in x["url"]]
            findings += apiprobe.probe(s, r["api_urls"], origin, budget=o.get("api_budget", 20))
            jq = r["libs"].get("jquery")
            if jq:
                findings.append(finding("web", "lib-jquery", "jQuery detectado en el cliente", "info", url,
                                        evidence=f"jQuery {jq}", cpe=f"cpe:/a:jquery:jquery:{jq}", confidence=0.9))
        except Exception as e:
            meta["render_error"] = str(e)[:300]
    findings += fuzz.run(s, pages, extra, o.get("fuzz_budget", 300), o.get("delay", 0.1), o.get("fuzz_post", False))
    return {"findings": findings, "meta": meta}
