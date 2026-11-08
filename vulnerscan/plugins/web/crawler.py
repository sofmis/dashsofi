from urllib.parse import urldefrag, urljoin, urlparse
import requests
from bs4 import BeautifulSoup

def crawl(s, start, max_pages=40, max_depth=2, timeout=10):
    origin, seen, queue, pages = urlparse(start).netloc, set(), [(start, 0)], []
    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        url = urldefrag(url)[0]
        if url in seen: continue
        seen.add(url)
        try: r = s.get(url, timeout=timeout)
        except requests.RequestException: continue
        if urlparse(r.url).netloc != origin: continue
        try: cookies = r.raw.headers.getlist("Set-Cookie")
        except Exception: cookies = []
        page = {"url": r.url, "status": r.status_code, "headers": dict(r.headers), "cookies": cookies, "forms": []}
        if "html" in r.headers.get("Content-Type", "") and depth < max_depth:
            soup = BeautifulSoup(r.text, "lxml")
            for a in soup.select("a[href]"):
                nxt = urljoin(r.url, a["href"])
                if urlparse(nxt).scheme in ("http", "https") and urlparse(nxt).netloc == origin: queue.append((nxt, depth + 1))
            for f in soup.find_all("form"):
                page["forms"].append({"method": (f.get("method") or "get").lower(), "action": urljoin(r.url, f.get("action") or r.url),
                                      "inputs": {i.get("name"): i.get("value") or "" for i in f.select("input[name],textarea[name],select[name]")}})
        pages.append(page)
    return pages
