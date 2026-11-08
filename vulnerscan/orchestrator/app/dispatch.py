import asyncio, os, httpx
from .scope import host_of

URLS = {k: os.getenv(f"PLUGIN_{k.upper()}", f"http://{k}:8000") for k in ("network", "web", "custom", "code", "osaudit")}

async def run_plan(target, ttype, modules, options, job):
    ok = lambda m: modules is None or m in modules
    raw, errors = [], []
    async with httpx.AsyncClient(timeout=3600) as c:
        async def run(mod, tgt, t):
            job["progress"].append(f"{mod} → {tgt}")
            try:
                r = await c.post(f"{URLS[mod]}/scan", json={"target": tgt, "options": {**options, "type": t}})
                r.raise_for_status(); res = r.json()
            except Exception as e:
                errors.append(f"{mod}: {e}"); return {"findings": [], "meta": {}}
            raw.extend(res.get("findings", []))
            return res

        if ttype == "osaudit":
            if ok("osaudit"): await run("osaudit", target, "osaudit")
        elif ttype in ("repo", "container"):
            if ok("code"): await run("code", target, ttype)
        elif ttype == "network":
            res = await run("network", target, "network") if ok("network") else {"meta": {}}
            urls = res.get("meta", {}).get("http_urls", [])
            await asyncio.gather(*[run(m, u, "web") for u in urls for m in ("web", "custom") if ok(m)])
        elif ttype == "web":
            await asyncio.gather(*[run(m, target, "web") for m in ("web", "custom") if ok(m)])
        else:
            url = f"https://{host_of(target)}"
            jobs = []
            if ok("network"): jobs.append(run("network", host_of(target), "network"))
            jobs += [run(m, url, "web") for m in ("web", "custom") if ok(m)]
            await asyncio.gather(*jobs)
    return raw, errors
