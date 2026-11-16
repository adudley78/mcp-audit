"""Weekly npm downloads (last-week) for every npm package in the registry stratum.
Unscoped: bulk endpoint, 128 per request. Scoped: one request each (the bulk endpoint refuses scoped names)."""
import gzip, json, sys, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
def get(url):
    for a in range(6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mcp-audit-corpus/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404: return None
            time.sleep(2 ** a)
        except Exception:
            time.sleep(2 ** a)
    return "ERR"
ents = json.load(gzip.open(sys.argv[1], "rt"))["entries"]
names = sorted({e["package"] for e in ents if e["type"] == "npm"})
uns = [n for n in names if not n.startswith("@")]; sc = [n for n in names if n.startswith("@")]
out, errs = {}, 0
for i in range(0, len(uns), 128):
    d = get("https://api.npmjs.org/downloads/point/last-week/" + ",".join(uns[i:i+128]))
    if isinstance(d, dict):
        for k, v in d.items(): out[k] = (v or {}).get("downloads")
    else: errs += 1
def one(n):
    d = get("https://api.npmjs.org/downloads/point/last-week/" + urllib.parse.quote(n, safe="@"))
    return n, d
with ThreadPoolExecutor(8) as ex:
    for n, d in ex.map(one, sc):
        if isinstance(d, dict): out[n] = d.get("downloads")
        elif d == "ERR": errs += 1
json.dump({"fetched": time.strftime("%Y-%m-%d"), "unit": "npm last-week downloads", "errors": errs, "downloads": out},
          open(sys.argv[2], "w"))
print("npm names", len(names), "with counts", sum(v is not None for v in out.values()), "errors", errs)
