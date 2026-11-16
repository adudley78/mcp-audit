"""For each PyPI candidate: latest version, summary, release times and console_scripts entry points (read from the wheel)."""
import io, json, sys, urllib.request, zipfile
from concurrent.futures import ThreadPoolExecutor
def get(url, raw=False):
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-audit-corpus/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read() if raw else json.load(r)
def one(c):
    e = {"name": c["project"], "downloads_30d": c["download_count"]}
    try:
        d = get(f"https://pypi.org/pypi/{c['project']}/json")
    except Exception as ex:
        e["error"] = str(ex); return e
    info = d["info"]; v = info["version"]
    e.update(latest=v, summary=info.get("summary") or "", requires_python=info.get("requires_python"),
             project_urls=info.get("project_urls"), yanked=info.get("yanked"))
    e["release_times"] = {ver: min((f["upload_time_iso_8601"] for f in fs), default=None)
                          for ver, fs in d["releases"].items() if fs}
    wheels = [f for f in d["urls"] if f["packagetype"] == "bdist_wheel"]
    wheels.sort(key=lambda f: ("none-any" not in f["filename"], f["filename"]))
    e["console_scripts"] = None
    if wheels:
        e["wheel"] = wheels[0]["filename"]; e["wheel_sha256"] = wheels[0]["digests"]["sha256"]
        try:
            z = zipfile.ZipFile(io.BytesIO(get(wheels[0]["url"], raw=True)))
            ep = [n for n in z.namelist() if n.endswith(".dist-info/entry_points.txt")]
            scripts, sect = [], None
            if ep:
                for line in z.read(ep[0]).decode().splitlines():
                    line = line.strip()
                    if line.startswith("["): sect = line.strip("[]"); continue
                    if sect == "console_scripts" and "=" in line: scripts.append(line.split("=")[0].strip())
            e["console_scripts"] = scripts
        except Exception as ex:
            e["wheel_error"] = str(ex)
    return e
cands = json.load(open(sys.argv[1]))
with ThreadPoolExecutor(12) as ex:
    res = list(ex.map(one, cands))
json.dump(res, open(sys.argv[2], "w"), indent=1)
print("probed", len(res))
