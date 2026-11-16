"""Page the official MCP Registry and keep the latest version of each server that ships an npm or PyPI package."""
import json, sys, time, urllib.parse, urllib.request
BASE = "https://registry.modelcontextprotocol.io/v0/servers"
def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-audit-corpus/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)
servers, cursor, pages = [], None, 0
while True:
    q = {"limit": 100, "version": "latest"}
    if cursor: q["cursor"] = cursor
    d = get(BASE + "?" + urllib.parse.urlencode(q)); pages += 1
    servers += d.get("servers", [])
    cursor = (d.get("metadata") or {}).get("nextCursor")
    if not cursor: break
    time.sleep(0.1)
out = []
for s in servers:
    srv = s["server"]; meta = (s.get("_meta") or {}).get("io.modelcontextprotocol.registry/official", {})
    if meta.get("status") not in (None, "active"): continue
    for p in srv.get("packages") or []:
        rt = p.get("registryType")
        if rt in ("npm", "pypi"):
            out.append({"server": srv["name"], "server_version": srv.get("version"), "registry_type": rt,
                        "identifier": p.get("identifier"), "package_version": p.get("version"),
                        "transport": (p.get("transport") or {}).get("type"), "description": srv.get("description", "")})
json.dump({"fetched": time.strftime("%Y-%m-%d"), "pages": pages, "servers_seen": len(servers), "packages": out},
          open(sys.argv[1], "w"), indent=1)
print("servers", len(servers), "npm/pypi packages", len(out),
      "npm", sum(p["registry_type"] == "npm" for p in out), "pypi", sum(p["registry_type"] == "pypi" for p in out))
