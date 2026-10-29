"""Install each corpus package into its own prefix as the unprivileged `probe` user.

--ignore-scripts: no package code runs at install time. Network only via the
registry proxy; the runtime pass has no network at all.
"""
import json, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
corpus = json.load(open(sys.argv[1]))["entries"]
out = {}
def slug(n): return n.replace("/", "__").replace("@", "")
def one(e):
    prefix = f"/srv/probe/pkgs/{slug(e['name'])}"
    env = {"HOME": "/srv/probe", "PATH": "/opt/node22/bin:/usr/bin:/bin",
           "HTTPS_PROXY": os.environ.get("HTTPS_PROXY", ""), "HTTP_PROXY": os.environ.get("HTTP_PROXY", ""),
           "npm_config_cafile": "/srv/probe/ca.crt", "npm_config_cache": "/srv/probe/.npm"}
    cmd = ["runuser", "-u", "probe", "--", "env", "-i", *[f"{k}={v}" for k, v in env.items()],
           "npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error",
           "--prefix", prefix, f"{e['name']}@{e['latest']}"]
    if os.path.isdir(prefix + "/node_modules/.bin"):
        return e["name"], {"rc": 0, "err": "already installed"}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return e["name"], {"rc": 124, "err": "install timed out after 900s"}
    return e["name"], {"rc": p.returncode, "err": p.stderr[-600:]}
with ThreadPoolExecutor(6) as ex:
    for name, r in ex.map(one, corpus):
        out[name] = r; print(name, r["rc"], flush=True)
json.dump(out, open(sys.argv[2], "w"), indent=1)
print("ok", sum(1 for r in out.values() if r["rc"] == 0), "of", len(out))
