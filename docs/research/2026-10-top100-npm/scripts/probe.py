"""For servers mcp-audit could not enumerate, spawn them once, send an MCP initialize, and capture
exit code + stderr so the failure reason is recorded (mcp-audit drops stderr on a failed handshake)."""
import json, subprocess, sys, glob, os, time
from concurrent.futures import ThreadPoolExecutor
out = {}
recs = [json.load(open(f)) for f in glob.glob(sys.argv[1] + '/*.json') if not f.endswith('_runtime_findings.json')]
fails = [r for r in recs if r['error']]
INIT = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-audit-probe", "version": "0"}}}) + "\n"
SAFE = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TERM", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "TMPDIR", "USER")}
def probe(r):
    cmd = ["npx", "-y", f"{r['package']}@{r['version']}"]
    t = time.time()
    try:
        p = subprocess.run(cmd, input=INIT, capture_output=True, text=True, timeout=25, env=SAFE)
        rc, so, se = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc, so, se = "timeout", (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), (e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
    return r['package'], {"rc": rc, "elapsed": round(time.time() - t, 1), "stdout_head": so[:400], "stderr": se[-2500:]}
with ThreadPoolExecutor(3) as ex:
    for name, res in ex.map(probe, fails):
        out[name] = res
        print(name, res['rc'], res['elapsed'], (res['stderr'].strip().splitlines() or [''])[-1][:120], flush=True)
json.dump(out, open(sys.argv[2], 'w'), indent=1)
