"""Q-045 summary (only the 100 corpus packages are counted): corpus, live pass, tools, collisions, runtime poisoning, static scan.

Same aggregates as docs/research/2026-10-top100-npm/scripts/summarize.py for the
sections re-measured; the dependency (deps.dev/OSV) and Semgrep passes were not
re-run. One change: each server's runtime findings are taken once, from the pass
whose enumeration is used (the 10-22 script added every pass's findings).
"""
import collections, glob, json, re, statistics
from pathlib import Path
from mcp_audit.models import ServerConfig, TransportType, ServerEnumeration
from mcp_audit.analyzers.collision import detect_tool_collisions
from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
from mcp_audit.mcp_client import build_runtime_server_config
from mcp_audit.registry.loader import load_registry, BUNDLED_REGISTRY_PATH

S = {}
corpus = json.load(open('data/corpus.json'))['entries']
regnames = {e['name'] for e in json.load(open(BUNDLED_REGISTRY_PATH))['entries']}
S['corpus'] = dict(n=len(corpus), weekly_downloads_total=sum(e['weekly'] for e in corpus),
    top=corpus[0]['name'], top_weekly=corpus[0]['weekly'], cutoff_weekly=corpus[-1]['weekly'],
    attested=sum(bool(e.get('attestations')) for e in corpus), zero_major=sum(e['latest'].startswith('0.') for e in corpus),
    scoped=sum(e['name'].startswith('@') for e in corpus), in_registry=sum(e['name'] in regnames for e in corpus))
inst = json.load(open('data/install.json'))
recs = {}
names = {e['name'] for e in corpus}
# Pass 1: default invocation; later passes: adjusted arguments (overrides).
PASSES = (('data/enum', '1'), ('data/enum-add', '1'), ('data/enum2', '2'), ('data/enum3', '3'), ('data/enum-add2', '2'))
for d, pnum in PASSES:
    for f in glob.glob(d + '/*.json'):
        if f.endswith('_runtime_findings.json'): continue
        r = json.load(open(f)); r['pass'] = pnum
        if r['package'] not in names: continue
        good = not r['error'] and not r['tools_error']
        if r['package'] not in recs or (good and (recs[r['package']]['error'] or recs[r['package']]['tools_error'])):
            recs[r['package']] = r
for e in corpus:
    if e['name'] not in recs:
        recs[e['name']] = {'package': e['name'], 'version': e['latest'], 'error': 'not run: ' + inst.get(e['name'], {}).get('err', 'not installed'), 'tools_error': None, 'tools': [], 'pass': '1'}
ok = [r for r in recs.values() if not r['error'] and not r['tools_error']]
def classify(r):
    t = (r['error'] or r['tools_error'] or '').lower()
    if t.startswith('not run') or inst.get(r['package'], {}).get('rc', 0) != 0: return 'install-failed'
    if re.search(r'enotfound|eai_again|getaddrinfo|fetch failed|econnrefused|network', t): return 'needs-network'
    if re.search(r'api[_ ]?key|token|credential|auth|login|unauthori|configure|setup|\benv var|environment variable|is not set|secret|password|required', t): return 'credential-gated'
    if re.search(r'usage:|--help|unknown command|subcommand|commands:', t): return 'cli-wrapper'
    if re.search(r'project|directory|workspace|no such file|enoent', t): return 'needs-project'
    return 'no-handshake'
failed = {r['package']: classify(r) for r in recs.values() if r not in ok}
S['connect'] = dict(attempted=len(recs), connected=len(ok),
    connected_default_invocation=sum(1 for r in ok if r['pass'] == '1'),
    connected_adjusted_invocation=sum(1 for r in ok if r['pass'] != '1'),
    failed=len(failed), failure_classes=dict(collections.Counter(failed.values())),
    classification_method='automatic, from each failure message (the 10-22 run classified by hand)')
tools = [(r['package'], t) for r in ok for t in r['tools']]
cnt = sorted(((len(r['tools']), r['package']) for r in ok), reverse=True)
dl = [len(t.get('description') or '') for _, t in tools]
S['tools'] = dict(total=len(tools), per_server_median=statistics.median([c for c, _ in cnt]),
    per_server_mean=round(statistics.mean([c for c, _ in cnt]), 1), ge50=sum(1 for c, _ in cnt if c >= 50),
    desc_chars_total=sum(dl), desc_median=statistics.median(dl), desc_ge2000=sum(1 for x in dl if x >= 2000),
    def_json_bytes_total=sum(len(json.dumps(t)) for _, t in tools),
    with_annotations=sum(1 for _, t in tools if t.get('annotations')))
def cfg(p): return ServerConfig(name=p, client='corpus', config_path=Path('/corpus/mcp.json'), transport=TransportType.STDIO, command='npx', args=['-y', p])
pairs = [(cfg(r['package']), ServerEnumeration(**{k: v for k, v in r.items() if k in ServerEnumeration.model_fields})) for r in ok]
coll = [f.model_dump(mode='json') for f in detect_tool_collisions(pairs, registry=load_registry())]
S['collisions'] = dict(count=len(coll), by_severity=dict(collections.Counter(f['severity'] for f in coll)))
pa = PoisoningAnalyzer(); pf = []
for s, en in pairs:
    rc = build_runtime_server_config(s, en)
    if rc is None: continue
    for fd in pa.analyze(rc):
        d = fd.model_dump(mode='json'); d['package'] = s.name; pf.append(d)
json.dump(pf, open('data/poison-findings-private.json', 'w'), indent=1)
S['poisoning'] = dict(total=len(pf), by_id=dict(collections.Counter(f['id'] for f in pf)),
    by_id_sev={f['id']: f['severity'] for f in pf},
    servers_with_findings=len({f['package'] for f in pf}),
    p060_evidence_sample=sorted({f['evidence'].strip() for f in pf if f['id'] == 'POISON-060'})[:12],
    p030_evidence=dict(collections.Counter(f['evidence'].strip().replace('Matched: ', '') for f in pf if f['id'] == 'POISON-030')),
    p012_p020=[(f['id'], f['evidence'].strip()) for f in pf if f['id'] in ('POISON-012', 'POISON-020')],
    p050_servers=len({f['package'] for f in pf if f['id'] == 'POISON-050'}))
st = json.load(open('data/static-scan.json'))
S['static'] = dict(findings=len(st['findings']), score=st['score']['numeric'], grade=st['score']['grade'],
    by_id=dict(collections.Counter(x['id'] for x in st['findings'])))
json.dump(S, open('data/summary.json', 'w'), indent=1, default=str)
print(json.dumps({k: S[k] for k in ('connect', 'tools', 'collisions', 'poisoning')}, indent=1, default=str)[:5000])
