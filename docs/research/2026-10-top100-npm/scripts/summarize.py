"""Compute every number the report cites, from the raw data files, into data/summary.json."""
import json, glob, collections, statistics, sys
from pathlib import Path
from mcp_audit.models import ServerConfig, TransportType, ServerEnumeration
from mcp_audit.analyzers.collision import detect_tool_collisions
from mcp_audit.registry.loader import load_registry

S = {}
corpus = json.load(open('data/corpus.json'))['entries']
from mcp_audit.registry.loader import BUNDLED_REGISTRY_PATH
reg = json.load(open(BUNDLED_REGISTRY_PATH))['entries']
regnames = {e['name'] for e in reg}
S['corpus'] = dict(
    n=len(corpus), weekly_downloads_total=sum(e['weekly'] for e in corpus),
    top=corpus[0]['name'], top_weekly=corpus[0]['weekly'], cutoff_weekly=corpus[-1]['weekly'],
    attested=sum(e['attestations'] for e in corpus),
    attested_weekly=sum(e['weekly'] for e in corpus if e['attestations']),
    zero_major=sum(e['latest'].startswith('0.') for e in corpus),
    prerelease=[e['name'] + '@' + e['latest'] for e in corpus if '-' in e['latest']],
    deprecated=sum(e['deprecated'] for e in corpus),
    scoped=sum(e['name'].startswith('@') for e in corpus),
    official=[e['name'] for e in corpus if e['name'].startswith('@modelcontextprotocol/')],
    in_registry=sorted(e['name'] for e in corpus if e['name'] in regnames),
    latest_older_than_6mo=[(e['name'], e['time_latest'][:10]) for e in corpus if e['time_latest'][:10] < '2026-04-22'],
    unattested=[e['name'] for e in corpus if not e['attestations']],
)

# ---- live enumeration ----
recs = {}
for d in ('data/enum', 'data/enum2', 'data/enum3'):
    for f in glob.glob(d + '/*.json'):
        if f.endswith('_runtime_findings.json'): continue
        r = json.load(open(f)); r['pass'] = d[-1] if d[-1].isdigit() else '1'
        good = not r['error'] and not r['tools_error']
        if r['package'] not in recs or good: recs[r['package']] = r
ok = [r for r in recs.values() if not r['error'] and not r['tools_error']]
cls = json.load(open('data/failure-classification.json'))
for p in list(cls):
    if p in {r['package'] for r in ok}: del cls[p]
failed = {r['package']: cls.get(r['package'], ('UNCLASSIFIED', ''))[0] for r in recs.values() if r not in ok}
S['connect'] = dict(
    attempted=len(recs), connected=len(ok), connected_default_invocation=sum(1 for r in ok if r['pass'] == '1'),
    connected_adjusted_invocation=sum(1 for r in ok if r['pass'] != '1'),
    failed=len(failed), failure_classes=dict(collections.Counter(failed.values())),
    failed_detail={p: cls[p] for p in cls},
    credential_gated=sorted(p for p, c in failed.items() if c == 'credential-gated'),
)
tools = [(r['package'], t) for r in ok for t in r['tools']]
cnt = sorted(((len(r['tools']), r['package']) for r in ok), reverse=True)
dl = [len(t.get('description') or '') for _, t in tools]
ann = [t for _, t in tools if t.get('annotations')]
names = collections.Counter(t['name'] for _, t in tools)
per = collections.Counter()
for p, t in tools: per[p] += len(json.dumps(t))
S['tools'] = dict(
    total=len(tools), per_server_median=statistics.median([c for c, _ in cnt]), per_server_mean=round(statistics.mean([c for c, _ in cnt]), 1),
    top10=cnt[:10], ge50=sum(1 for c, _ in cnt if c >= 50), ge20=sum(1 for c, _ in cnt if c >= 20), le5=sum(1 for c, _ in cnt if c <= 5),
    desc_chars_total=sum(dl), desc_median=statistics.median(dl), desc_ge2000=sum(1 for x in dl if x >= 2000), desc_ge2000_servers=sorted({p for p, t in tools if len(t.get('description') or '') >= 2000}),
    desc_empty=sum(1 for x in dl if x == 0),
    def_json_bytes_total=sum(len(json.dumps(t)) for _, t in tools), largest_by_bytes=per.most_common(8),
    with_annotations=len(ann), servers_with_annotations=len({p for p, t in tools if t.get('annotations')}),
    annotation_keys=dict(collections.Counter(k for t in ann for k in t['annotations'])),
    readonly_true=sum(1 for t in ann if t['annotations'].get('readOnlyHint') is True),
    destructive_true=sum(1 for t in ann if t['annotations'].get('destructiveHint') is True),
    with_output_schema=sum(1 for _, t in tools if t.get('output_schema')), with_title=sum(1 for _, t in tools if t.get('title')),
    distinct_names=len(names), shared_names=sorted([(n, c) for n, c in names.items() if c >= 2], key=lambda x: -x[1]),
    longest=sorted(((len(t.get('description') or ''), p, t['name']) for p, t in tools), reverse=True)[:8],
)
# official COLLIDE-001 across every connected server
def cfg(p): return ServerConfig(name=p, client='corpus', config_path=Path('/corpus/mcp.json'), transport=TransportType.STDIO, command='npx', args=['-y', p])
pairs = [(cfg(r['package']), ServerEnumeration(**{k: v for k, v in r.items() if k in ServerEnumeration.model_fields})) for r in ok]
coll = [f.model_dump(mode='json') for f in detect_tool_collisions(pairs, registry=load_registry())]
S['collisions'] = dict(count=len(coll), by_severity=dict(collections.Counter(f['severity'] for f in coll)), items=[(f['title'], f['severity'], f['evidence'][:200]) for f in coll])

# ---- runtime poisoning (mcp-audit's own analysis of the live definitions) ----
pf = []
for d in ('data/enum', 'data/enum2', 'data/enum3'):
    pf += json.load(open(d + '/_runtime_findings.json'))['runtime_poisoning']
S['poisoning'] = dict(total=len(pf), by_id=dict(collections.Counter(f['id'] for f in pf)), by_id_sev={f['id']: f['severity'] for f in pf},
                      by_package=collections.Counter(f['package'] for f in pf).most_common(12),
                      p060_packages=dict(collections.Counter(f['package'] for f in pf if f['id'] == 'POISON-060')),
                      p060_evidence_sample=sorted({f['evidence'].strip() for f in pf if f['id'] == 'POISON-060'})[:12],
                      p030_evidence=dict(collections.Counter(f['evidence'].strip().replace('Matched: ', '') for f in pf if f['id'] == 'POISON-030')),
                      p012_p020=[(f['id'], f['package'], f['evidence'].strip()) for f in pf if f['id'] in ('POISON-012', 'POISON-020')],
                      p050_servers=len({f['package'] for f in pf if f['id'] == 'POISON-050'}))

# ---- static scan of the 100-server config ----
st = json.load(open('data/static-scan.json'))
S['static'] = dict(findings=len(st['findings']), score=st['score']['numeric'], grade=st['score']['grade'],
                   by_id=dict(collections.Counter(x['id'] for x in st['findings'])),
                   sc=[(x['id'], x['severity'], x['title']) for x in st['findings'] if x['id'].startswith('SC-')],
                   toxic=dict(collections.Counter(x['id'] for x in st['findings'] if x['id'].startswith(('TOXIC', 'INTEG')))))

# ---- dependency advisories (deps.dev graph + OSV) ----
rows = json.load(open('data/vuln-rows.json')); osv = json.load(open('data/osv-advisories.json')); dg = json.load(open('data/depsdev-graphs.json'))
resolved = [k for k, v in dg.items() if v['ok']]
sdkv = collections.Counter(v['sdk'][0] for v in dg.values() if v['ok'] and v['sdk'])
bysrv = collections.defaultdict(list)
for r in rows: bysrv[r['server']].append(r)
worst = collections.Counter()
for s, rs in bysrv.items():
    sevs = {r['sev'] for r in rs}; worst['HIGH' if 'HIGH' in sevs else 'MODERATE' if 'MODERATE' in sevs else 'LOW'] += 1
sdk = [r for r in rows if r['pkg'] == '@modelcontextprotocol/sdk']
adv = {i: dict(published=a.get('published', '')[:10], summary=a.get('summary'), sev=(a.get('database_specific') or {}).get('severity'), aliases=a.get('aliases'),
               ranges=[(x['package']['name'], x.get('ranges', [{}])[0].get('events')) for x in a.get('affected', [])][:3]) for i, a in osv.items()}
S['vulns'] = dict(
    depsdev_resolved=len(resolved), depsdev_404=sorted(k for k, v in dg.items() if not v['ok']),
    graph_nodes_median=statistics.median([v['nodes'] for v in dg.values() if v['ok']]), graph_nodes_max=max(v['nodes'] for v in dg.values() if v['ok']),
    servers_depending_on_sdk=sum(1 for v in dg.values() if v['ok'] and v['sdk']), sdk_versions=dict(sdkv.most_common()),
    advisory_rows=len(rows), distinct_advisories=len(osv), advisories_by_sev=dict(collections.Counter(a['sev'] for a in adv.values())),
    servers_affected=len(bysrv), servers_by_worst=dict(worst), servers_affected_list=sorted(bysrv),
    sdk_rows=len(sdk), sdk_servers=sorted({r['server'] for r in sdk}), sdk_by_adv=dict(collections.Counter(r['osv'] for r in sdk)),
    sdk_affected_versions=dict(collections.Counter(r['ver'] for r in sdk)),
    key_advisories={i: adv[i] for i in ('GHSA-46jr-4wx8-v453', 'GHSA-22jm-h49p-29qw', 'GHSA-6qxp-vccf-f47h', 'GHSA-w48q-cv73-mx4w', 'GHSA-345p-7cg4-v4c7', 'GHSA-8r9q-7v3j-jr4g', 'GHSA-rvq5-wwqv-78pq', 'GHSA-6prh-2h8m-c8cw') if i in adv},
    servers_hit_by={i: sorted({r['server'] for r in rows if r['osv'] == i}) for i in ('GHSA-46jr-4wx8-v453', 'GHSA-22jm-h49p-29qw', 'GHSA-6qxp-vccf-f47h', 'GHSA-w48q-cv73-mx4w')},
    affected_packages_top=collections.Counter(r['pkg'] for r in rows).most_common(12),
    non_sdk_high=dict(collections.Counter((r['pkg']) for r in rows if r['sev'] == 'HIGH' and not r['pkg'].startswith('@modelcontextprotocol'))),
)
json.dump(S, open('data/summary.json', 'w'), indent=1, default=str)
print(json.dumps({k: (v if k != 'tools' else {kk: vv for kk, vv in v.items() if kk not in ('shared_names',)}) for k, v in S.items()}, indent=1, default=str)[:12000])
