import json, glob, collections, re, os
NOISE = re.compile(r'(^|/)(test|tests|__tests__|spec|specs|fixtures?|examples?|example-|docs?|node_modules|dist|build|out|vendor|\.next|coverage|benchmarks?|scripts?)(/|$)|\.test\.|\.spec\.|\.min\.js$|\.d\.ts$', re.I)
repos = json.load(open('data/repos.json'))
per = {}; rule_all = collections.Counter(); rule_src = collections.Counter(); sev = {}; hits = []
timed_out = []; scanned = 0
for line in open('data/sast/_summary.txt'):
    n, rc, _ = line.split(' ', 2)
    if 'rc=0' not in rc and 'rc=1' not in rc: timed_out.append(n)
for f in sorted(glob.glob('data/sast/*.json')):
    n = os.path.basename(f)[:-5]
    try: d = json.load(open(f))
    except Exception: continue
    if n in timed_out: continue
    scanned += 1
    c = collections.Counter(); cs = collections.Counter()
    for r in d['results']:
        rid = r['check_id'].split('.')[-1]; sev[rid] = r['extra']['severity']
        rel = r['path'].split(n + '/', 1)[-1]
        c[rid] += 1; rule_all[rid] += 1
        if not NOISE.search(rel):
            cs[rid] += 1; rule_src[rid] += 1
            hits.append(dict(repo=n, rule=rid, path=rel, line=r['start']['line'], sev=r['extra']['severity'], snippet=(r['extra'].get('lines') or '')[:160]))
    per[n] = dict(all=sum(c.values()), src=sum(cs.values()), rules_src=dict(cs))
repos_with_src_hit = sum(1 for v in per.values() if v['src'])
S = dict(repos_cloned=len(glob.glob('data/sast/*.json')), repos_scanned=scanned, timed_out=timed_out, findings_all=sum(rule_all.values()), findings_src=sum(rule_src.values()),
         repos_with_src_hit=repos_with_src_hit, rule_src=dict(rule_src.most_common()), rule_all=dict(rule_all.most_common()), sev=sev,
         repos_by_rule={rid: sum(1 for v in per.values() if v['rules_src'].get(rid)) for rid in rule_src},
         per_repo={k: v for k, v in sorted(per.items(), key=lambda kv: -kv[1]['src'])})
json.dump(S, open('data/sast-summary.json', 'w'), indent=1)
json.dump(hits, open('data/sast-hits-src.json', 'w'), indent=1)
print(json.dumps({k: v for k, v in S.items() if k != 'per_repo'}, indent=1))
for rid in ('mcp-ts-hardcoded-api-key', 'mcp-ts-pem-private-key', 'mcp-ts-tool-description-exfiltration', 'mcp-ts-tool-description-injection-2', 'mcp-sdk-singleton-transport', 'mcp-sdk-singleton-server-reuse', 'mcp-ts-description-unicode-escape', 'mcp-api-key-header-logged', 'mcp-ts-credential-default-param', 'mcp-ts-tool-arg-url-ssrf', 'mcp-ts-execsync-injection', 'mcp-ts-exec-injection'):
    print('\n##', rid)
    for h in hits:
        if h['rule'] == rid: print(' ', h['repo'], h['path'] + ':' + str(h['line']), '|', h['snippet'].strip().replace('\n', ' ')[:130])
