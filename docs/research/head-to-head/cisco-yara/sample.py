import json, random, yara, hashlib
from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
import sys
D=sys.argv[1].rstrip("/")+"/"
an=YaraAnalyzer(); rules=an._rules
fl={}
for l in open(D+"cisco_histor.jsonl"):
    r=json.loads(l)
    if r["cisco"]: fl[r["sha"]]=r
texts={}
for l in open(D+"histor_texts.jsonl"):
    r=json.loads(l)
    if r["sha"] in fl: texts[r["sha"]]=r
shas=sorted(fl); random.Random(171).shuffle(shas)
out=[]
for sha in shas[:150]:
    t=texts[sha]["text"]; data=t.encode()
    ms=rules.match(data=t); snips=[]
    for m in ms:
        for s in m.strings:
            for inst in s.instances[:1]:
                a=max(0,inst.offset-150); b=inst.offset+inst.matched_length+150
                snips.append({"rule":m.rule,"matched":data[inst.offset:inst.offset+inst.matched_length].decode("utf-8","replace"),"context":" ".join(data[a:b].decode("utf-8","replace").split())})
            break
    out.append({"n":len(out)+1,"sha":sha,"rules":fl[sha]["cisco"],"credenzo":texts[sha]["credenzo"],"snippets":snips[:4]})
json.dump(out,open(D+"cisco_sample.json","w"),indent=1,ensure_ascii=False)
print(len(shas),len(out)); print(json.dumps(out[0],ensure_ascii=False)[:900])
