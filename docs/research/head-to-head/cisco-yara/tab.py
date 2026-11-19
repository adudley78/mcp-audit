"""Print the comparison table from the files of export.py and cisco_run.py: ``python -I tab.py OUT``."""
import sys
import json, collections
D=sys.argv[1].rstrip("/")+"/"
S=collections.defaultdict(lambda: collections.Counter())
rules=collections.defaultdict(collections.Counter)
for l in open(D+"cisco_sets.jsonl"):
    r=json.loads(l); c=S[r["set"]]; c["n"]+=1
    c["cred"]+=bool(r["credenzo"]); c["cred_high"]+=r["credenzo_high"]; c["cisco"]+=bool(r["cisco"]); c["cisco_high"]+=r["cisco_high"]
    c["both"]+=bool(r["credenzo"]) and bool(r["cisco"]); c["either"]+=bool(r["credenzo"]) or bool(r["cisco"]); c["cisco_desc"]+=bool(r["cisco_desc"])
    rules[r["set"]].update(r["cisco"])
for k,c in S.items():
    n=c["n"]; print(f"{k:20s} n={n:5d} credenzo {c['cred']:4d} ({c['cred']/n:.1%}) high {c['cred_high']:4d} | cisco {c['cisco']:4d} ({c['cisco']/n:.1%}) high {c['cisco_high']:4d} desc-only {c['cisco_desc']} | both {c['both']} either {c['either']}")
    print("      cisco rules:",dict(rules[k].most_common(6)))
cis={}; cred={}
for l in open(D+"cisco_histor.jsonl"):
    r=json.loads(l); cis[r["sha"]]=(bool(r["cisco"]),r["cisco_high"],r["cisco"])
for l in open(D+"histor_texts.jsonl"):
    r=json.loads(l); cred[r["sha"]]=(bool(r["credenzo"]),r["credenzo_high"])
res=collections.defaultdict(set); srv=collections.defaultdict(set); n=0
for l in open(D+"histor_map.jsonl"):
    r=json.loads(l); n+=1
    for sha,istext in r["items"]:
        for name,(f,h) in (("cred",cred[sha]),("cisco",cis[sha][:2])):
            for key,ok in ((name,f),(name+"_high",h),(name+"_text",f and istext),(name+"_text_high",h and istext)):
                if ok: res[key].add(r["id"]); srv[key].add(r["server"])
print("HISTOR changes with a checked text:",n,"of 126105")
for k in sorted(res): print(f"  {k:18s} changes {len(res[k]):5d}  servers {len(srv[k]):5d}")
rc=collections.Counter()
for f,h,rl in cis.values(): rc.update(rl)
print("cisco rules on distinct HISTOR texts:",dict(rc.most_common()))
print("texts flagged: credenzo",sum(v[0] for v in cred.values()),"cisco",sum(v[0] for v in cis.values()),"both",sum(1 for s in cred if cred[s][0] and cis[s][0]))
