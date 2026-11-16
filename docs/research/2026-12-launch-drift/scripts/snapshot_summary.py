"""Collapse the per-pair snapshot records into snapshot-summary.json (digests only, no tool text)."""
import json, sys
from collections import Counter
from pathlib import Path
recs = [json.load(open(p)) for p in sorted(Path(sys.argv[1]).glob("*.json"))]
rows = [{"type": r["type"], "package": r["package"], "version": r["version"], "labels": sorted(r["labels"]),
         "connected": not r.get("error") and bool(r.get("digests")), "error": r.get("error"),
         "tool_count": len(r.get("digests") or {}), "digests": r.get("digests") or {}} for r in recs]
rows.sort(key=lambda r: (r["type"], r["package"], r["version"]))
fail = Counter((r["error"] or "connected, no tools").split(":")[0][:60] for r in rows if not r["connected"])
json.dump({"pairs": len(rows), "connected": sum(r["connected"] for r in rows),
           "failure_classes": fail.most_common(), "rows": rows}, open(sys.argv[2], "w"), indent=1)
print("pairs", len(rows), "connected", sum(r["connected"] for r in rows), fail.most_common(6))
