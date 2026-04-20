# ruff: noqa: E501
"""Interactive HTML dashboard for MCP scan results.

Generates a fully self-contained HTML file — no CDN, no external dependencies —
embedding D3.js v7 and all scan data as an inline JSON object.  The dashboard
renders a force-directed attack graph, a sortable findings table, attack path
narratives, and hitting-set removal recommendations.

Usage (programmatic):
    from mcp_audit.output.dashboard import generate_html
    html = generate_html(result)
    Path("report.html").write_text(html)
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel

from mcp_audit._paths import data_dir
from mcp_audit.licensing import is_pro_feature_available
from mcp_audit.models import ScanResult

_console = Console()

# ── D3 loader ─────────────────────────────────────────────────────────────────


def _load_d3() -> str:
    """Return the bundled D3.js v7 minified source."""
    return (data_dir() / "d3.v7.min.js").read_text(encoding="utf-8")


# ── Scan data builder ─────────────────────────────────────────────────────────

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _build_scan_data(result: ScanResult) -> dict:
    """Serialise scan result into the SCAN_DATA dict embedded in the dashboard.

    Args:
        result: Completed scan result, including ``servers`` and
            ``attack_path_summary`` fields.

    Returns:
        A plain dict suitable for ``json.dumps``.
    """
    from mcp_audit.analyzers.toxic_flow import tag_server  # noqa: PLC0415

    # Per-server capability tags.
    server_caps: dict[str, list[str]] = {
        s.name: sorted(str(c) for c in tag_server(s)) for s in result.servers
    }

    # Per-server finding stats.
    server_finding_count: dict[str, int] = {}
    server_max_sev: dict[str, str] = {}

    for f in result.findings:
        names = f.server.split(" + ") if " + " in f.server else [f.server]
        for name in names:
            server_finding_count[name] = server_finding_count.get(name, 0) + 1
            current = server_max_sev.get(name)
            if current is None or (
                _SEV_ORDER.index(str(f.severity)) < _SEV_ORDER.index(current)
            ):
                server_max_sev[name] = str(f.severity)

    # Toxic edge data for the graph (deduplicated by source+target).
    seen_pairs: set[tuple[str, str]] = set()
    toxic_edges: list[dict] = []
    for f in result.findings:
        if f.analyzer != "toxic_flow" or " + " not in f.server:
            continue
        src, tgt = f.server.split(" + ", 1)
        key = (src, tgt)
        if key not in seen_pairs:
            seen_pairs.add(key)
            toxic_edges.append(
                {
                    "source": src,
                    "target": tgt,
                    "severity": str(f.severity),
                    "finding_id": f.id,
                    "label": f.title,
                }
            )

    # Attack path summary.
    ap_summary = result.attack_path_summary
    attack_paths: list[dict] = []
    hitting_set: list[str] = []
    paths_broken_by: dict[str, list[str]] = {}
    if ap_summary:
        attack_paths = [
            {
                "id": p.id,
                "severity": str(p.severity),
                "title": p.title,
                "description": p.description,
                "hops": p.hops,
                "source_capability": p.source_capability,
                "sink_capability": p.sink_capability,
            }
            for p in ap_summary.paths
        ]
        hitting_set = ap_summary.hitting_set
        paths_broken_by = ap_summary.paths_broken_by

    # Severity breakdown.
    finding_counts = dict.fromkeys(_SEV_ORDER, 0)
    for f in result.findings:
        finding_counts[str(f.severity)] += 1

    hitting_set_set = set(hitting_set)

    score_data = None
    if result.score is not None:
        score_data = {
            "numeric_score": result.score.numeric_score,
            "grade": result.score.grade,
            "positive_signals": result.score.positive_signals,
            "deductions": result.score.deductions,
        }

    return {
        "version": result.version,
        "timestamp": result.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
        "score": score_data,
        "machine": {
            "hostname": result.machine.hostname,
            "username": result.machine.username,
            "os": result.machine.os,
            "os_version": result.machine.os_version,
            "scan_id": result.machine.scan_id,
        },
        "clients_scanned": result.clients_scanned,
        "servers_found": result.servers_found,
        "finding_counts": finding_counts,
        "findings": [
            {
                "id": f.id,
                "severity": str(f.severity),
                "analyzer": f.analyzer,
                "client": f.client,
                "server": f.server,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
        "servers": [
            {
                "id": s.name,
                "name": s.name,
                "client": s.client,
                "capabilities": server_caps.get(s.name, []),
                "finding_count": server_finding_count.get(s.name, 0),
                "max_severity": server_max_sev.get(s.name),
                "in_hitting_set": s.name in hitting_set_set,
            }
            for s in result.servers
        ],
        "toxic_edges": toxic_edges,
        "attack_paths": attack_paths,
        "hitting_set": hitting_set,
        "paths_broken_by": paths_broken_by,
        "summary": {
            "total_findings": len(result.findings),
            "critical": finding_counts["CRITICAL"],
            "high": finding_counts["HIGH"],
            "medium": finding_counts["MEDIUM"],
            "low": finding_counts["LOW"],
            "info": finding_counts["INFO"],
            "server_count": len(result.servers),
            "path_count": len(attack_paths),
        },
    }


# ── HTML template ─────────────────────────────────────────────────────────────
# Uses __SCAN_DATA_JSON__ and __D3_JS__ as substitution markers so that the
# abundant JavaScript { } and ${ } syntax never collides with Python
# str.format() or f-string interpretation.

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcp-audit — Security Dashboard</title>
<style>
[data-theme="dark"]{
  --bg-deep:#0c0c1a;--bg-panel:#13132a;--bg-card:#1a1a38;--bg-hover:#222250;
  --border:#2a2a55;--border-light:#3a3a6a;
  --text-primary:#e8e8f0;--text-secondary:#9898b8;--text-dim:#6868a0;
  --crit:#ff3b4f;--high:#ff8c2e;--med:#ffcc30;--low:#4a9eff;--info:#6b7280;
  --safe:#22cc66;--accent:#00ccff;--hit:#d946ef;
  --tt-shadow:0 6px 24px rgba(0,0,0,.55);
  --row-hl-bg:rgba(0,204,255,.06);
}
[data-theme="light"]{
  --bg-deep:#f0f1f5;--bg-panel:#ffffff;--bg-card:#f5f5fa;--bg-hover:#eeeef5;
  --border:#d8d8e8;--border-light:#c0c0d8;
  --text-primary:#1a1a2e;--text-secondary:#5a5a78;--text-dim:#8888a8;
  --crit:#dc2626;--high:#ea580c;--med:#ca8a04;--low:#2563eb;--info:#6b7280;
  --safe:#16a34a;--accent:#0088cc;--hit:#a855f7;
  --tt-shadow:0 2px 8px rgba(0,0,0,.1);
  --row-hl-bg:rgba(0,136,204,.08);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{
  background:var(--bg-deep);color:var(--text-primary);
  font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:13px;
}
.app{
  display:grid;
  grid-template-rows:56px 1fr 240px;
  grid-template-columns:1fr 340px;
  height:100vh;
}

/* ── Top bar ── */
.top-bar{
  grid-column:1/-1;grid-row:1;
  display:flex;align-items:center;justify-content:space-between;
  padding:0 20px;background:var(--bg-panel);
  border-bottom:1px solid var(--border);z-index:10;
}
.logo{display:flex;align-items:baseline;gap:6px}
.logo-name{
  font-family:"JetBrains Mono",ui-monospace,"Cascadia Code","Fira Code",monospace;font-size:15px;font-weight:600;
  color:var(--accent);letter-spacing:.3px;
}
.logo-ver{
  font-family:"JetBrains Mono",ui-monospace,"Cascadia Code","Fira Code",monospace;font-size:13px;font-weight:400;
  color:var(--text-dim);
}
.top-right{display:flex;align-items:center;gap:14px}
.top-stats{display:flex;align-items:center;gap:18px}
.machine-bar{
  padding:3px 20px;background:var(--bg-deep);
  border-bottom:1px solid var(--border);
  font-size:11px;color:var(--text-dim);font-family:"JetBrains Mono",ui-monospace,"Cascadia Code","Fira Code",monospace;
  letter-spacing:.2px;
}

/* ── Theme toggle ── */
.theme-toggle{
  width:36px;height:20px;border-radius:10px;border:1px solid var(--border);
  background:var(--bg-card);cursor:pointer;position:relative;
  transition:background .2s;display:flex;align-items:center;padding:0 3px;
  flex-shrink:0;
}
.theme-toggle::after{
  content:'';width:14px;height:14px;border-radius:50%;background:var(--accent);
  transition:transform .2s;position:absolute;left:3px;
}
[data-theme="light"] .theme-toggle::after{transform:translateX(16px)}
.theme-toggle::before{
  content:'●';font-size:9px;color:var(--text-dim);
  position:absolute;right:4px;top:50%;transform:translateY(-50%);
  pointer-events:none;line-height:1;transition:opacity .15s;
}
[data-theme="light"] .theme-toggle::before{content:'☀';right:auto;left:4px}
.sev-counter{display:flex;align-items:baseline;gap:5px}
.sc-num{font-size:14px;font-weight:700;line-height:1}
.sc-label{font-size:12px;color:var(--text-secondary)}
.top-summary{font-size:12px;color:var(--text-dim)}
.grade-badge{display:flex;align-items:baseline;gap:6px;padding:2px 10px;border-radius:6px;border:1px solid var(--border)}
.grade-letter{font-size:22px;font-weight:700;line-height:1}
.grade-num{font-size:13px;font-weight:600;color:var(--text-secondary)}

/* ── Layout regions ── */
.graph-panel{
  grid-column:1;grid-row:2;
  background:var(--bg-deep);position:relative;overflow:hidden;
  display:flex;flex-direction:column;
}
.sidebar{
  grid-column:2;grid-row:2;
  background:var(--bg-panel);border-left:1px solid var(--border);
  display:flex;flex-direction:column;overflow:hidden;
}
.bottom-panel{
  grid-column:1/-1;grid-row:3;
  background:var(--bg-panel);border-top:1px solid var(--border);
  display:flex;flex-direction:column;overflow:hidden;
}

/* ── Graph panel ── */
.graph-header{
  flex-shrink:0;padding:8px 14px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px;
}
.graph-header-label{
  font-size:11px;font-weight:600;letter-spacing:0.9px;
  color:var(--text-dim);text-transform:uppercase;
}
.graph-hint{font-size:10px;color:var(--text-dim);opacity:.7}
#graph-svg{flex:1;width:100%;display:block}
.node{cursor:pointer}
.link{stroke-linecap:round}

/* ── Tooltip ── */
.tooltip{
  position:fixed;display:none;pointer-events:none;z-index:200;
  background:var(--bg-card);border:1px solid var(--border-light);
  border-radius:7px;padding:10px 13px;font-size:12px;max-width:240px;
  line-height:1.55;box-shadow:var(--tt-shadow);
}
.tt-name{
  font-family:"JetBrains Mono",ui-monospace,"Cascadia Code","Fira Code",monospace;font-weight:500;font-size:12px;
  color:var(--text-primary);margin-bottom:5px;
}
.tt-row{color:var(--text-secondary);font-size:11px}
.tt-hs{color:var(--hit);font-size:11px;margin-top:4px}

/* ── Sidebar ── */
.sidebar-header{
  flex-shrink:0;padding:10px 14px;
  border-bottom:1px solid var(--border);
  font-size:11px;font-weight:600;letter-spacing:0.8px;
  color:var(--text-secondary);text-transform:uppercase;
}
.path-list{flex:1;overflow-y:auto;padding:8px 8px}

.path-card{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:8px;padding:12px 13px;margin-bottom:7px;
  cursor:pointer;transition:background .15s,border-color .15s;
}
.path-card:hover{background:var(--bg-hover);border-color:var(--border-light)}
.path-card.active{border-color:var(--crit);background:rgba(255,59,79,.06)}
.pc-head{display:flex;align-items:center;gap:7px;margin-bottom:6px}
.sev-badge{
  display:inline-block;font-size:10px;font-weight:600;letter-spacing:.5px;
  text-transform:uppercase;padding:2px 8px;border-radius:20px;
}
.sev-badge-CRITICAL{background:rgba(255,59,79,.15);color:var(--crit)}
.sev-badge-HIGH{background:rgba(255,140,46,.15);color:var(--high)}
.sev-badge-MEDIUM{background:rgba(255,204,48,.12);color:var(--med)}
.sev-badge-LOW{background:rgba(74,158,255,.15);color:var(--low)}
.sev-badge-INFO{background:rgba(107,114,128,.15);color:var(--info)}
.pc-title{font-size:13px;font-weight:500;color:var(--text-primary);flex:1;line-height:1.35}
.pc-chain{
  font-family:"JetBrains Mono",ui-monospace,"Cascadia Code","Fira Code",monospace;font-size:11px;
  color:var(--text-secondary);margin-bottom:5px;
}
.pc-chain-arrow{color:var(--crit);margin:0 4px}
.pc-desc{font-size:11px;color:var(--text-secondary);line-height:1.4}

/* ── Hitting set panel ── */
.hs-panel{
  flex-shrink:0;border-top:1px solid var(--hit);
  background:var(--bg-card);border-radius:0 0 0 0;padding:11px 13px;
}
.hs-header{
  font-size:10px;font-weight:600;letter-spacing:.7px;text-transform:uppercase;
  color:var(--hit);margin-bottom:8px;
}
.hs-item{display:flex;align-items:flex-start;gap:8px;margin-bottom:6px}
.hs-item:last-child{margin-bottom:0}
.hs-x{color:var(--hit);font-size:13px;line-height:1.2;flex-shrink:0;margin-top:1px}
.hs-name{
  font-family:"JetBrains Mono",ui-monospace,"Cascadia Code","Fira Code",monospace;font-size:11px;
  color:var(--text-primary);font-weight:500;
}
.hs-sub{font-size:10px;color:var(--text-dim)}

/* ── Bottom panel ── */
.bottom-header{
  flex-shrink:0;display:flex;align-items:center;gap:14px;
  padding:7px 14px;border-bottom:1px solid var(--border);
}
.findings-label{
  font-size:11px;font-weight:600;letter-spacing:.8px;
  color:var(--text-secondary);text-transform:uppercase;white-space:nowrap;
}
.filter-group{display:flex;gap:5px;flex-wrap:wrap;align-items:center}
.filter-btn{
  font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;
  padding:3px 10px;border-radius:20px;border:1px solid var(--border);
  background:transparent;color:var(--text-dim);cursor:pointer;
  font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;transition:all .12s;
}
.filter-btn:hover{border-color:var(--border-light);color:var(--text-secondary)}
.filter-btn.active-all{background:rgba(232,232,240,.08);color:var(--text-primary);border-color:var(--border-light)}

.table-wrap{flex:1;overflow-y:auto}
.findings-table{width:100%;border-collapse:collapse;font-size:12px}
.findings-table th{
  position:sticky;top:0;background:var(--bg-panel);
  padding:7px 11px;text-align:left;font-size:10px;font-weight:600;
  letter-spacing:.7px;color:var(--text-dim);text-transform:uppercase;
  border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;z-index:5;
}
.findings-table th:hover{color:var(--text-secondary)}
.findings-table td{
  padding:6px 11px;border-bottom:1px solid var(--border);
  vertical-align:middle;max-width:300px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;
}
.findings-table tr{cursor:pointer;transition:background .1s}
.findings-table tr:hover td{background:var(--bg-hover)}
.findings-table tr.row-hl td{background:var(--row-hl-bg)}
.td-sev{display:flex;align-items:center;gap:6px;white-space:nowrap}
.sev-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.td-mono{font-family:"JetBrains Mono",ui-monospace,"Cascadia Code","Fira Code",monospace;font-size:11px;color:var(--text-secondary)}

/* ── Legend ── */
.graph-legend{
  position:absolute;bottom:12px;left:12px;
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:7px;padding:9px 12px;font-size:10px;color:var(--text-dim);
  pointer-events:none;
}
.leg-row{display:flex;align-items:center;gap:7px;margin-bottom:5px}
.leg-row:last-child{margin-bottom:0}
.leg-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.leg-dash{width:18px;height:2px;flex-shrink:0;border-top:2px dashed}
.leg-line{width:18px;height:2px;flex-shrink:0}

/* ── Animations ── */
@keyframes march{to{stroke-dashoffset:-24}}
.path-hl{animation:march .5s linear infinite;pointer-events:none}
@keyframes hs-pulse{0%{transform:scale(1);opacity:.45}100%{transform:scale(2.2);opacity:0}}
.hs-pulse-ring{transform-box:fill-box;transform-origin:center;animation:hs-pulse 1.8s ease-out infinite}

/* ── Scrollbars ── */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
</style>
</head>
<body class="dash" data-theme="dark">
<div class="app">

  <!-- Top bar -->
  <header class="top-bar">
    <div class="logo">
      <span class="logo-name">mcp-audit</span>
      <span class="logo-ver" id="logo-ver"></span>
    </div>
    <div class="top-right">
    <button class="theme-toggle" id="theme-toggle"
            onclick="toggleTheme()"
            aria-label="Toggle light/dark theme"
            title="Toggle light/dark theme"></button>
    <div class="grade-badge" id="grade-badge" style="display:none" title="Security grade">
      <span class="grade-letter" id="grade-letter"></span>
      <span class="grade-num" id="grade-num"></span>
    </div>
    <div class="top-stats">
      <div class="sev-counter" id="crit-ctr" style="display:none">
        <span class="sc-num" style="color:var(--crit)" id="crit-num"></span>
        <span class="sc-label">critical</span>
      </div>
      <div class="sev-counter" id="high-ctr" style="display:none">
        <span class="sc-num" style="color:var(--high)" id="high-num"></span>
        <span class="sc-label">high</span>
      </div>
      <div class="sev-counter" id="med-ctr" style="display:none">
        <span class="sc-num" style="color:var(--med)" id="med-num"></span>
        <span class="sc-label">medium</span>
      </div>
      <span class="top-summary" id="top-summary"></span>
    </div>
    </div>
  </header>
  <div class="machine-bar" id="machine-bar"></div>

  <!-- Graph panel -->
  <section class="graph-panel">
    <div class="graph-header">
      <span class="graph-header-label">Attack Graph</span>
      <span class="graph-hint">click path to highlight · drag to reposition</span>
    </div>
    <svg id="graph-svg"></svg>
    <div class="graph-legend">
      <div class="leg-row"><div class="leg-dot" style="background:var(--accent)"></div>AI Agent</div>
      <div class="leg-row"><div class="leg-dot" style="background:var(--crit)"></div>Critical server</div>
      <div class="leg-row"><div class="leg-dot" style="background:var(--high)"></div>High server</div>
      <div class="leg-row"><div class="leg-dot" style="background:var(--safe)"></div>Clean server</div>
      <div class="leg-row"><div class="leg-dash" style="border-color:var(--hit)"></div>In hitting set</div>
      <div class="leg-row"><div class="leg-line" style="background:var(--crit)"></div>Toxic flow</div>
    </div>
  </section>

  <!-- Sidebar: attack paths + hitting set -->
  <aside class="sidebar">
    <div class="sidebar-header">Exploitable attack paths</div>
    <div class="path-list" id="path-list"></div>
    <div class="hs-panel" id="hs-panel"></div>
  </aside>

  <!-- Bottom: findings table -->
  <section class="bottom-panel">
    <div class="bottom-header">
      <span class="findings-label">Findings</span>
      <div class="filter-group" id="filter-group"></div>
    </div>
    <div class="table-wrap">
      <table class="findings-table">
        <thead>
          <tr>
            <th data-col="severity">Severity</th>
            <th data-col="analyzer">Analyzer</th>
            <th data-col="server">Server</th>
            <th data-col="title">Finding</th>
          </tr>
        </thead>
        <tbody id="findings-tbody"></tbody>
      </table>
    </div>
  </section>
</div>

<!-- Tooltip -->
<div class="tooltip" id="tooltip"></div>

<!-- Embedded scan data -->
<script>const SCAN_DATA = __SCAN_DATA_JSON__;</script>

<!-- D3.js v7 (embedded, no CDN) -->
<script>__D3_JS__</script>

<!-- Dashboard application -->
<script>
(function(){
'use strict';

// ── Theme-aware color palette ────────────────────────────────────────────────
const PALETTE = {
  dark:{
    CRITICAL:'#ff3b4f',HIGH:'#ff8c2e',MEDIUM:'#ffcc30',LOW:'#4a9eff',INFO:'#6b7280',
    safe:'#22cc66',accent:'#00ccff',hit:'#d946ef',border:'#2a2a55',
    agentFill:'#0a1428',fillSuffix:'18',baseOpacity:0.3,toxicOpacity:0.6,
    nodeText:'#e8e8f0',capText:'#6868a0',
  },
  light:{
    CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#ca8a04',LOW:'#2563eb',INFO:'#6b7280',
    safe:'#16a34a',accent:'#0088cc',hit:'#a855f7',border:'#d8d8e8',
    agentFill:'#e0f4ff',fillSuffix:'20',baseOpacity:0.4,toxicOpacity:0.7,
    nodeText:'#1a1a2e',capText:'#8888a8',
  },
};
const C = Object.assign({}, PALETTE.dark);

const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

let state = {selPath:null, selServer:null, sevFilter:null, sortCol:'severity', sortAsc:true};
let svgSel, nodeG, linkG, sim, nodeMap = {};

function sevColor(s){ return C[s] || C.INFO; }
function sevFill(s){ return sevColor(s) + C.fillSuffix; }
function nodeR(caps){ const n=(caps||[]).length; return n<=1?17:n===2?20:22; }
function trunc(s,n){ return s&&s.length>n?s.slice(0,n)+'…':(s||''); }

function sevBadge(sev){
  return `<span class="sev-badge sev-badge-${sev||'INFO'}">${sev||'INFO'}</span>`;
}

// ── Stats ──────────────────────────────────────────────────────────────────
function initStats(){
  const S = SCAN_DATA.summary;
  document.getElementById('logo-ver').textContent = 'v' + SCAN_DATA.version;

  if(S.critical>0){
    document.getElementById('crit-ctr').style.display='flex';
    document.getElementById('crit-num').textContent = S.critical;
  }
  if(S.high>0){
    document.getElementById('high-ctr').style.display='flex';
    document.getElementById('high-num').textContent = S.high;
  }
  if(S.medium>0){
    document.getElementById('med-ctr').style.display='flex';
    document.getElementById('med-num').textContent = S.medium;
  }
  const f = S.total_findings;
  const p = S.path_count;
  document.getElementById('top-summary').textContent =
    `${S.server_count} server${S.server_count!==1?'s':''} · `+
    `${f} finding${f!==1?'s':''} · `+
    `${p} attack path${p!==1?'s':''}`;

  const M = SCAN_DATA.machine;
  if(M){
    document.getElementById('machine-bar').textContent =
      `${M.hostname}  ·  ${M.username}@${M.os}  ·  scan ${M.scan_id}  ·  ${SCAN_DATA.timestamp}`;
  }

  const SC = SCAN_DATA.score;
  if(SC){
    const gradeColors = {A:'var(--safe)',B:'var(--safe)',C:'var(--med)',D:'var(--med)',F:'var(--crit)'};
    const badge = document.getElementById('grade-badge');
    const letterEl = document.getElementById('grade-letter');
    const numEl = document.getElementById('grade-num');
    letterEl.textContent = SC.grade;
    letterEl.style.color = gradeColors[SC.grade] || 'var(--text-primary)';
    numEl.textContent = SC.numeric_score;
    badge.style.display = 'flex';
    badge.title = `Grade ${SC.grade} · ${SC.numeric_score}/100`;
  }
}

// ── Graph ──────────────────────────────────────────────────────────────────
function initGraph(){
  const D = SCAN_DATA;
  const el = document.getElementById('graph-svg');
  const W = el.parentElement.clientWidth;
  const H = el.parentElement.clientHeight - 38;

  svgSel = d3.select('#graph-svg')
    .attr('viewBox', `0 0 ${W} ${H}`)
    .attr('preserveAspectRatio','xMidYMid meet');

  svgSel.append('rect')
    .attr('width',W).attr('height',H)
    .attr('fill','transparent')
    .on('click', clearSel);

  const nodes = [{
    id:'__agent__', label:'AI Agent', type:'agent',
    caps:[], finding_count:0, max_severity:null, in_hitting_set:false,
  }];
  D.servers.forEach(s=>{
    nodes.push({
      id: s.id, label: s.name, type:'server',
      client: s.client, caps: s.capabilities||[],
      finding_count: s.finding_count||0,
      max_severity: s.max_severity||null,
      in_hitting_set: s.in_hitting_set||false,
    });
  });
  nodes.forEach(n=>{ nodeMap[n.id]=n; });

  const links = [
    ...D.servers.map(s=>({source:'__agent__',target:s.id,kind:'base'})),
    ...(D.toxic_edges||[]).map(e=>({source:e.source,target:e.target,kind:'toxic',severity:e.severity,label:e.label||''})),
  ];

  // Pin agent at centre when alone; softer charge for small graphs so a single
  // server doesn't fly to the edge of the canvas.
  if(D.servers.length === 0){ nodes[0].fx = W/2; nodes[0].fy = H/2; }
  const isSmall = D.servers.length <= 1;
  sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d=>d.id).distance(d=>d.kind==='base'?150:110))
    .force('charge', d3.forceManyBody().strength(isSmall ? -150 : -480))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(d=>(d.type==='agent'?28:nodeR(d.caps))+14));

  linkG = svgSel.append('g');
  const linkSel = linkG.selectAll('line').data(links).join('line')
    .attr('stroke', d=>d.kind==='toxic'?sevColor(d.severity):C.border)
    .attr('stroke-width', d=>d.kind==='toxic'?(d.severity==='CRITICAL'?2.5:1.5):0.5)
    .attr('opacity', d=>d.kind==='toxic'?C.toxicOpacity:C.baseOpacity)
    .attr('stroke-linecap','round');

  // Hover brighten for toxic edges
  linkSel.filter(d=>d.kind==='toxic')
    .on('mouseover', function(){ d3.select(this).attr('opacity',1.0); })
    .on('mouseout',  function(){ d3.select(this).attr('opacity',C.toxicOpacity); });

  nodeG = svgSel.append('g');
  const nodeSel = nodeG.selectAll('g').data(nodes).join('g')
    .attr('class','node')
    .call(d3.drag()
      .on('start',(e,d)=>{ if(!e.active) sim.alphaTarget(.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',(e,d)=>{ d.fx=e.x; d.fy=e.y; })
      .on('end',(e,d)=>{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; })
    );

  // AI Agent outer ring
  nodeSel.filter(d=>d.type==='agent').append('circle')
    .attr('r',36).attr('fill','none')
    .attr('stroke',C.accent).attr('stroke-width',.5).attr('opacity',.3);

  // Server hitting-set pulse ring (behind node)
  nodeSel.filter(d=>d.type==='server'&&d.in_hitting_set).append('circle')
    .attr('class','hs-pulse-ring')
    .attr('r', d=>nodeR(d.caps)+4)
    .attr('fill','none').attr('stroke',C.hit).attr('stroke-width',1.5).attr('opacity',.45);

  // Main circle
  nodeSel.append('circle')
    .attr('class','node-circle')
    .attr('r', d=>d.type==='agent'?28:nodeR(d.caps))
    .attr('fill', d=>d.type==='agent'?C.agentFill:sevFill(d.max_severity))
    .attr('stroke', d=>{
      if(d.type==='agent') return C.accent;
      if(d.in_hitting_set) return C.hit;
      return d.max_severity ? sevColor(d.max_severity) : C.safe;
    })
    .attr('stroke-width', d=>d.type==='agent'?1.5:1.2);

  // Hitting-set dashed outer ring (on top)
  nodeSel.filter(d=>d.type==='server'&&d.in_hitting_set).append('circle')
    .attr('class','hs-dash-ring')
    .attr('r', d=>nodeR(d.caps)+4)
    .attr('fill','none').attr('stroke',C.hit)
    .attr('stroke-width',1.5).attr('stroke-dasharray','4 3').attr('opacity',.9);

  // Node label (name)
  nodeSel.append('text')
    .attr('class','node-label')
    .attr('text-anchor','middle')
    .attr('dy', d=>d.type==='agent'?'0.35em':(d.caps&&d.caps.length?'-0.35em':'0.35em'))
    .attr('font-size', d=>d.type==='agent'?'11px':'10px')
    .attr('font-weight', d=>d.type==='agent'?'600':'400')
    .attr('font-family','JetBrains Mono, ui-monospace, Fira Code, monospace')
    .attr('fill', C.nodeText).attr('pointer-events','none')
    .text(d=>trunc(d.label,12));

  // Capability sub-label for server nodes
  nodeSel.filter(d=>d.type==='server'&&d.caps&&d.caps.length>0).append('text')
    .attr('class','cap-label')
    .attr('text-anchor','middle').attr('dy','0.9em')
    .attr('font-size','8px').attr('fill', C.capText).attr('pointer-events','none')
    .text(d=>trunc(d.caps.slice(0,2).join(', '),16));

  nodeSel
    .on('mouseover', showTooltip)
    .on('mousemove', moveTooltip)
    .on('mouseout',  hideTooltip)
    .on('click', (e,d)=>{ e.stopPropagation(); onNodeClick(d); });

  sim.on('tick',()=>{
    linkSel
      .attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
      .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    nodeSel.attr('transform',d=>`translate(${d.x},${d.y})`);
    // keep animated path-hl lines in sync
    svgSel.selectAll('.path-hl')
      .attr('x1',function(){ return +d3.select(this).attr('data-ax'); })
      .attr('y1',function(){ return +d3.select(this).attr('data-ay'); })
      .attr('x2',function(){ return +d3.select(this).attr('data-bx'); })
      .attr('y2',function(){ return +d3.select(this).attr('data-by'); });
  });

  // No-servers empty state: guidance text below the centred AI Agent node
  if(D.servers.length === 0){
    svgSel.append('text')
      .attr('class','graph-empty-text')
      .attr('x', W/2).attr('y', H/2 + 52)
      .attr('text-anchor','middle').attr('font-size','13px')
      .attr('fill','var(--text-dim)')
      .attr('font-family','system-ui, -apple-system, Segoe UI, sans-serif')
      .text('No MCP servers detected.');
    svgSel.append('text')
      .attr('class','graph-empty-text')
      .attr('x', W/2).attr('y', H/2 + 72)
      .attr('text-anchor','middle').attr('font-size','11px')
      .attr('fill','var(--text-dim)')
      .attr('font-family','JetBrains Mono, ui-monospace, Fira Code, monospace')
      .text('Run mcp-audit discover to check supported clients.');
  }
}

// ── Tooltip ────────────────────────────────────────────────────────────────
function showTooltip(e, d){
  const tt = document.getElementById('tooltip');
  if(d.type==='agent'){
    tt.innerHTML = '<div class="tt-name">AI Agent</div><div class="tt-row">Connects to all MCP servers</div>';
  } else {
    const caps = d.caps.length ? d.caps.join(', ') : 'none detected';
    const sev  = d.max_severity || 'clean';
    const hs   = d.in_hitting_set
      ? '<div class="tt-hs">⚠ In hitting set — removal recommended</div>' : '';
    tt.innerHTML =
      `<div class="tt-name">${d.label}</div>`+
      `<div class="tt-row">Client: ${d.client||'—'}</div>`+
      `<div class="tt-row">Capabilities: ${caps}</div>`+
      `<div class="tt-row">Findings: ${d.finding_count} · max severity: `+
      `<span style="color:${d.max_severity?sevColor(d.max_severity):'var(--safe)'}">${sev}</span></div>`+
      hs;
  }
  tt.style.display = 'block';
  moveTooltip(e);
}
function moveTooltip(e){
  const tt = document.getElementById('tooltip');
  tt.style.left = (e.pageX+16)+'px';
  tt.style.top  = (e.pageY-12)+'px';
}
function hideTooltip(){ document.getElementById('tooltip').style.display='none'; }

// ── Selection & highlights ─────────────────────────────────────────────────
function onNodeClick(d){
  if(d.type==='agent') return;
  state.selServer = state.selServer===d.id ? null : d.id;
  state.selPath   = null;
  document.querySelectorAll('.path-card').forEach(el=>el.classList.remove('active'));
  applyHighlights();
  renderFindings();
}

function clearSel(){
  state.selPath   = null;
  state.selServer = null;
  document.querySelectorAll('.path-card').forEach(el=>el.classList.remove('active'));
  applyHighlights();
  renderFindings();
}

function focusServer(name){
  state.selServer = name;
  state.selPath   = null;
  document.querySelectorAll('.path-card').forEach(el=>el.classList.remove('active'));
  applyHighlights();
  renderFindings();
}

function applyHighlights(){
  const path = state.selPath
    ? SCAN_DATA.attack_paths.find(p=>p.id===state.selPath) : null;
  const hops = path ? path.hops : null;

  nodeG.selectAll('g.node').attr('opacity', d=>{
    if(hops) return (hops.includes(d.id)||d.type==='agent') ? 1 : .12;
    if(state.selServer) return (d.id===state.selServer||d.type==='agent') ? 1 : .18;
    return 1;
  });

  svgSel.selectAll('.path-hl').remove();

  if(hops && hops.length>1){
    for(let i=0; i<hops.length-1; i++){
      const a = nodeMap[hops[i]];
      const b = nodeMap[hops[i+1]];
      if(a && b){
        svgSel.append('line')
          .attr('class','path-hl')
          .attr('data-ax', a.x).attr('data-ay', a.y)
          .attr('data-bx', b.x).attr('data-by', b.y)
          .attr('x1',a.x).attr('y1',a.y)
          .attr('x2',b.x).attr('y2',b.y)
          .attr('stroke',C.CRITICAL).attr('stroke-width',3)
          .attr('stroke-dasharray','8 4').attr('stroke-linecap','round')
          .attr('opacity',.9);
      }
    }
  }
}

// ── Paths panel ────────────────────────────────────────────────────────────
function initPaths(){
  const D = SCAN_DATA;
  const list = document.getElementById('path-list');
  list.innerHTML = '';

  if(!D.attack_paths.length){
    list.innerHTML =
      '<div style="display:flex;align-items:center;justify-content:center;'+
      'min-height:80px;padding:32px 16px;text-align:center;'+
      'color:var(--text-dim);font-size:13px;line-height:1.6">'+
      'No exploitable attack paths detected.</div>';
    document.getElementById('hs-panel').style.display = 'none';
    return;
  }

  D.attack_paths.forEach(p=>{
    const card = document.createElement('div');
    card.className = 'path-card';
    card.dataset.pid = p.id;

    const chainHtml = p.hops.map(h=>`<span>${h}</span>`)
      .join('<span class="pc-chain-arrow">→</span>');

    card.innerHTML =
      `<div class="pc-head">${sevBadge(p.severity)}<span class="pc-title">${p.title}</span></div>`+
      `<div class="pc-chain">${chainHtml}</div>`+
      `<div class="pc-desc">${p.description}</div>`;

    card.addEventListener('click', ()=>{
      document.querySelectorAll('.path-card').forEach(el=>el.classList.remove('active'));
      if(state.selPath===p.id){
        state.selPath = null;
      } else {
        state.selPath   = p.id;
        state.selServer = null;
        card.classList.add('active');
      }
      applyHighlights();
    });
    list.appendChild(card);
  });

  // Hitting set panel — hide if no removal candidates (all paths broken by same set)
  const hsEl = document.getElementById('hs-panel');
  if(!D.hitting_set.length){
    hsEl.style.display = 'none';
    return;
  }

  const total = D.attack_paths.length;
  let html = '<div class="hs-header">Recommended action</div>';
  D.hitting_set.forEach(s=>{
    const n = (D.paths_broken_by[s]||[]).length;
    html +=
      `<div class="hs-item" onclick="focusServer('${s}')" style="cursor:pointer">`+
      `<span class="hs-x">×</span>`+
      `<div><div class="hs-name">${s}</div>`+
      `<div class="hs-sub">Breaks ${n} of ${total} attack path${total!==1?'s':''}</div></div>`+
      `</div>`;
  });
  hsEl.innerHTML = html;
}

// ── Findings table ─────────────────────────────────────────────────────────
function initFindings(){
  const D = SCAN_DATA;
  const grp = document.getElementById('filter-group');
  grp.innerHTML = '';

  const allBtn = document.createElement('button');
  allBtn.className = 'filter-btn active-all';
  allBtn.textContent = 'All';
  allBtn.addEventListener('click', ()=>setSevFilter(null, allBtn));
  grp.appendChild(allBtn);

  SEV_ORDER.forEach(sev=>{
    const cnt = D.findings.filter(f=>f.severity===sev).length;
    if(!cnt) return;
    const btn = document.createElement('button');
    btn.className = 'filter-btn';
    btn.style.cssText =
      `border-color:${sevColor(sev)};color:${sevColor(sev)};background:${sevColor(sev)}22`;
    btn.innerHTML = `${sev} <span style="opacity:.55;font-weight:400">${cnt}</span>`;
    btn.addEventListener('click', ()=>setSevFilter(sev, btn));
    grp.appendChild(btn);
  });

  // Column header sort
  document.querySelectorAll('.findings-table th[data-col]').forEach(th=>{
    th.addEventListener('click', ()=>sortBy(th.dataset.col));
  });

  renderFindings();
}

function setSevFilter(sev, btn){
  state.sevFilter = sev;
  state.selServer = null;
  document.querySelectorAll('.filter-btn').forEach(b=>{
    b.classList.remove('active-all');
    b.style.fontWeight = '600';
  });
  btn.classList.add('active-all');
  applyHighlights();
  renderFindings();
}

function sortBy(col){
  if(state.sortCol===col) state.sortAsc = !state.sortAsc;
  else { state.sortCol=col; state.sortAsc=true; }
  renderFindings();
}

function renderFindings(){
  let data = SCAN_DATA.findings.slice();
  if(state.sevFilter) data = data.filter(f=>f.severity===state.sevFilter);
  if(state.selServer) data = data.filter(f=>f.server===state.selServer||f.server.includes(state.selServer));

  const col = state.sortCol;
  data.sort((a,b)=>{
    if(col==='severity'){
      const va=SEV_ORDER.indexOf(a.severity), vb=SEV_ORDER.indexOf(b.severity);
      return state.sortAsc ? va-vb : vb-va;
    }
    const va=a[col]||'', vb=b[col]||'';
    return state.sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });

  const tbody = document.getElementById('findings-tbody');
  tbody.innerHTML = '';

  // Global zero-findings state — shown regardless of active filters
  if(!SCAN_DATA.findings.length){
    tbody.innerHTML =
      '<tr><td colspan="4" style="padding:40px;text-align:center;'+
      'color:var(--text-dim);font-size:13px;border:none">'+
      'No security issues found</td></tr>';
    return;
  }

  data.forEach(f=>{
    const tr = document.createElement('tr');
    const hl = state.selServer&&(f.server===state.selServer||f.server.includes(state.selServer));
    if(hl) tr.className='row-hl';
    const dot = `<span class="sev-dot" style="background:${sevColor(f.severity)}"></span>`;
    const sevTxt = `<span style="color:${sevColor(f.severity)}">${f.severity}</span>`;
    tr.innerHTML =
      `<td><div class="td-sev">${dot}${sevTxt}</div></td>`+
      `<td class="td-mono">${f.analyzer}</td>`+
      `<td class="td-mono" title="${f.server}">${trunc(f.server,28)}</td>`+
      `<td title="${f.title||''}">${trunc(f.title||'',55)}</td>`;
    tr.addEventListener('click', ()=>{
      if(!f.server.includes(' + ')) focusServer(f.server);
    });
    tbody.appendChild(tr);
  });
}

// ── Theme toggle ───────────────────────────────────────────────────────────
function updateGraphTheme(){
  // Agent outer ring stroke
  nodeG.selectAll('g.node').filter(d=>d.type==='agent').select('circle:first-child')
    .attr('stroke', C.accent);
  // All main circles: fill + stroke
  nodeG.selectAll('.node-circle')
    .attr('fill', d=>d.type==='agent' ? C.agentFill : sevFill(d.max_severity))
    .attr('stroke', d=>{
      if(d.type==='agent') return C.accent;
      if(d.in_hitting_set) return C.hit;
      return d.max_severity ? sevColor(d.max_severity) : C.safe;
    });
  // HS rings
  nodeG.selectAll('.hs-pulse-ring,.hs-dash-ring').attr('stroke', C.hit);
  // Labels
  nodeG.selectAll('.node-label').attr('fill', C.nodeText);
  nodeG.selectAll('.cap-label').attr('fill', C.capText);
  // Base edges
  linkG.selectAll('line').filter(d=>d.kind==='base')
    .attr('stroke', C.border)
    .attr('opacity', C.baseOpacity);
  // Toxic edges — update opacity and re-bind mouseout
  const tox = C.toxicOpacity;
  linkG.selectAll('line').filter(d=>d.kind==='toxic')
    .attr('opacity', tox)
    .on('mouseout', function(){ d3.select(this).attr('opacity', tox); });
}

function toggleTheme(){
  const dash = document.querySelector('.dash');
  const next = dash.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  dash.setAttribute('data-theme', next);
  Object.assign(C, PALETTE[next]);
  updateGraphTheme();
  initFindings(); // rebuild filter buttons with updated severity colors
}

// ── Bootstrap ──────────────────────────────────────────────────────────────
window.focusServer = focusServer;
window.toggleTheme = toggleTheme;

document.addEventListener('DOMContentLoaded', ()=>{
  initStats();
  initGraph();
  initPaths();
  initFindings();
});

})();
</script>
</body>
</html>
"""


# ── Public API ────────────────────────────────────────────────────────────────


def generate_html(result: ScanResult, console: Console | None = None) -> str | None:
    """Generate a self-contained HTML dashboard for *result*.

    Embeds D3.js (bundled with the package) and the full scan data as an
    inline JSON object.  The output file has zero external dependencies and
    works offline.

    Args:
        result: Completed :class:`~mcp_audit.models.ScanResult`, populated by
            :func:`~mcp_audit.scanner.run_scan`.  The ``servers`` and
            ``attack_path_summary`` fields are used for the attack graph and
            path panels.

    Returns:
        Complete HTML string ready to write to a ``.html`` file, or ``None``
        if the feature is not available under the current license.
    """
    _con = console or _console
    if not is_pro_feature_available("dashboard"):
        _con.print(
            Panel(
                "[bold]The interactive dashboard requires mcp-audit Pro.[/bold]\n\n"
                "Your scan completed successfully. Results are available in terminal and JSON formats.\n\n"
                "Upgrade to Pro: [link=https://mcp-audit.dev/pro]https://mcp-audit.dev/pro[/link]\n"
                "Already have a key? Run: [bold]mcp-audit activate <your-key>[/bold]",
                title="Pro Feature",
                border_style="yellow",
            )
        )
        return None

    scan_data = _build_scan_data(result)
    d3_js = _load_d3()
    html = _DASHBOARD_HTML
    html = html.replace("__SCAN_DATA_JSON__", json.dumps(scan_data, indent=2))
    html = html.replace("__D3_JS__", d3_js)
    return html
