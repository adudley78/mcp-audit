"""Regression tests: XSS injection via finding fields in the HTML dashboard.

json.dumps() does not HTML-escape <, >, or & by default.  Without explicit
escaping, a malicious MCP server description containing </script> would close
the inline <script> block early and allow arbitrary HTML/JS injection in the
generated dashboard file.  generate_html() must Unicode-escape these chars.
"""

from __future__ import annotations

from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.output.dashboard import generate_html

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _result_with_description(description: str) -> ScanResult:
    """Return a ScanResult containing one finding with *description*."""
    finding = Finding(
        id="XSS-001",
        severity=Severity.HIGH,
        analyzer="poisoning",
        client="cursor",
        server="evil-server",
        title="XSS test finding",
        description=description,
        evidence=description,
        remediation="Remove the server.",
    )
    return ScanResult(
        clients_scanned=1,
        servers_found=1,
        findings=[finding],
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_script_tag_injection_in_description_is_neutralised() -> None:
    """A description containing </script> must not appear unescaped in the HTML."""
    payload = "</script><script>alert(1)</script>"
    html = generate_html(_result_with_description(payload))

    # The raw injection string must not appear verbatim inside the HTML.
    assert "</script><script>" not in html
    # The data must still be present, encoded as Unicode escapes.
    assert "\\u003c" in html


def test_ampersand_in_description_is_neutralised() -> None:
    """& must be escaped to \\u0026 to prevent entity injection."""
    html = generate_html(_result_with_description("foo & bar"))
    assert "\\u0026" in html
    # The literal ampersand must not appear inside the script block.  We check
    # the full HTML rather than trying to isolate the script tag, because any
    # occurrence of & in the JSON blob is dangerous.
    script_start = html.find("<script>")
    script_end = html.rfind("</script>")
    assert script_start != -1 and script_end != -1
    script_content = html[script_start:script_end]
    assert "foo & bar" not in script_content


# ── Scan strings rendered by the page's own JavaScript (STORY-0103) ──────────
#
# The JSON blob above is only half of it: the dashboard script then puts
# server names, finding titles and attack-path hops into the page with
# innerHTML.  A server name comes from a config file a cloned repository can
# plant; a COLLIDE-001 title carries a tool name a live server chose.  These
# tests run the generated page's real script under Node against a small DOM
# stub that records every innerHTML assignment, and fire the mouseover and
# click handlers so the tooltip and the re-rendered table run too.

import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402  # nosec B404 — runs node on a test-written file
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from mcp_audit.fleet.merger import FleetMerger, generate_fleet_html  # noqa: E402
from mcp_audit.models import (  # noqa: E402
    AttackPath,
    AttackPathSummary,
    ServerConfig,
    TransportType,
)
from mcp_audit.output.dashboard import (  # noqa: E402
    _DASHBOARD_HTML,
    _load_d3,
    fill_template,
    script_safe_json,
)

_IMG = "<img src=x onerror=alert(1)>"
_SCRIPT = "</script><script>alert(1)</script>"
_ATTR = 'x" onmouseover="alert(1)'
_JS_STR = "a');alert(1);('"
_EVIL_SERVER = f"{_IMG}{_ATTR}{_JS_STR}"

_NODE = shutil.which("node")
_needs_node = pytest.mark.skipif(_NODE is None, reason="node is not installed")

# A recording DOM: every innerHTML assignment is logged; d3 is a chainable
# proxy that keeps each .data() array so .on() handlers can be fired with it.
_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const LOG = [];
const LISTENED = [];
function el(){
  const e = {
    _html: '', style: {}, dataset: {}, children: [], listeners: {},
    classList: {add(){}, remove(){}, toggle(){}, contains(){ return false; }},
    parentElement: {clientWidth: 800, clientHeight: 600},
    clientWidth: 800, clientHeight: 600, textContent: '', title: '',
    className: '', value: '',
    appendChild(c){ this.children.push(c); return c; },
    addEventListener(t, fn){
      (this.listeners[t] = this.listeners[t] || []).push(fn); LISTENED.push(this);
    },
    setAttribute(){}, getAttribute(){ return 'dark'; },
  };
  Object.defineProperty(e, 'innerHTML', {
    get(){ return this._html; },
    set(v){ this._html = String(v); LOG.push(String(v)); },
  });
  return e;
}
const ids = {};
const READY = [];
const HANDLERS = [];
globalThis.window = globalThis;
globalThis.document = {
  getElementById(id){ return ids[id] || (ids[id] = el()); },
  createElement(){ return el(); },
  querySelectorAll(){ return []; },
  querySelector(){ return el(); },
  addEventListener(t, fn){ if (t === 'DOMContentLoaded') READY.push(fn); },
};
function chain(data){
  let p;
  p = new Proxy(function(){}, {
    get(_, prop){
      if (prop === Symbol.toPrimitive) return () => 0;
      if (prop === 'data') return (arr) => chain(Array.isArray(arr) ? arr : data);
      if (prop === 'on') return (ev, fn) => {
        if (typeof fn === 'function') HANDLERS.push({ev, fn, data});
        return p;
      };
      return () => p;
    },
    apply(){ return p; },
  });
  return p;
}
globalThis.d3 = chain([]);
const html = fs.readFileSync(process.argv[2], 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
// [0] the data, [1] the D3 bundle (replaced by the stub), [2] the page script.
vm.runInThisContext(scripts[0]);
vm.runInThisContext(scripts[2]);
READY.forEach(fn => fn());
const ev = {pageX: 0, pageY: 0, stopPropagation(){}};
for (const h of HANDLERS) {
  if (h.ev !== 'mouseover' && h.ev !== 'click') continue;
  for (const d of h.data) { try { h.fn.call(el(), ev, d); } catch (e) {} }
}
for (const e of LISTENED.slice()) {
  for (const fn of (e.listeners.click || [])) { try { fn(ev); } catch (x) {} }
}
process.stdout.write(JSON.stringify(LOG));
"""


def _rendered_html(tmp_path: Path, page: str) -> list[str]:
    """Run *page*'s script under node; return every innerHTML assigned."""
    page_file = tmp_path / "page.html"
    page_file.write_text(page, encoding="utf-8")
    harness = tmp_path / "harness.js"
    harness.write_text(_HARNESS, encoding="utf-8")
    proc = subprocess.run(  # noqa: S603  # nosec B603 — fixed argv, test files
        [str(_NODE), str(harness), str(page_file)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _assert_no_live_markup(fragments: list[str], *, expect: str) -> None:
    joined = "\n".join(fragments)
    assert expect in joined  # the hostile strings were actually rendered
    lowered = joined.lower()
    assert "<img" not in lowered
    assert "<script" not in lowered
    assert 'onmouseover="' not in lowered
    assert "alert(1);('" not in joined  # the single quote is an entity


def _hostile_result() -> ScanResult:
    evil = _EVIL_SERVER
    other = "fetch"
    finding = Finding(
        id="COLLIDE-001",
        severity=Severity.HIGH,
        analyzer="collision",
        client=f"cursor{_IMG}",
        server=evil,
        title=f"Tool name collision: {_SCRIPT}{_IMG}",
        description=_IMG,
        evidence=_IMG,
        remediation="r",
    )
    toxic = Finding(
        id="TOXIC-001",
        severity=Severity.CRITICAL,
        analyzer="toxic_flow",
        client="cursor",
        server=f"{evil} + {other}",
        title=f"toxic {_IMG}",
        description="d",
        evidence="e",
        remediation="r",
    )
    servers = [
        ServerConfig(
            name=name,
            client=f"cursor{_IMG}",
            config_path=Path("/repo/.mcp.json"),
            transport=TransportType.STDIO,
            command="npx",
            args=["-y", "x"],
        )
        for name in (evil, other)
    ]
    path = AttackPath(
        id="PATH-001",
        severity=Severity.CRITICAL,
        title=f"path {_IMG}",
        description=f"desc {_SCRIPT}",
        hops=[evil, other],
        source_capability="file_read",
        sink_capability="network_out",
    )
    return ScanResult(
        clients_scanned=1,
        servers_found=2,
        servers=servers,
        findings=[finding, toxic],
        attack_path_summary=AttackPathSummary(
            paths=[path], hitting_set=[evil], paths_broken_by={evil: ["PATH-001"]}
        ),
    )


@_needs_node
def test_dashboard_renders_scan_strings_as_text(tmp_path: Path) -> None:
    fragments = _rendered_html(tmp_path, generate_html(_hostile_result()))
    _assert_no_live_markup(fragments, expect="&lt;img src=x onerror=alert(1)&gt;")
    joined = "\n".join(fragments)
    assert "&quot; onmouseover=&quot;" in joined
    assert "tt-name" in joined  # the tooltip ran
    assert "hs-name" in joined  # the hitting-set panel ran
    assert "pc-title" in joined  # the attack-path cards ran


@_needs_node
def test_fleet_report_renders_scan_strings_as_text(tmp_path: Path) -> None:
    scan = {
        "version": "0.21.1",
        "timestamp": "2026-04-16T10:00:00+00:00",
        "machine": {
            "hostname": _EVIL_SERVER,
            "username": "u",
            "os": "Linux",
            "os_version": "1",
            "scan_id": "00000000-0000-0000-0000-000000000001",
        },
        "clients_scanned": 1,
        "servers_found": 1,
        "servers": [],
        "findings": [
            {
                "id": "COLLIDE-001",
                "severity": "HIGH",
                "analyzer": f"collision{_IMG}",
                "client": "cursor",
                "server": _EVIL_SERVER,
                "title": f"{_SCRIPT}{_IMG}",
                "description": "d",
                "evidence": "e",
                "remediation": "r",
            }
        ],
        "errors": [],
        "attack_path_summary": None,
        "score": {
            "numeric_score": 50,
            "grade": "F",
            "positive_signals": [],
            "deductions": [],
        },
    }
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(scan), encoding="utf-8")
    page = generate_fleet_html(FleetMerger().merge([scan_file]))
    fragments = _rendered_html(tmp_path, page)
    _assert_no_live_markup(fragments, expect="&lt;img src=x onerror=alert(1)&gt;")


@pytest.mark.parametrize(
    "page",
    [
        lambda: generate_html(_hostile_result()),
        lambda: _fleet_page_for_static_checks(),
    ],
    ids=["dashboard", "fleet"],
)
def test_embedded_json_cannot_end_the_script(page) -> None:  # noqa: ANN001
    html = page()
    data_script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    assert "</script" not in data_script.lower()
    for raw in ("<", ">", "&"):
        assert raw not in data_script.split("=", 1)[1]
    assert html.lower().count("<img") == 0


def _fleet_page_for_static_checks() -> str:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        scan_file = Path(tmp) / "scan.json"
        test_fleet_payload = {
            "version": "0.21.1",
            "timestamp": "2026-04-16T10:00:00+00:00",
            "machine": {
                "hostname": _EVIL_SERVER,
                "username": "u",
                "os": "Linux",
                "os_version": "1",
                "scan_id": "s",
            },
            "clients_scanned": 1,
            "servers_found": 1,
            "servers": [],
            "findings": [],
            "errors": [],
            "attack_path_summary": None,
            "score": None,
        }
        scan_file.write_text(json.dumps(test_fleet_payload), encoding="utf-8")
        return generate_fleet_html(FleetMerger().merge([scan_file]))


def test_a_server_named_like_a_marker_stays_data() -> None:
    """Two chained str.replace calls spliced the D3 bundle into the JSON."""
    result = _hostile_result()
    result.servers[1].name = "__D3_JS__"
    html = generate_html(result)
    data_script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    data = json.loads(data_script.split("=", 1)[1].strip().rstrip(";"))
    assert "__D3_JS__" in [s["name"] for s in data["servers"]]
    assert html.count(_load_d3()[:200]) == 1  # the bundle, once, in its own tag


def test_fill_template_is_single_pass() -> None:
    out = fill_template("[A][B]", {"[A]": "[B]", "[B]": "x\\1"})
    assert out == "[B]x\\1"


def test_script_safe_json_round_trips() -> None:
    value = {"s": "</script><!-- &  "}
    text = script_safe_json(value)
    assert not re.search(r"[<>& ]", text)
    assert json.loads(text) == value


def test_template_has_no_inline_handler_built_from_data() -> None:
    """An inline onclick that interpolates data cannot be made safe by
    escaping (entities decode before the JavaScript runs)."""
    for literal in re.findall(r"`[^`]*`", _DASHBOARD_HTML):
        if "<" in literal and "${" in literal:
            assert not re.search(r"\bon[a-z]+\s*=", literal), literal


# Interpolations in HTML-building template literals that are not esc(...):
# each is itself built only from esc(...) output or constants.
_PREBUILT = {
    "dot",  # `<span class="sev-dot" style="background:${col}">`
    "sevTxt",  # `<span style="color:${col}">${esc(f.severity)}</span>`
    "col",  # esc(sevColor(f.severity))
    "chainHtml",  # hops, each `<span>${esc(h)}</span>`
    "sevBadge(p.severity)",  # escapes its argument
    "v",  # inside sevBadge: esc(sev||'INFO')
    "total!==1?'s':''",
}


def test_every_dashboard_interpolation_into_html_is_escaped() -> None:
    script = _DASHBOARD_HTML.split("<!-- Dashboard application -->", 1)[1]
    checked = 0
    for literal in re.findall(r"`[^`]*`", script):
        if "<" not in literal:
            continue  # not markup: textContent, attributes, CSS, transforms
        for expr in re.findall(r"\$\{(.*?)\}(?=[^}]|$)", literal):
            expr = expr.strip()
            assert expr.startswith("esc(") or expr in _PREBUILT, (expr, literal)
            checked += 1
    assert checked >= 25  # the audit found the tooltip, cards and table
