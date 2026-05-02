# ruff: noqa: E501
"""Fleet merger — consolidates JSON scan outputs from multiple machines.

Typical workflow:
1. Each machine runs: mcp-audit scan --format json --output-file results.json
2. Collect all JSON files to a central directory.
3. Run: mcp-audit merge --dir ./results/

The merger deduplicates findings across machines by grouping on
(analyzer, server_name, title). A finding that appears on 12 of 15
machines is represented once with affected_count=12.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import warnings
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from mcp_audit import __version__
from mcp_audit._paths import data_dir
from mcp_audit.models import Finding, ScanScore, Severity

_SCANNER_VERSION = __version__

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Required top-level keys that identify a file as mcp-audit JSON output.
# Accept both "machine_info" (current) and legacy "machine" for backward
# compatibility with scan files produced before the key rename.
_REQUIRED_KEYS: frozenset[str] = frozenset({"version", "timestamp", "findings"})
_MACHINE_KEYS: tuple[str, ...] = ("machine_info", "machine")


# ── Data models ───────────────────────────────────────────────────────────────


class MachineReport(BaseModel):
    """A single machine's scan result as ingested by the fleet merger."""

    machine_id: str
    """Derived from MachineInfo.hostname or asset_id when --asset-prefix was set."""

    asset_prefix: str | None
    """Always None when loaded from JSON — machine_info.asset_id carries the value."""

    scanner_version: str
    scan_timestamp: datetime
    findings: list[Finding]
    score: ScanScore | None
    server_count: int
    source_file: str


class DeduplicatedFinding(BaseModel):
    """A finding that may affect multiple machines.

    Machines are deduplicated on (analyzer, server_name, title). A finding that
    appears on three different machines is represented once with affected_count=3.
    """

    finding_id: str
    """SHA-256 of '{analyzer}:{server_name}:{title}', truncated to 16 hex chars."""

    analyzer: str
    server_name: str
    severity: Severity
    title: str
    description: str
    affected_machines: list[str]
    affected_count: int
    first_seen: datetime
    """Earliest scan_timestamp among all affected machines."""


class FleetStats(BaseModel):
    """Summary statistics across all machines in a fleet report."""

    total_machines: int
    total_findings: int
    unique_findings: int
    most_common_finding: str | None
    """Title of the DeduplicatedFinding affecting the most machines."""

    riskiest_machine: str | None
    """machine_id with the highest count of CRITICAL + HIGH findings."""

    severity_breakdown: dict[str, int]
    """Total finding count per severity level across all machines."""

    average_score: float | None
    lowest_score_machine: str | None


class FleetReport(BaseModel):
    """The complete merged output from a fleet scan."""

    generated_at: datetime
    scanner_version: str
    machine_count: int
    machines: list[MachineReport]
    deduplicated_findings: list[DeduplicatedFinding]
    stats: FleetStats
    version_mismatches: list[str]
    """Human-readable warnings for machines that ran a non-majority scanner version."""


# ── Merger ────────────────────────────────────────────────────────────────────


class FleetMerger:
    """Loads and merges JSON scan outputs from multiple machines.

    Args:
        asset_prefix_filter: When set, only machines whose machine_id starts
            with this string are included in the merged report. Useful for
            filtering to a subset of the fleet (e.g. ``"prod-"``).

    Note:
        ``asset_prefix`` is not persisted in scan JSON output. Filtering is
        applied against ``machine_id`` (the machine's hostname). See GAPS.md.
    """

    def __init__(self, asset_prefix_filter: str | None = None) -> None:
        self.asset_prefix_filter = asset_prefix_filter

    def load_report(self, path: Path) -> MachineReport:
        """Load a single JSON scan output file and return a :class:`MachineReport`.

        Args:
            path: Path to the JSON file produced by ``mcp-audit scan --format json``.

        Returns:
            A :class:`MachineReport` populated from the file.

        Raises:
            ValueError: If the file is not readable, not valid JSON, or does not
                contain the required mcp-audit fields.
        """
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Cannot read {path}: {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(
                f"{path} is not a valid mcp-audit JSON output "
                f"(expected object, got {type(data).__name__})"
            )

        missing = _REQUIRED_KEYS - data.keys()
        if missing:
            raise ValueError(
                f"{path} is missing required mcp-audit fields: "
                f"{', '.join(sorted(missing))}"
            )

        machine = next(
            (data[k] for k in _MACHINE_KEYS if k in data and isinstance(data[k], dict)),
            {},
        )
        if "hostname" not in machine:
            raise ValueError(
                f"{path}: scan file must contain a 'machine_info' object "
                "with a 'hostname' field"
            )

        # Warn (don't crash) on version mismatch.
        file_version = str(data.get("version", "unknown"))
        if file_version != _SCANNER_VERSION:
            warnings.warn(
                f"{path.name}: scanner version mismatch "
                f"(file={file_version!r}, current={_SCANNER_VERSION!r}). "
                "Results may differ from current analysis rules.",
                stacklevel=2,
            )

        # Parse timestamp.
        ts_raw = data["timestamp"]
        try:
            scan_timestamp = datetime.fromisoformat(str(ts_raw))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{path}: invalid timestamp value: {ts_raw!r}") from exc

        # Parse findings — skip any that don't conform to the Finding model.
        findings: list[Finding] = []
        for f_data in data.get("findings", []):
            if not isinstance(f_data, dict):
                continue
            with contextlib.suppress(Exception):
                findings.append(Finding(**f_data))

        # Parse score — optional, silently skip on failure.
        score: ScanScore | None = None
        raw_score = data.get("score")
        if isinstance(raw_score, dict):
            with contextlib.suppress(Exception):
                score = ScanScore(**raw_score)

        machine_id = machine.get("hostname", "unknown")

        return MachineReport(
            machine_id=machine_id,
            asset_prefix=None,
            scanner_version=file_version,
            scan_timestamp=scan_timestamp,
            findings=findings,
            score=score,
            server_count=int(data.get("servers_found", 0)),
            source_file=str(path),
        )

    def merge(self, paths: list[Path]) -> FleetReport:
        """Merge scan output files into a single :class:`FleetReport`.

        Args:
            paths: Paths to JSON scan output files. Each is loaded via
                :meth:`load_report`; failures propagate as :class:`ValueError`.

        Returns:
            A :class:`FleetReport` with deduplicated findings and fleet-wide stats.

        Raises:
            ValueError: If ``paths`` is empty, or if no machines remain after
                applying :attr:`asset_prefix_filter`.
        """
        if not paths:
            raise ValueError("No scan files provided to merge")

        machines: list[MachineReport] = [self.load_report(p) for p in paths]

        # Apply machine-level filter on machine_id prefix.
        if self.asset_prefix_filter is not None:
            machines = [
                m for m in machines if m.machine_id.startswith(self.asset_prefix_filter)
            ]

        if not machines:
            raise ValueError(
                f"No machine reports remain after applying "
                f"asset_prefix_filter={self.asset_prefix_filter!r}"
            )

        # Version mismatch: find majority version, flag outliers.
        version_counts: Counter[str] = Counter(m.scanner_version for m in machines)
        majority_version = version_counts.most_common(1)[0][0]
        version_mismatches = [
            f"{m.machine_id}: ran version {m.scanner_version!r} "
            f"(majority is {majority_version!r})"
            for m in machines
            if m.scanner_version != majority_version
        ]

        # Deduplication: group by (analyzer, server_name, title).
        groups: dict[tuple[str, str, str], list[tuple[str, datetime, Finding]]] = {}
        for machine in machines:
            for finding in machine.findings:
                key = (finding.analyzer, finding.server, finding.title)
                groups.setdefault(key, []).append(
                    (machine.machine_id, machine.scan_timestamp, finding)
                )

        deduplicated: list[DeduplicatedFinding] = []
        for (analyzer, server_name, title), entries in groups.items():
            # Collect unique machine_ids preserving order of first appearance.
            seen_machines: dict[str, None] = {}
            first_seen = entries[0][1]
            sample_finding = entries[0][2]
            for mid, ts, _ in entries:
                seen_machines[mid] = None
                if ts < first_seen:
                    first_seen = ts

            machine_ids = list(seen_machines.keys())

            finding_id = hashlib.sha256(
                f"{analyzer}:{server_name}:{title}".encode()
            ).hexdigest()[:16]

            deduplicated.append(
                DeduplicatedFinding(
                    finding_id=finding_id,
                    analyzer=analyzer,
                    server_name=server_name,
                    severity=sample_finding.severity,
                    title=title,
                    description=sample_finding.description,
                    affected_machines=machine_ids,
                    affected_count=len(machine_ids),
                    first_seen=first_seen,
                )
            )

        # Sort: affected_count desc, then severity ascending index (CRITICAL=0 first).
        deduplicated.sort(
            key=lambda d: (-d.affected_count, _SEVERITY_ORDER[d.severity])
        )

        stats = _calculate_fleet_stats(machines, deduplicated)

        return FleetReport(
            generated_at=datetime.now(UTC),
            scanner_version=_SCANNER_VERSION,
            machine_count=len(machines),
            machines=machines,
            deduplicated_findings=deduplicated,
            stats=stats,
            version_mismatches=version_mismatches,
        )


# ── Internal helpers ──────────────────────────────────────────────────────────


def _calculate_fleet_stats(
    machines: list[MachineReport],
    deduplicated: list[DeduplicatedFinding],
) -> FleetStats:
    """Compute :class:`FleetStats` from a list of loaded machine reports."""
    total_findings = sum(len(m.findings) for m in machines)
    unique_findings = len(deduplicated)

    most_common_finding = deduplicated[0].title if deduplicated else None

    # Riskiest machine: highest count of CRITICAL + HIGH findings.
    risk_counts: dict[str, int] = {
        m.machine_id: sum(
            1 for f in m.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        for m in machines
    }
    max_risk = max(risk_counts.values(), default=0)
    riskiest_machine = (
        max(risk_counts, key=lambda k: risk_counts[k]) if max_risk > 0 else None
    )

    # Severity breakdown across all machines.
    severity_breakdown: dict[str, int] = {sev.value: 0 for sev in Severity}
    for machine in machines:
        for f in machine.findings:
            severity_breakdown[f.severity.value] += 1

    # Score aggregation.
    scored = [
        (m.machine_id, m.score.numeric_score) for m in machines if m.score is not None
    ]
    average_score: float | None = (
        round(sum(s for _, s in scored) / len(scored), 1) if scored else None
    )
    lowest_score_machine: str | None = (
        min(scored, key=lambda x: x[1])[0] if scored else None
    )

    return FleetStats(
        total_machines=len(machines),
        total_findings=total_findings,
        unique_findings=unique_findings,
        most_common_finding=most_common_finding,
        riskiest_machine=riskiest_machine,
        severity_breakdown=severity_breakdown,
        average_score=average_score,
        lowest_score_machine=lowest_score_machine,
    )


# ── Fleet HTML dashboard ───────────────────────────────────────────────────────

# Worst-first ordering: F is most critical, A is cleanest.
_GRADE_ORDER: list[str] = ["F", "D", "C", "B", "A"]


def _load_d3() -> str:
    """Return the bundled D3.js v7 minified source."""
    return (data_dir() / "d3.v7.min.js").read_text(encoding="utf-8")


def _build_fleet_data(report: FleetReport) -> dict:
    """Serialise *report* into the JSON blob embedded in the fleet dashboard.

    Args:
        report: The merged :class:`FleetReport`.

    Returns:
        A plain dict suitable for :func:`json.dumps`.
    """
    grades: list[str] = []
    machines_data: list[dict] = []

    for m in report.machines:
        sev_breakdown: dict[str, int] = {sev.value: 0 for sev in Severity}
        for f in m.findings:
            sev_breakdown[f.severity.value] += 1

        grade = m.score.grade if m.score else None
        numeric_score = m.score.numeric_score if m.score else None

        if grade and grade in _GRADE_ORDER:
            grades.append(grade)

        machines_data.append(
            {
                "machine_id": m.machine_id,
                "grade": grade,
                "numeric_score": numeric_score,
                "finding_count": len(m.findings),
                "severity_breakdown": sev_breakdown,
                "scan_timestamp": m.scan_timestamp.strftime("%Y-%m-%d %H:%M UTC"),
            }
        )

    # Fleet grade = worst grade across all machines (lowest index in _GRADE_ORDER).
    fleet_grade: str | None = (
        min(grades, key=lambda g: _GRADE_ORDER.index(g)) if grades else None
    )

    findings_data = [
        {
            "finding_id": df.finding_id,
            "analyzer": df.analyzer,
            "server_name": df.server_name,
            "severity": df.severity.value,
            "title": df.title,
            "description": df.description,
            "affected_machines": df.affected_machines,
            "affected_count": df.affected_count,
            "first_seen": df.first_seen.strftime("%Y-%m-%d %H:%M UTC"),
        }
        for df in report.deduplicated_findings
    ]

    return {
        "generated_at": report.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        "scanner_version": report.scanner_version,
        "fleet_grade": fleet_grade,
        "machines": machines_data,
        "findings": findings_data,
        "stats": {
            "total_machines": report.stats.total_machines,
            "total_findings": report.stats.total_findings,
            "unique_findings": report.stats.unique_findings,
            "average_score": report.stats.average_score,
            "riskiest_machine": report.stats.riskiest_machine,
            "severity_breakdown": report.stats.severity_breakdown,
            "most_common_finding": report.stats.most_common_finding,
        },
        "version_mismatches": report.version_mismatches,
    }


# Uses __FLEET_DATA_JSON__ and __D3_JS__ as substitution markers so that the
# abundant JavaScript { } and ${ } syntax never collides with Python str.format()
# or f-string interpretation.
_FLEET_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcp-audit — Fleet Dashboard</title>
<style>
[data-theme="dark"]{
  --bg-deep:#0c0c1a;--bg-panel:#13132a;--bg-card:#1a1a38;--bg-hover:#222250;
  --border:#2a2a55;--border-light:#3a3a6a;
  --text-primary:#e8e8f0;--text-secondary:#9898b8;--text-dim:#6868a0;
  --crit:#ff3b4f;--high:#ff8c2e;--med:#ffcc30;--low:#4a9eff;--info:#6b7280;
  --safe:#22cc66;--accent:#00ccff;
  --row-hover:rgba(255,255,255,.03);
}
[data-theme="light"]{
  --bg-deep:#f0f1f5;--bg-panel:#ffffff;--bg-card:#f5f5fa;--bg-hover:#eeeef5;
  --border:#d8d8e8;--border-light:#c0c0d8;
  --text-primary:#1a1a2e;--text-secondary:#5a5a78;--text-dim:#8888a8;
  --crit:#dc2626;--high:#ea580c;--med:#ca8a04;--low:#2563eb;--info:#6b7280;
  --safe:#16a34a;--accent:#0088cc;
  --row-hover:rgba(0,0,0,.03);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{
  background:var(--bg-deep);color:var(--text-primary);
  font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:13px;
  display:flex;flex-direction:column;
}

/* ── Top bar ── */
.top-bar{
  flex-shrink:0;display:flex;align-items:center;justify-content:space-between;
  padding:0 20px;height:56px;background:var(--bg-panel);
  border-bottom:1px solid var(--border);z-index:10;
}
.logo{display:flex;align-items:baseline;gap:6px}
.logo-name{
  font-family:"JetBrains Mono",ui-monospace,"Cascadia Code","Fira Code",monospace;font-size:15px;font-weight:600;
  color:var(--accent);letter-spacing:.3px;
}
.logo-sub{
  font-family:"JetBrains Mono",ui-monospace,"Cascadia Code","Fira Code",monospace;font-size:11px;
  color:var(--text-dim);letter-spacing:.2px;
}
.top-center{display:flex;align-items:center;gap:18px}
.top-stat{display:flex;flex-direction:column;align-items:center}
.ts-num{font-size:18px;font-weight:700;line-height:1;color:var(--text-primary)}
.ts-label{font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
.ts-divider{width:1px;height:28px;background:var(--border);flex-shrink:0}
.top-right{display:flex;align-items:center;gap:12px}
.fleet-grade-badge{
  display:flex;align-items:center;gap:8px;padding:4px 12px;
  border-radius:6px;border:1px solid var(--border);background:var(--bg-card);
}
.grade-meta{display:flex;flex-direction:column;gap:1px}
.grade-label-sm{font-size:9px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-dim)}
.grade-row{display:flex;align-items:baseline;gap:5px}
.grade-letter{font-size:22px;font-weight:700;line-height:1}
.grade-num{font-size:12px;font-weight:600;color:var(--text-secondary)}
.top-date{font-size:11px;color:var(--text-dim);font-family:"JetBrains Mono",ui-monospace,monospace}

/* ── Theme toggle ── */
.theme-toggle{
  width:36px;height:20px;border-radius:10px;border:1px solid var(--border);
  background:var(--bg-card);cursor:pointer;position:relative;
  transition:background .2s;display:flex;align-items:center;padding:0 3px;flex-shrink:0;
}
.theme-toggle::after{
  content:'';width:14px;height:14px;border-radius:50%;background:var(--accent);
  transition:transform .2s;position:absolute;left:3px;
}
[data-theme="light"] .theme-toggle::after{transform:translateX(16px)}
.theme-toggle::before{
  content:'●';font-size:9px;color:var(--text-dim);
  position:absolute;right:4px;top:50%;transform:translateY(-50%);pointer-events:none;line-height:1;
}
[data-theme="light"] .theme-toggle::before{content:'☀';right:auto;left:4px}

/* ── Summary bar ── */
.summary-bar{
  flex-shrink:0;padding:5px 16px;background:var(--bg-deep);
  border-bottom:1px solid var(--border);
  font-size:11px;color:var(--text-dim);
  font-family:"JetBrains Mono",ui-monospace,monospace;letter-spacing:.15px;
}

/* ── Section headers ── */
.section-hdr{
  flex-shrink:0;display:flex;align-items:center;gap:8px;
  padding:7px 16px;border-bottom:1px solid var(--border);
  background:var(--bg-panel);
}
.section-label{
  font-size:11px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;
  color:var(--text-secondary);
}
.section-count{font-size:11px;color:var(--text-dim);font-family:"JetBrains Mono",ui-monospace,monospace}

/* ── Machine grid ── */
.machines-section{flex-shrink:0;background:var(--bg-panel);border-bottom:1px solid var(--border)}
.machine-grid{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));
  gap:10px;padding:12px 16px;max-height:210px;overflow-y:auto;
}
.machine-card{
  background:var(--bg-card);border:1px solid var(--border);border-radius:8px;
  padding:11px 12px;cursor:pointer;transition:border-color .15s,background .15s;
  display:flex;flex-direction:column;gap:7px;
}
.machine-card:hover{border-color:var(--border-light);background:var(--bg-hover)}
.machine-card.selected{border-color:var(--accent)}
[data-theme="dark"] .machine-card.selected{background:rgba(0,204,255,.06)}
[data-theme="light"] .machine-card.selected{background:rgba(0,136,204,.08)}
.mc-header{display:flex;align-items:center;justify-content:space-between;gap:6px}
.mc-hostname{
  font-family:"JetBrains Mono",ui-monospace,monospace;font-size:11px;font-weight:500;
  color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;
}
.mc-grade{
  font-size:13px;font-weight:700;line-height:1;flex-shrink:0;
  padding:1px 6px;border-radius:4px;border:1px solid currentColor;
}
.mc-counts{font-size:11px;color:var(--text-secondary);line-height:1.35}
.mc-counts b{font-weight:600}
.sev-bar{height:5px;border-radius:3px;overflow:hidden;display:flex;gap:1px;background:var(--border)}
.sev-seg{height:100%;flex-shrink:0;transition:opacity .15s}

/* ── Findings section ── */
.findings-section{
  flex:1;display:flex;flex-direction:column;overflow:hidden;
  background:var(--bg-panel);
}
.filter-bar{
  flex-shrink:0;display:flex;align-items:center;gap:8px;flex-wrap:wrap;
  padding:7px 14px;border-bottom:1px solid var(--border);
}
.findings-label{
  font-size:11px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;
  color:var(--text-secondary);white-space:nowrap;
}
.filter-sep{width:1px;height:16px;background:var(--border);flex-shrink:0}
.filter-group{display:flex;gap:5px;flex-wrap:wrap;align-items:center}
.filter-btn{
  font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;
  padding:3px 10px;border-radius:20px;border:1px solid var(--border);
  background:transparent;color:var(--text-dim);cursor:pointer;
  font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;transition:all .12s;
}
.filter-btn:hover{border-color:var(--border-light);color:var(--text-secondary)}
.filter-btn.active-all{background:rgba(232,232,240,.08);color:var(--text-primary);border-color:var(--border-light)}
.filter-select{
  font-size:11px;padding:3px 8px;border-radius:4px;
  border:1px solid var(--border);background:var(--bg-card);color:var(--text-secondary);
  cursor:pointer;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  outline:none;
}
.filter-select:focus{border-color:var(--accent)}

/* ── Table ── */
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
.findings-table tr:hover td{background:var(--row-hover)}
.td-sev{display:flex;align-items:center;gap:6px;white-space:nowrap}
.sev-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.td-mono{font-family:"JetBrains Mono",ui-monospace,monospace;font-size:11px;color:var(--text-secondary)}

/* ── Scrollbars ── */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
</style>
</head>
<body class="fleet-dash" data-theme="dark">

<!-- Top bar -->
<header class="top-bar">
  <div class="logo">
    <span class="logo-name">mcp-audit</span>
    <span class="logo-sub">Fleet Dashboard</span>
  </div>
  <div class="top-center" id="top-center"></div>
  <div class="top-right">
    <span class="top-date" id="top-date"></span>
    <div class="fleet-grade-badge" id="fleet-grade-badge" style="display:none" title="Worst-case fleet grade">
      <div class="grade-meta">
        <span class="grade-label-sm">Fleet Grade</span>
        <div class="grade-row">
          <span class="grade-letter" id="fleet-grade-letter"></span>
          <span class="grade-num" id="fleet-grade-num"></span>
        </div>
      </div>
    </div>
    <button class="theme-toggle" onclick="toggleTheme()"
            aria-label="Toggle light/dark theme" title="Toggle light/dark theme"></button>
  </div>
</header>

<!-- Summary bar -->
<div class="summary-bar" id="summary-bar"></div>

<!-- Machine grid -->
<section class="machines-section" id="machines-section">
  <div class="section-hdr">
    <span class="section-label">Fleet Summary</span>
    <span class="section-count" id="machines-count"></span>
  </div>
  <div class="machine-grid" id="machine-grid"></div>
</section>

<!-- Findings table -->
<section class="findings-section">
  <div class="filter-bar">
    <span class="findings-label">Findings</span>
    <div class="filter-sep"></div>
    <div class="filter-group" id="sev-filters"></div>
    <div class="filter-sep"></div>
    <select class="filter-select" id="machine-select" onchange="onMachineSelect()" title="Filter by machine">
      <option value="">All Machines</option>
    </select>
    <select class="filter-select" id="analyzer-select" onchange="onAnalyzerSelect()" title="Filter by analyzer">
      <option value="">All Analyzers</option>
    </select>
  </div>
  <div class="table-wrap">
    <table class="findings-table">
      <thead>
        <tr>
          <th data-col="severity">Severity</th>
          <th data-col="affected_count">Machines</th>
          <th data-col="analyzer">Analyzer</th>
          <th data-col="server_name">Server</th>
          <th data-col="title">Finding</th>
        </tr>
      </thead>
      <tbody id="findings-tbody"></tbody>
    </table>
  </div>
</section>

<!-- Embedded fleet data -->
<script>const FLEET_DATA = __FLEET_DATA_JSON__;</script>

<!-- D3.js v7 (embedded, no CDN) -->
<script>__D3_JS__</script>

<!-- Fleet dashboard application -->
<script>
(function(){
'use strict';

const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
const PALETTE = {
  dark:{CRITICAL:'#ff3b4f',HIGH:'#ff8c2e',MEDIUM:'#ffcc30',LOW:'#4a9eff',INFO:'#6b7280'},
  light:{CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#ca8a04',LOW:'#2563eb',INFO:'#6b7280'},
};
let SC = Object.assign({}, PALETTE.dark);

const GRADE_COLORS = {A:'var(--safe)',B:'var(--low)',C:'var(--med)',D:'var(--high)',F:'var(--crit)'};
function gradeColor(g){ return GRADE_COLORS[g] || 'var(--text-dim)'; }
function sevColor(s){ return SC[s] || SC.INFO; }
function trunc(s, n){ return s && s.length > n ? s.slice(0, n) + '\u2026' : (s || ''); }

let state = {sevFilt:'', machineFilt:'', analyzerFilt:'', sortCol:'severity', sortAsc:true};

// ── Header ────────────────────────────────────────────────────────────────────
function initHeader(){
  const D = FLEET_DATA;
  const s = D.stats;

  // Top-centre stat tiles
  const critH = (s.severity_breakdown.CRITICAL||0) + (s.severity_breakdown.HIGH||0);
  let tc = document.getElementById('top-center');
  tc.innerHTML =
    tile(s.total_machines, 'Machines') +
    divider() +
    tile(s.total_findings, 'Findings') +
    divider() +
    `<div class="top-stat"><div class="ts-num" style="color:var(--crit)">${critH}</div><div class="ts-label">Crit+High</div></div>` +
    (s.average_score != null
      ? divider() + tile(s.average_score.toFixed(1), 'Avg Score')
      : '');

  document.getElementById('top-date').textContent = D.generated_at;
  document.getElementById('machines-count').textContent =
    D.machines.length + ' machine' + (D.machines.length !== 1 ? 's' : '');

  // Summary bar
  const parts = [];
  if(s.riskiest_machine) parts.push('Riskiest: ' + s.riskiest_machine);
  if(s.most_common_finding) parts.push('Top issue: ' + trunc(s.most_common_finding, 55));
  if(D.version_mismatches && D.version_mismatches.length)
    parts.push(D.version_mismatches.length + ' version mismatch(es)');
  document.getElementById('summary-bar').textContent =
    parts.length ? parts.join('  \u00b7  ') : 'mcp-audit v' + D.scanner_version;

  // Fleet grade badge
  if(D.fleet_grade){
    const badge = document.getElementById('fleet-grade-badge');
    const letter = document.getElementById('fleet-grade-letter');
    const num = document.getElementById('fleet-grade-num');
    letter.textContent = D.fleet_grade;
    letter.style.color = gradeColor(D.fleet_grade);
    const scores = D.machines.filter(m=>m.numeric_score!=null).map(m=>m.numeric_score);
    if(scores.length) num.textContent = Math.min.apply(null, scores) + '/100';
    badge.style.display = 'flex';
  }
}

function tile(val, label){
  return '<div class="top-stat"><div class="ts-num">' + val + '</div><div class="ts-label">' + label + '</div></div>';
}
function divider(){ return '<div class="ts-divider"></div>'; }

// ── Machine grid ──────────────────────────────────────────────────────────────
function initMachineGrid(){
  const grid = document.getElementById('machine-grid');
  grid.innerHTML = '';

  if(!FLEET_DATA.machines.length){
    grid.innerHTML = '<div style="color:var(--text-dim);padding:16px;font-size:12px">No machines in fleet.</div>';
    return;
  }

  FLEET_DATA.machines.forEach(function(m){
    const card = document.createElement('div');
    card.className = 'machine-card';
    card.dataset.mid = m.machine_id;

    const gradeEl = m.grade
      ? '<span class="mc-grade" style="color:' + gradeColor(m.grade) + ';border-color:' + gradeColor(m.grade) + '">' + m.grade + '</span>'
      : '<span class="mc-grade" style="color:var(--text-dim);border-color:var(--border)">\u2013</span>';

    const crit = m.severity_breakdown.CRITICAL||0;
    const high = m.severity_breakdown.HIGH||0;
    const med  = m.severity_breakdown.MEDIUM||0;
    const low  = m.severity_breakdown.LOW||0;
    const info = m.severity_breakdown.INFO||0;
    const total = m.finding_count;

    const countTxt = total > 0
      ? '<b style="color:var(--crit)">' + crit + '</b> crit \u00b7 ' +
        '<b style="color:var(--high)">' + high + '</b> high \u00b7 ' +
        total + ' total'
      : '<b style="color:var(--safe)">No findings</b>';

    // Mini severity bar
    let barSegs = '';
    if(total > 0){
      [['CRITICAL',crit],['HIGH',high],['MEDIUM',med],['LOW',low],['INFO',info]].forEach(function(pair){
        const sev = pair[0], cnt = pair[1];
        if(!cnt) return;
        const pct = (cnt / total * 100).toFixed(1);
        barSegs += '<div class="sev-seg" style="width:' + pct + '%;background:' + sevColor(sev) + '" title="' + sev + ': ' + cnt + '"></div>';
      });
    } else {
      barSegs = '<div class="sev-seg" style="width:100%;background:var(--safe)" title="Clean"></div>';
    }

    card.innerHTML =
      '<div class="mc-header"><span class="mc-hostname" title="' + m.machine_id + '">' + trunc(m.machine_id, 22) + '</span>' + gradeEl + '</div>' +
      '<div class="mc-counts">' + countTxt + '</div>' +
      '<div class="sev-bar">' + barSegs + '</div>';

    card.addEventListener('click', function(){
      const isSelected = card.classList.contains('selected');
      document.querySelectorAll('.machine-card').forEach(function(c){ c.classList.remove('selected'); });
      const machSel = document.getElementById('machine-select');
      if(!isSelected){
        card.classList.add('selected');
        state.machineFilt = m.machine_id;
        machSel.value = m.machine_id;
      } else {
        state.machineFilt = '';
        machSel.value = '';
      }
      renderTable();
    });

    grid.appendChild(card);
  });
}

// ── Severity filter pills ─────────────────────────────────────────────────────
function initSevFilters(){
  const grp = document.getElementById('sev-filters');
  grp.innerHTML = '';

  const allBtn = document.createElement('button');
  allBtn.className = 'filter-btn active-all';
  allBtn.textContent = 'All';
  allBtn.addEventListener('click', function(){ setSevFilter('', allBtn); });
  grp.appendChild(allBtn);

  SEV_ORDER.forEach(function(sev){
    const cnt = FLEET_DATA.findings.filter(function(f){ return f.severity === sev; }).length;
    if(!cnt) return;
    const btn = document.createElement('button');
    btn.className = 'filter-btn';
    btn.style.cssText = 'border-color:' + sevColor(sev) + ';color:' + sevColor(sev) + ';background:' + sevColor(sev) + '22';
    btn.innerHTML = sev + ' <span style="opacity:.55;font-weight:400">' + cnt + '</span>';
    btn.addEventListener('click', function(){ setSevFilter(sev, btn); });
    grp.appendChild(btn);
  });
}

function setSevFilter(sev, btn){
  state.sevFilt = sev;
  document.querySelectorAll('#sev-filters .filter-btn').forEach(function(b){ b.classList.remove('active-all'); });
  btn.classList.add('active-all');
  renderTable();
}

// ── Machine + Analyzer dropdowns ──────────────────────────────────────────────
function initSelects(){
  const machSel = document.getElementById('machine-select');
  FLEET_DATA.machines.forEach(function(m){
    const opt = document.createElement('option');
    opt.value = m.machine_id;
    opt.textContent = trunc(m.machine_id, 30);
    machSel.appendChild(opt);
  });

  const azSel = document.getElementById('analyzer-select');
  const analyzers = FLEET_DATA.findings.map(function(f){ return f.analyzer; })
    .filter(function(v, i, a){ return a.indexOf(v) === i; }).sort();
  analyzers.forEach(function(az){
    const opt = document.createElement('option');
    opt.value = az;
    opt.textContent = az;
    azSel.appendChild(opt);
  });
}

function onMachineSelect(){
  const val = document.getElementById('machine-select').value;
  state.machineFilt = val;
  document.querySelectorAll('.machine-card').forEach(function(c){
    c.classList.toggle('selected', !!val && c.dataset.mid === val);
  });
  renderTable();
}

function onAnalyzerSelect(){
  state.analyzerFilt = document.getElementById('analyzer-select').value;
  renderTable();
}

// ── Table sort ────────────────────────────────────────────────────────────────
function sortBy(col){
  if(state.sortCol === col) state.sortAsc = !state.sortAsc;
  else { state.sortCol = col; state.sortAsc = true; }
  renderTable();
}

// ── Render findings table ─────────────────────────────────────────────────────
function renderTable(){
  let data = FLEET_DATA.findings.slice();
  if(state.sevFilt) data = data.filter(function(f){ return f.severity === state.sevFilt; });
  if(state.machineFilt) data = data.filter(function(f){ return f.affected_machines.indexOf(state.machineFilt) !== -1; });
  if(state.analyzerFilt) data = data.filter(function(f){ return f.analyzer === state.analyzerFilt; });

  const col = state.sortCol;
  data.sort(function(a, b){
    if(col === 'severity'){
      const va = SEV_ORDER.indexOf(a.severity), vb = SEV_ORDER.indexOf(b.severity);
      return state.sortAsc ? va - vb : vb - va;
    }
    if(col === 'affected_count'){
      return state.sortAsc ? a.affected_count - b.affected_count : b.affected_count - a.affected_count;
    }
    const va = String(a[col] || ''), vb = String(b[col] || '');
    return state.sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });

  const tbody = document.getElementById('findings-tbody');
  tbody.innerHTML = '';
  const total = FLEET_DATA.stats.total_machines;

  if(!FLEET_DATA.findings.length){
    tbody.innerHTML = emptyRow(5, 'No security findings across fleet — all machines clean.');
    return;
  }
  if(!data.length){
    tbody.innerHTML = emptyRow(5, 'No findings match the current filters.');
    return;
  }

  data.forEach(function(f){
    const tr = document.createElement('tr');
    const dot = '<span class="sev-dot" style="background:' + sevColor(f.severity) + '"></span>';
    const sevTxt = '<span style="color:' + sevColor(f.severity) + '">' + f.severity + '</span>';
    const machTxt = f.affected_count + '/' + total;
    const machStyle = f.affected_count === total ? 'color:var(--crit);font-weight:600' : '';
    tr.innerHTML =
      '<td><div class="td-sev">' + dot + sevTxt + '</div></td>' +
      '<td class="td-mono" style="' + machStyle + '" title="' + f.affected_machines.join(', ') + '">' + machTxt + '</td>' +
      '<td class="td-mono">' + f.analyzer + '</td>' +
      '<td class="td-mono" title="' + f.server_name + '">' + trunc(f.server_name, 24) + '</td>' +
      '<td title="' + (f.title||'') + '">' + trunc(f.title||'', 60) + '</td>';
    tbody.appendChild(tr);
  });
}

function emptyRow(cols, msg){
  return '<tr><td colspan="' + cols + '" style="padding:36px;text-align:center;color:var(--text-dim);font-size:13px;border:none">' + msg + '</td></tr>';
}

// ── Theme ─────────────────────────────────────────────────────────────────────
function toggleTheme(){
  const el = document.querySelector('.fleet-dash');
  const next = el.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  el.setAttribute('data-theme', next);
  Object.assign(SC, PALETTE[next]);
  // Rebuild colour-dependent elements
  initSevFilters();
  initMachineGrid();
  // Re-sync machine selection state after grid rebuild
  if(state.machineFilt){
    document.querySelectorAll('.machine-card').forEach(function(c){
      c.classList.toggle('selected', c.dataset.mid === state.machineFilt);
    });
    document.getElementById('machine-select').value = state.machineFilt;
  }
  renderTable();
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
window.toggleTheme = toggleTheme;
window.onMachineSelect = onMachineSelect;
window.onAnalyzerSelect = onAnalyzerSelect;

document.addEventListener('DOMContentLoaded', function(){
  initHeader();
  initMachineGrid();
  initSevFilters();
  initSelects();
  document.querySelectorAll('.findings-table th[data-col]').forEach(function(th){
    th.addEventListener('click', function(){ sortBy(th.dataset.col); });
  });
  renderTable();
});

})();
</script>
</body>
</html>"""


def generate_fleet_html(report: FleetReport) -> str:
    """Render *report* as a self-contained D3 fleet dashboard HTML page.

    The output embeds D3.js v7 (bundled with the package) and all fleet data
    as an inline JSON object.  The file has zero external dependencies and
    renders correctly with no network access.

    Args:
        report: The :class:`FleetReport` to render.

    Returns:
        A UTF-8 HTML string suitable for writing to a ``.html`` file.
    """
    fleet_data = _build_fleet_data(report)
    d3_js = _load_d3()
    html = _FLEET_HTML
    _json_blob = json.dumps(fleet_data, indent=2)
    # Escape < > & so a malicious server name containing </script> cannot break
    # out of the inline <script> block.  \uXXXX escapes are valid JSON and
    # decoded transparently by JavaScript.
    _json_blob = (
        _json_blob.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    html = html.replace("__FLEET_DATA_JSON__", _json_blob)
    html = html.replace("__D3_JS__", d3_js)
    return html
