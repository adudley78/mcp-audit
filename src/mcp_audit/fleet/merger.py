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
_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"version", "timestamp", "findings"}
)
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


def generate_fleet_html(report: FleetReport) -> str:
    """Render *report* as a self-contained HTML page.

    Uses Rich's console recording to produce styled HTML.  This is a simplified
    table view — a full D3 fleet visualization is a future enhancement (see GAPS.md).

    Args:
        report: The :class:`FleetReport` to render.

    Returns:
        A UTF-8 HTML string suitable for writing to a ``.html`` file.
    """
    from rich.console import Console  # noqa: PLC0415
    from rich.panel import Panel  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415

    con = Console(record=True, width=120)

    # ── Section 1: Fleet Summary ──────────────────────────────────────────────
    s = report.stats
    score_line = f"{s.average_score:.1f}/100" if s.average_score is not None else "N/A"
    lines = [
        f"[bold]Total machines scanned:[/bold] {s.total_machines}",
        f"[bold]Total findings:[/bold] {s.total_findings}",
        f"[bold]Unique findings:[/bold] {s.unique_findings}",
        f"[bold]Average config score:[/bold] {score_line}",
    ]
    if s.riskiest_machine:
        risk_count = sum(
            1
            for m in report.machines
            if m.machine_id == s.riskiest_machine
            for f in m.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        lines.append(
            f"[bold]Riskiest machine:[/bold] [red]{s.riskiest_machine}[/red] "
            f"({risk_count} critical/high finding{'s' if risk_count != 1 else ''})"
        )
    if s.most_common_finding:
        top = report.deduplicated_findings[0]
        lines.append(
            f"[bold]Most widespread issue:[/bold] {s.most_common_finding} "
            f"(affects {top.affected_count}/{s.total_machines} machines)"
        )
    if report.version_mismatches:
        n_mm = len(report.version_mismatches)
        lines.append(f"[bold yellow]Version mismatches:[/bold yellow] {n_mm}")

    con.print(Panel("\n".join(lines), title="Fleet Summary", border_style="cyan"))

    # ── Section 2: Finding Breakdown ──────────────────────────────────────────
    if report.deduplicated_findings:
        _SEV_STYLE = {  # noqa: N806
            "CRITICAL": "[bold red]CRITICAL[/bold red]",
            "HIGH": "[red]HIGH[/red]",
            "MEDIUM": "[yellow]MEDIUM[/yellow]",
            "LOW": "[blue]LOW[/blue]",
            "INFO": "[dim]INFO[/dim]",
        }

        table = Table(show_header=True, header_style="bold", title="Finding Breakdown")
        table.add_column("Severity", width=10)
        table.add_column("Finding")
        table.add_column("Affected Machines", justify="center", width=20)
        table.add_column("First Seen", width=20)

        for df in report.deduplicated_findings:
            sev_display = _SEV_STYLE.get(df.severity.value, df.severity.value)
            machines_display = f"{df.affected_count}/{s.total_machines} machines"
            first_seen_str = df.first_seen.strftime("%Y-%m-%d %H:%M")
            table.add_row(sev_display, df.title, machines_display, first_seen_str)

        con.print(table)
    else:
        con.print("[green]No findings across fleet.[/green]")

    if report.version_mismatches:
        con.print("\n[yellow]Version mismatch warnings:[/yellow]")
        for w in report.version_mismatches:
            con.print(f"  [yellow]•[/yellow] {w}")

    return con.export_html(inline_styles=True)
