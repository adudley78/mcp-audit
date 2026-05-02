"""Scan scoring engine — converts findings into a numeric grade."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp_audit.models import Finding, ScanScore, Severity

if TYPE_CHECKING:
    from mcp_audit.governance.models import ScoringWeights

# ── Severity deduction table ──────────────────────────────────────────────────

_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    # INFO is an informational observation, not a security risk; the −1 nudge
    # ensures a perfect score is reserved for truly clean configurations.
    Severity.INFO: 1,
}

# ── Grade thresholds ──────────────────────────────────────────────────────────

_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (0, "F"),
]

# ── Grade colours (Rich markup) ───────────────────────────────────────────────

_GRADE_STYLE: dict[str, str] = {
    "A": "bold green",
    "B": "bold green",
    "C": "bold yellow",
    "D": "bold yellow",
    "F": "bold red",
}


def _grade_for(score: int) -> str:
    """Return the letter grade for *score*."""
    for threshold, letter in _GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"


def calculate_score(
    findings: list[Finding],
    weights: ScoringWeights | None = None,
    weights_source: str = "default",
) -> ScanScore:
    """Compute a :class:`ScanScore` from a list of :class:`~mcp_audit.models.Finding`.

    Algorithm:
    1. Start at 100.
    2. Deduct per finding by severity
       (CRITICAL −25, HIGH −10, MEDIUM −5, LOW −2, INFO −1).
       When *weights* is supplied, uses ``weights.deductions`` instead of the
       module-level ``_DEDUCTIONS`` constants.
    3. Clamp to 0.
    4. Apply up to ``max_total_bonus`` (+10) in positive-signal bonuses.
    5. Clamp to 100 maximum.

    Args:
        findings: All findings produced by the scan pipeline.
        weights: Optional custom scoring weights from a governance policy.
            When ``None``, the hardcoded module-level constants are used.
        weights_source: Audit label written to :attr:`ScanScore.weights_source`.
            Pass ``"policy:<abs-path>"`` when custom weights are active.

    Returns:
        A fully populated :class:`ScanScore`.
    """
    # ── Resolve effective deduction amounts (positive ints) ──────────────────
    if weights is not None:
        d = weights.deductions
        effective_deductions: dict[Severity, int] = {
            Severity.CRITICAL: abs(d.CRITICAL),
            Severity.HIGH: abs(d.HIGH),
            Severity.MEDIUM: abs(d.MEDIUM),
            Severity.LOW: abs(d.LOW),
            Severity.INFO: abs(d.INFO),
        }
        ps = weights.positive_signals
        pts_no_credentials = ps.no_credentials
        pts_all_pinned = ps.all_pinned
        pts_registry_only = ps.registry_only
        max_bonus = ps.max_total_bonus
    else:
        effective_deductions = dict(_DEDUCTIONS)
        pts_no_credentials = 3
        pts_all_pinned = 3
        pts_registry_only = 4
        max_bonus = 10

    # ── Count by severity ─────────────────────────────────────────────────────
    counts: dict[Severity, int] = dict.fromkeys(effective_deductions, 0)
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    # ── Raw deductions ────────────────────────────────────────────────────────
    raw_score = 100
    deductions: list[str] = []
    for sev in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ):
        n = counts[sev]
        if n == 0:
            continue
        pts = n * effective_deductions[sev]
        raw_score -= pts
        if pts > 0:
            deductions.append(
                f"{n} {sev.value.lower()} finding{'s' if n != 1 else ''} (-{pts} pts)"
            )

    raw_score = max(0, raw_score)

    # ── Positive-signal bonuses ───────────────────────────────────────────────
    positive_signals: list[str] = []
    bonus = 0

    has_credential_findings = any(f.analyzer == "credentials" for f in findings)
    if not has_credential_findings and pts_no_credentials > 0:
        bonus += pts_no_credentials
        positive_signals.append(
            f"No credential exposure detected (+{pts_no_credentials} pts)"
        )

    has_critical_or_high = counts[Severity.CRITICAL] > 0 or counts[Severity.HIGH] > 0
    if not has_critical_or_high and pts_all_pinned > 0:
        bonus += pts_all_pinned
        positive_signals.append(
            f"No high-severity issues found (+{pts_all_pinned} pts)"
        )

    has_poisoning_findings = any(f.analyzer == "poisoning" for f in findings)
    if not has_poisoning_findings and pts_registry_only > 0:
        bonus += pts_registry_only
        positive_signals.append(
            f"No prompt injection risks detected (+{pts_registry_only} pts)"
        )

    bonus = min(bonus, max_bonus)
    final_score = min(100, raw_score + bonus)

    return ScanScore(
        numeric_score=final_score,
        grade=_grade_for(final_score),
        positive_signals=positive_signals,
        deductions=deductions,
        weights_source=weights_source,
    )


def format_grade_terminal(score: ScanScore) -> str:
    """Return a Rich-markup string rendering the grade panel.

    Displays a bordered box with the letter grade (colour-coded), numeric
    score, positive signals, and deductions — suitable for printing with a
    Rich :class:`~rich.console.Console`.

    Args:
        score: A :class:`ScanScore` as returned by :func:`calculate_score`.

    Returns:
        Rich markup string.  Caller is responsible for printing it.
    """
    style = _GRADE_STYLE[score.grade]
    lines: list[str] = []

    lines.append(
        f"  MCP Config Grade:  [{style}]{score.grade}[/{style}]"
        f"  [bold]{score.numeric_score}[/bold] / 100"
    )
    lines.append("  [dim]Base: 100[/dim]")

    for signal in score.positive_signals:
        lines.append(f"  [green]✓[/green] {signal}")

    for deduction in score.deductions:
        lines.append(f"  [red]✗[/red] {deduction}")

    if score.weights_source != "default":
        lines.append(f"  [dim]Weights: {score.weights_source}[/dim]")

    inner = "\n".join(lines)
    return f"[bold]Scan Score[/bold]\n{inner}"
