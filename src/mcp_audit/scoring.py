"""Scan scoring engine — converts findings into a numeric grade."""

from __future__ import annotations

from mcp_audit.models import Finding, ScanScore, Severity

# ── Severity deduction table ──────────────────────────────────────────────────

_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
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


def calculate_score(findings: list[Finding]) -> ScanScore:
    """Compute a :class:`ScanScore` from a list of :class:`~mcp_audit.models.Finding`.

    Algorithm:
    1. Start at 100.
    2. Deduct per finding by severity
       (CRITICAL −25, HIGH −15, MEDIUM −8, LOW −3, INFO −1).
    3. Clamp to 0.
    4. Apply up to +10 in positive-signal bonuses.
    5. Clamp to 100 maximum.

    Args:
        findings: All findings produced by the scan pipeline.

    Returns:
        A fully populated :class:`ScanScore`.
    """
    # ── Count by severity ─────────────────────────────────────────────────────
    counts: dict[Severity, int] = dict.fromkeys(_DEDUCTIONS, 0)
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
        pts = n * _DEDUCTIONS[sev]
        raw_score -= pts
        deductions.append(
            f"{n} {sev.value.lower()} finding{'s' if n != 1 else ''} (-{pts} pts)"
        )

    raw_score = max(0, raw_score)

    # ── Positive-signal bonuses ───────────────────────────────────────────────
    positive_signals: list[str] = []
    bonus = 0

    has_credential_findings = any(f.analyzer == "credentials" for f in findings)
    if not has_credential_findings:
        bonus += 3
        positive_signals.append("No credential exposure detected")

    has_critical_or_high = counts[Severity.CRITICAL] > 0 or counts[Severity.HIGH] > 0
    if not has_critical_or_high:
        bonus += 5
        positive_signals.append("No high-severity issues found")

    has_poisoning_findings = any(f.analyzer == "poisoning" for f in findings)
    if not has_poisoning_findings:
        bonus += 2
        positive_signals.append("No prompt injection risks detected")

    bonus = min(bonus, 10)
    final_score = min(100, raw_score + bonus)

    return ScanScore(
        numeric_score=final_score,
        grade=_grade_for(final_score),
        positive_signals=positive_signals,
        deductions=deductions,
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

    for signal in score.positive_signals:
        lines.append(f"  [green]✓[/green] {signal}")

    for deduction in score.deductions:
        lines.append(f"  [red]✗[/red] {deduction}")

    inner = "\n".join(lines)
    return f"[bold]Scan Score[/bold]\n{inner}"
