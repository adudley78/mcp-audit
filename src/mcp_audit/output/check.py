"""One-page security verdict formatter for `mcp-audit check`."""

from __future__ import annotations

from rich.console import Console
from rich.rule import Rule

from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.registration.models import RegistrationConfig

# ── Severity colour map (Rich markup) ─────────────────────────────────────────

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "orange1 bold",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

# ── Auto-fixable finding IDs ───────────────────────────────────────────────────
# These IDs map to remediations that `mcp-audit fix --apply` can handle.

_AUTO_FIXABLE: frozenset[str] = frozenset(
    {
        "CRED-001",
        "CRED-002",
        "TRANSPORT-001",
        "SC-001",
        "SC-002",
    }
)

# ── Static remediation hints, keyed on finding ID ────────────────────────────
# Plain English, no OWASP codes, no analyzer names.
# Auto-fixable IDs resolve to the fix command; others get a specific action.

_HINTS: dict[str, str] = {
    # Credentials
    "CRED-001": "Run `mcp-audit fix --apply` to redact automatically.",
    "CRED-002": "Run `mcp-audit fix --apply` to redact automatically.",
    # Transport
    "TRANSPORT-001": "Run `mcp-audit fix --apply` to upgrade to HTTPS automatically.",
    "TRANSPORT-002": "Bind this server to 127.0.0.1 (localhost) instead of 0.0.0.0.",
    "TRANSPORT-003": "Host this server over HTTPS to encrypt traffic in transit.",
    "TRANSPORT-004": (
        "Enable TLS certificate validation — do not set rejectUnauthorized: false."
    ),
    # Supply chain / typosquatting
    "SC-001": "Run `mcp-audit fix --apply` to replace with the verified package name.",
    "SC-002": "Run `mcp-audit fix --apply` to replace with the verified package name.",
    "SC-003": "Verify this package name against the official MCP registry before use.",
    # Poisoning / prompt injection
    "POISON-001": (
        "Remove or sanitise the suspicious instruction from the tool description."
    ),
    "POISON-002": (
        "Remove hidden text or invisible characters from the tool description."
    ),
    "POISON-003": "Remove data exfiltration instructions from the tool description.",
    "POISON-010": (
        "Remove the prompt that instructs the model to ignore prior context."
    ),
    "POISON-011": (
        "Remove the override directive that attempts to reassign the model's role."
    ),
    "POISON-020": ("Remove the encoded payload from the tool or resource description."),
    "POISON-021": (
        "Remove the obfuscated instruction from the tool or resource description."
    ),
    "POISON-030": "Remove the tool-chaining manipulation instruction.",
    "POISON-040": (
        "Remove the shadow-tool registration instruction from the description."
    ),
    "POISON-050": (
        "Remove the capability escalation directive from the tool description."
    ),
    "POISON-060": (
        "Remove the memory-poisoning instruction from the tool description."
    ),
    "POISON-012": (
        "Remove the privilege-escalation instruction from the tool description."
    ),
    # Rug-pull
    "RUGPULL-000": (
        "A server disappeared since the last scan"
        " — verify it was intentionally removed."
    ),
    "RUGPULL-001": (
        "A server's command changed unexpectedly — verify the update is legitimate."
    ),
    "RUGPULL-002": (
        "A server's description changed since the last scan — review the change."
    ),
    "RUGPULL-003": "Server arguments changed — verify the change is intentional.",
    # Toxic flow / capability combinations
    "TOXIC-001": (
        "Separate file-system and network-egress servers to prevent exfiltration."
    ),
    "TOXIC-002": (
        "Review whether both code-execution and file-system access are needed together."
    ),
    "TOXIC-003": (
        "Consider whether both code-execution and network access are required."
    ),
    "TOXIC-004": "Separate secret-store access from network-egress servers.",
    "TOXIC-005": (
        "Review this server pair"
        " — together they form a dangerous capability combination."
    ),
    "TOXIC-006": "Separate credential access from code-execution servers.",
    "TOXIC-007": (
        "Review this cross-server capability chain for unintended escalation paths."
    ),
    # Config hygiene
    "CFHYG-001": (
        "Pin the package to an explicit version (e.g. @2.1.0)"
        " to prevent unexpected updates."
    ),
    "CFHYG-002": "Remove unused or disabled server entries from the config.",
    "CFHYG-003": (
        "Replace the wildcard tool-activation pattern"
        " with an explicit list of allowed tools."
    ),
    "CFHYG-004": (
        "Use a specific version tag instead of 'latest' to get deterministic behaviour."
    ),
    "CFHYG-005": (
        "Remove environment variable names that look like placeholders or test values."
    ),
    "CFHYG-006": ("Remove or update the stale server entry — it appears to be unused."),
    # Baseline drift
    "DRIFT": (
        "Review this change. If intentional,"
        " run `mcp-audit baseline save` to update your baseline."
    ),
    # Attestation
    "ATTEST": (
        "The package hash does not match the registry"
        " — do not use this server until verified."
    ),
}


def _remediation_hint(finding: Finding) -> str:
    """Return a one-line plain-English remediation hint for *finding*.

    Checks the static :data:`_HINTS` table first, falling back to the
    first sentence of ``finding.remediation`` when the ID is unknown.

    Args:
        finding: A :class:`~mcp_audit.models.Finding` from the scan pipeline.

    Returns:
        A single-line plain-English instruction suitable for non-expert users.
    """
    # Exact match
    if finding.id in _HINTS:
        return _HINTS[finding.id]

    # Prefix match (e.g. "DRIFT-001" → "DRIFT", "ATTEST-…" → "ATTEST")
    prefix = finding.id.split("-")[0]
    if prefix in _HINTS:
        return _HINTS[prefix]

    # Fallback: first sentence of the stored remediation text
    sentences = finding.remediation.split(". ")
    return sentences[0].rstrip(".") + "."


def _grade_color(grade: str) -> str:
    """Return the Rich colour tag for a letter grade."""
    if grade in ("A", "B"):
        return "bold green"
    if grade in ("C", "D"):
        return "bold yellow"
    return "bold red"


MAX_FINDINGS_SHOWN = 5

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def print_check_results(
    result: ScanResult,
    console: Console | None = None,
    registration: RegistrationConfig | None = None,
) -> None:
    """Print the one-page security verdict to the terminal.

    Renders a clean, 80-column-max summary with:
    - Letter grade and numeric score
    - Optional registration line (when *registration* is provided)
    - Up to :data:`MAX_FINDINGS_SHOWN` findings (highest severity first)
    - Per-finding remediation hints
    - Footer with ``mcp-audit fix`` and ``mcp-audit scan`` guidance

    Args:
        result: Completed scan result from :func:`~mcp_audit.scanner.run_scan`.
        console: Rich console to write to.  A new one is created if omitted.
        registration: Current registration config, if the user is registered.
            When provided, a ``Registered as: <org>`` line appears beneath the
            grade panel.
    """
    if console is None:
        console = Console(width=80)

    grade = result.score.grade if result.score else "?"
    score_num = result.score.numeric_score if result.score else 0
    grade_style = _grade_color(grade)

    console.print()
    console.print(Rule("[bold]mcp-audit — Security Check[/bold]"))

    if not result.findings:
        console.print()
        console.print(
            f"  Grade: [{grade_style}]{grade}[/{grade_style}]  ✓ No issues found"
        )
        if registration:
            _print_registered_as(console, registration)
        console.print()
        console.print("  Your MCP configuration looks clean.")
        console.print()
        console.print(Rule())
        return

    # ── Grade line ────────────────────────────────────────────────────────────
    console.print()
    console.print(
        f"  Grade: [{grade_style}]{grade}[/{grade_style}]  "
        f"(Score: [bold]{score_num}[/bold]/100)"
    )
    if registration:
        _print_registered_as(console, registration)
    console.print()

    # ── Attack path warning ───────────────────────────────────────────────────
    has_attack_paths = bool(
        result.attack_path_summary and result.attack_path_summary.paths
    )
    if grade == "F" and has_attack_paths:
        console.print(
            "  [bold red]⛔ Active attack path detected.[/bold red]"
            "  Run [bold]mcp-audit scan[/bold] for full details."
        )
        console.print()

    # ── Findings list ─────────────────────────────────────────────────────────
    sorted_findings = sorted(
        result.findings,
        key=lambda f: _SEVERITY_ORDER.index(f.severity),
    )

    total = len(sorted_findings)
    shown = sorted_findings[:MAX_FINDINGS_SHOWN]
    remainder = total - len(shown)

    fixable_ids = sorted({f.id for f in shown if f.id in _AUTO_FIXABLE})
    fixable_shown = len(fixable_ids)

    issue_word = "issue" if total == 1 else "issues"
    need_word = "needs" if total == 1 else "need"
    console.print(f"  [bold]⚠  {total} {issue_word} {need_word} your attention:[/bold]")
    console.print()

    for i, finding in enumerate(shown, start=1):
        color = _SEVERITY_COLORS[finding.severity]
        sev_badge = f"[{color}]{finding.severity.value}[/{color}]"
        hint = _remediation_hint(finding)
        console.print(f"  {i}. [{sev_badge}] {finding.title}")
        console.print(f"     → {hint}")
        console.print()

    if remainder > 0:
        console.print(
            f"  [dim]… and {remainder} more — run [bold]mcp-audit scan[/bold]"
            " to see all.[/dim]"
        )
        console.print()

    # ── Fix summary line ──────────────────────────────────────────────────────
    if fixable_shown > 0:
        ids_str = ", ".join(fixable_ids)
        n_word = "finding" if fixable_shown == 1 else "findings"
        console.print(
            f"  → Run [bold]mcp-audit fix --apply[/bold] to auto-remediate "
            f"[{ids_str}] ({fixable_shown} {n_word})"
        )
        console.print()

    # ── Footer ────────────────────────────────────────────────────────────────
    console.print(Rule())
    console.print("[dim]To see all findings:  mcp-audit scan[/dim]")
    if fixable_shown > 0:
        console.print("[dim]To apply auto-fixes:  mcp-audit fix --apply[/dim]")


def _print_registered_as(console: Console, registration: RegistrationConfig) -> None:
    """Print a single dim registration line beneath the grade.

    Prefers org name, falls back to display name, then truncated email.
    """
    label = registration.org or registration.name
    if not label:
        at = registration.email.find("@")
        if at > 2:
            label = registration.email[:2] + "***" + registration.email[at:]
        else:
            label = registration.email
    console.print(f"  [dim]Registered as: {label}[/dim]")
