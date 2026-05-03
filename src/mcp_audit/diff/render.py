"""Render MCP diff results to terminal, JSON, and PR-comment Markdown."""

from __future__ import annotations

import json
from collections import Counter

from rich.console import Console
from rich.rule import Rule
from rich.text import Text

from mcp_audit.diff.comparator import Change, ChangeType, EntityType
from mcp_audit.models import Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "orange1",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

CHANGE_ICONS = {
    ChangeType.ADDED: "+",
    ChangeType.REMOVED: "-",
    ChangeType.CHANGED: "~",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _max_severity(changes: list[Change]) -> Severity | None:
    """Return the highest severity present in *changes*."""
    for sev in _SEVERITY_ORDER:
        if any(c.severity == sev for c in changes):
            return sev
    return None


def _summary_counts(changes: list[Change]) -> dict[str, int]:
    """Count server-level adds/removes/changes."""
    server_changes = [c for c in changes if c.entity_type == EntityType.SERVER]
    added = sum(1 for c in server_changes if c.change_type == ChangeType.ADDED)
    removed = sum(1 for c in server_changes if c.change_type == ChangeType.REMOVED)
    changed = sum(1 for c in server_changes if c.change_type == ChangeType.CHANGED)
    return {"added": added, "removed": removed, "changed": changed}


# ── Terminal renderer ──────────────────────────────────────────────────────────


def render_terminal(
    changes: list[Change],
    base_label: str,
    head_label: str,
    console: Console | None = None,
) -> None:
    """Print MCP diff results to the terminal using Rich formatting.

    Args:
        changes: The list of changes from :func:`compare`.
        base_label: Human-readable label for the base state.
        head_label: Human-readable label for the head state.
        console: Rich Console to use; creates a new one if not provided.
    """
    con = console or Console()

    con.print()
    con.print(Rule(f"[bold]mcp-audit diff[/bold]  {base_label} → {head_label}"))
    con.print()

    if not changes:
        con.print("[green]✓ No MCP changes detected.[/green]")
        con.print()
        return

    counts = _summary_counts(changes)
    max_sev = _max_severity(changes)
    sev_color = SEVERITY_COLORS.get(max_sev, "white") if max_sev else "white"
    sev_icon = SEVERITY_ICONS.get(max_sev, "") if max_sev else ""

    parts: list[str] = []
    if counts["added"]:
        parts.append(f"{counts['added']} added")
    if counts["removed"]:
        parts.append(f"{counts['removed']} removed")
    if counts["changed"]:
        parts.append(f"{counts['changed']} changed")

    con.print(
        f"[{sev_color}]{sev_icon}[/{sev_color}] "
        f"[bold]{', '.join(parts)} "
        f"server{'s' if sum(counts.values()) != 1 else ''}[/bold]"
        f"  — max severity: [{sev_color}][bold]{max_sev}[/bold][/{sev_color}]"
    )
    con.print()

    # Group sub-changes under their parent server for readability
    server_changes = [c for c in changes if c.entity_type == EntityType.SERVER]
    sub_by_parent: dict[str, list[Change]] = {}
    for c in changes:
        if c.parent_server:
            sub_by_parent.setdefault(c.parent_server, []).append(c)

    for sc in server_changes:
        sev_color = SEVERITY_COLORS[sc.severity]
        icon = CHANGE_ICONS[sc.change_type]
        con.print(
            Text.assemble(
                (f"  {icon} ", "bold"),
                (f"[{sc.severity}] ", f"bold {sev_color}"),
                (sc.entity_name, "bold"),
                (f"  {sc.change_type}", "dim"),
            )
        )

        if sc.command_diff:
            cd = sc.command_diff
            if cd.get("before_command") != cd.get("after_command"):
                con.print(
                    f"      command: [red]{cd['before_command']}[/red] → "
                    f"[green]{cd['after_command']}[/green]"
                )
            if cd.get("before_args") != cd.get("after_args"):
                con.print(f"      args before: [dim]{cd['before_args']}[/dim]")
                con.print(f"      args after:  [green]{cd['after_args']}[/green]")

        subs = sub_by_parent.get(sc.entity_name, [])
        for sub in subs:
            sub_icon = CHANGE_ICONS[sub.change_type]
            sub_color = SEVERITY_COLORS[sub.severity]
            con.print(
                f"      {sub_icon} [{sub.severity}] "
                f"[{sub_color}]{sub.entity_type}:[/{sub_color}] {sub.entity_name}"
            )

        con.print()


# ── JSON renderer ──────────────────────────────────────────────────────────────


def render_json(changes: list[Change]) -> str:
    """Serialize *changes* to a JSON array string.

    Each record has the fields specified in STORY-0014:
    ``change_type``, ``entity_type``, ``entity_name``, ``before``, ``after``,
    ``severity``, ``owasp_mcp_top_10``.

    The ``parent_server`` and ``command_diff`` fields are included as
    extensions when non-null.

    Args:
        changes: The list of changes from :func:`compare`.

    Returns:
        Pretty-printed JSON string.
    """
    records = []
    for c in changes:
        record: dict = {
            "change_type": c.change_type,
            "entity_type": c.entity_type,
            "entity_name": c.entity_name,
            "before": c.before,
            "after": c.after,
            "severity": c.severity,
            "owasp_mcp_top_10": c.owasp_mcp_top_10,
        }
        if c.parent_server is not None:
            record["parent_server"] = c.parent_server
        if c.command_diff is not None:
            record["command_diff"] = c.command_diff
        records.append(record)
    return json.dumps(records, indent=2, default=str)


# ── PR-comment Markdown renderer ───────────────────────────────────────────────

_PR_SEV_BADGE = {
    Severity.CRITICAL: "🔴 **CRITICAL**",
    Severity.HIGH: "🟠 **HIGH**",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
    Severity.INFO: "⚪ INFO",
}


def render_pr_comment(
    changes: list[Change],
    base_label: str,
    head_label: str,
) -> str:
    """Render *changes* as GitHub-flavored Markdown for a PR comment.

    The output is capped at 100 lines to fit cleanly in GitHub notification
    emails.  Each changed server is wrapped in a ``<details>`` block.
    The uncollapsed summary line is kept to ≤ 80 characters.

    Args:
        changes: The list of changes from :func:`compare`.
        base_label: Human-readable label for the base state.
        head_label: Human-readable label for the head state.

    Returns:
        GitHub-flavored Markdown string.
    """
    lines: list[str] = []

    lines.append(f"## MCP Security Diff: `{base_label}` → `{head_label}`")
    lines.append("")

    if not changes:
        lines.append(f"✅ No MCP changes between `{base_label}` and `{head_label}`.")
        return "\n".join(lines)

    counts = _summary_counts(changes)
    max_sev = _max_severity(changes)
    badge = _PR_SEV_BADGE.get(max_sev, "") if max_sev else ""

    summary_parts: list[str] = []
    if counts["added"]:
        summary_parts.append(f"**{counts['added']} added**")
    if counts["removed"]:
        summary_parts.append(f"**{counts['removed']} removed**")
    if counts["changed"]:
        summary_parts.append(f"**{counts['changed']} changed**")

    lines.append(
        f"{badge} &nbsp; {', '.join(summary_parts)} server"
        f"{'s' if sum(counts.values()) != 1 else ''}"
    )
    lines.append("")

    # Group sub-changes by parent server
    sub_by_parent: dict[str, list[Change]] = {}
    for c in changes:
        if c.parent_server:
            sub_by_parent.setdefault(c.parent_server, []).append(c)

    server_changes = [c for c in changes if c.entity_type == EntityType.SERVER]

    for sc in server_changes:
        badge = _PR_SEV_BADGE.get(sc.severity, "")
        # Keep summary line ≤ 80 chars
        summary = f"{badge} · `{sc.entity_name}` {sc.change_type}"[:80]
        lines.append("<details>")
        lines.append(f"<summary>{summary}</summary>")
        lines.append("")

        # Server metadata table
        after = sc.after or {}
        before = sc.before or {}

        if sc.change_type == ChangeType.ADDED:
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            if after.get("command"):
                lines.append(f"| Command | `{after['command']}` |")
            if after.get("args"):
                args_str = " ".join(str(a) for a in after["args"])[:60]
                lines.append(f"| Args | `{args_str}` |")
            env_keys = after.get("env_keys", [])
            env_refs = ", ".join(f"`{k}`" for k in env_keys) or "—"
            lines.append(f"| Env vars | {env_refs} |")
            if after.get("url"):
                lines.append(f"| URL | `{after['url']}` |")

        elif sc.change_type == ChangeType.CHANGED and sc.command_diff:
            cd = sc.command_diff
            lines.append("| Field | Before | After |")
            lines.append("|-------|--------|-------|")
            if cd.get("before_command") != cd.get("after_command"):
                lines.append(
                    f"| command | `{cd['before_command']}` | `{cd['after_command']}` |"
                )
            if cd.get("before_args") != cd.get("after_args"):
                ba = " ".join(str(a) for a in (cd.get("before_args") or []))[:40]
                aa = " ".join(str(a) for a in (cd.get("after_args") or []))[:40]
                lines.append(f"| args | `{ba}` | `{aa}` |")

        elif sc.change_type == ChangeType.REMOVED:
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            if before.get("command"):
                lines.append(f"| Command | `{before['command']}` |")

        # Sub-changes within this server
        subs = sub_by_parent.get(sc.entity_name, [])
        if subs:
            lines.append("")
            lines.append("**Related changes:**")
            for sub in subs:
                sub_badge = _PR_SEV_BADGE.get(sub.severity, "")
                lines.append(
                    f"- {sub_badge} `{sub.entity_type}` **{sub.entity_name}** "
                    f"{sub.change_type}"
                )

        # OWASP references
        if sc.owasp_mcp_top_10:
            lines.append("")
            lines.append(f"*OWASP MCP Top 10: {', '.join(sc.owasp_mcp_top_10)}*")

        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Severity breakdown footer
    sev_counts: Counter[str] = Counter(str(c.severity) for c in changes)
    footer_parts = [
        f"{count} {sev}" for sev, count in sev_counts.most_common() if count > 0
    ]
    if footer_parts:
        lines.append(f"*{' · '.join(footer_parts)} across all changes*")
        lines.append("")

    # Trim to 100 lines if needed
    if len(lines) > 100:
        lines = lines[:97]
        lines.append(
            "*…output truncated — run `mcp-audit diff` locally for full report*"
        )
        lines.append("")

    return "\n".join(lines)
