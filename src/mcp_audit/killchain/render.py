"""Markdown and JSON output formatters for killchain results.

Markdown output is the primary human-readable artifact: clean enough to
copy-paste into Slack, email, or a PR description without losing meaning.
JSON output is machine-ingestible and round-trips through ``--input``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from mcp_audit.analyzers.attack_paths import _SEVERITY_ORDER
from mcp_audit.killchain.recommender import KillSwitch
from mcp_audit.models import AttackPathSummary, Severity  # noqa: F401

# ── Blast-radius summary helpers ──────────────────────────────────────────────


def _severity_counts(summary: AttackPathSummary) -> dict[Severity, int]:
    """Return per-severity path counts for *summary*."""
    counts: dict[Severity, int] = {}
    for path in summary.paths:
        counts[path.severity] = counts.get(path.severity, 0) + 1
    return counts


def _blast_radius_line(summary: AttackPathSummary) -> str:
    """Format a one-line blast-radius description.

    Examples:
        "12 reachable attack paths (3 CRITICAL, 7 HIGH, 2 MEDIUM)"
        "0 reachable attack paths"
    """
    n = len(summary.paths)
    if n == 0:
        return "0 reachable attack paths"
    counts = _severity_counts(summary)
    detail_parts = [
        f"{counts[sev]} {sev}" for sev in _SEVERITY_ORDER if (counts.get(sev, 0)) > 0
    ]
    detail = f" ({', '.join(detail_parts)})" if detail_parts else ""
    return f"{n} reachable attack path{'s' if n != 1 else ''}{detail}"


# ── Markdown renderer ─────────────────────────────────────────────────────────


def render_markdown(
    switches: list[KillSwitch],
    original_summary: AttackPathSummary,
    simulated_summary: AttackPathSummary | None = None,
    *,
    timestamp: datetime | None = None,
) -> str:
    """Render a human-readable Markdown kill-chain report.

    The output is structured as:

    1. Header with current blast-radius summary.
    2. Top-N recommended changes (one ``###`` section per kill switch).
    3. What-if simulation block (if *simulated_summary* is provided).

    Args:
        switches: Ranked kill switches from
            :func:`~mcp_audit.killchain.recommender.recommend`.
        original_summary: Attack-path summary from the original scan.
        simulated_summary: Attack-path summary after applying all *switches*
            (from :func:`~mcp_audit.killchain.simulator.simulate`).  Omitted
            when there are no paths.
        timestamp: Override the report timestamp (useful in tests).

    Returns:
        Multi-line Markdown string (always ends with a newline).
    """
    ts = (timestamp or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = [
        "# mcp-audit killchain report",
        "",
        f"_Generated: {ts}_",
        "",
    ]

    # ── Blast-radius summary ──────────────────────────────────────────────────
    lines += [
        "## Current blast radius",
        "",
        f"**{_blast_radius_line(original_summary)}**",
        "",
    ]

    if not original_summary.paths:
        lines += [
            "No reachable attack paths — no changes recommended.",
            "",
        ]
        return "\n".join(lines)

    # ── No changes produced (degenerate case) ────────────────────────────────
    if not switches:
        lines += [
            "_No actionable kill switches could be derived from the attack-path graph._",  # noqa: E501
            "",
        ]
        return "\n".join(lines)

    # ── All-independent-paths notice ─────────────────────────────────────────
    # When every kill switch removes exactly 1 path, there is no shared edge.
    no_shared_edge = len(original_summary.paths) > 1 and all(
        ks.paths_removed <= 1 for ks in switches
    )
    if no_shared_edge:
        lines += [
            "> **Note:** All attack paths share no common edge — multiple independent "
            "changes are required. Each recommendation below targets one unique path.",
            "",
        ]

    # ── Recommended changes ───────────────────────────────────────────────────
    n_shown = len(switches)
    lines += [
        f"## Top {n_shown} recommended change{'s' if n_shown != 1 else ''}",
        "",
    ]

    for i, ks in enumerate(switches, start=1):
        lines += [
            f"### {i}. {ks.change_id} — {ks.description}",
            "",
            f"- **Paths removed:** {ks.paths_removed} "
            f"(of {len(original_summary.paths)}) — {ks.severity_reduction}",
            f"- **Paths remaining after this change:** {ks.paths_remaining}",
            "",
            f"> {ks.rationale}",
            "",
        ]
        if ks.path_ids_removed:
            ids_str = ", ".join(f"`{pid}`" for pid in ks.path_ids_removed[:8])
            suffix = (
                f" _(+{len(ks.path_ids_removed) - 8} more)_"
                if len(ks.path_ids_removed) > 8
                else ""
            )
            lines += [f"_Paths broken: {ids_str}{suffix}_", ""]

        lines.append("---")
        lines.append("")

    # ── What-if simulation ────────────────────────────────────────────────────
    if simulated_summary is not None:
        lines += [
            "## What-if: all recommended changes applied",
            "",
        ]
        remaining_count = len(simulated_summary.paths)
        n_word = f"{n_shown} change{'s' if n_shown != 1 else ''}"
        if remaining_count == 0:
            total = len(original_summary.paths)
            lines += [
                f"Applying all {n_word} **eliminates all {total} known attack paths**.",
                "",
                "**Post-remediation blast radius:** 0 reachable attack paths",
                "",
            ]
        else:
            from_n = len(original_summary.paths)
            to_s = f"path{'s' if remaining_count != 1 else ''}"
            post = _blast_radius_line(simulated_summary)
            lines += [
                f"Applying all {n_word} reduces blast radius "
                f"from **{from_n}** to **{remaining_count}** {to_s}.",
                "",
                f"**Post-remediation blast radius:** {post}",
                "",
                "_Remaining paths require additional independent changes "
                "not covered by this recommendation set._",
                "",
            ]

    return "\n".join(lines)


# ── JSON renderer ─────────────────────────────────────────────────────────────


def render_json(
    switches: list[KillSwitch],
    original_summary: AttackPathSummary,
    simulated_summary: AttackPathSummary | None = None,
    *,
    timestamp: datetime | None = None,
    indent: int = 2,
) -> str:
    """Render a machine-ingestible JSON kill-chain report.

    The top-level structure is::

        {
          "generated": "<ISO-8601>",
          "original_blast_radius": <int>,
          "simulated_blast_radius": <int> | null,
          "kill_switches": [ ... ]
        }

    Each kill-switch object matches the ``KillSwitch`` Pydantic model schema.

    Args:
        switches: Ranked kill switches.
        original_summary: Attack-path summary from the original scan.
        simulated_summary: Attack-path summary after applying all switches.
        timestamp: Override the report timestamp (useful in tests).
        indent: JSON indentation level.

    Returns:
        JSON string (always ends with a newline).
    """
    ts = timestamp or datetime.now(UTC)
    payload: dict = {
        "generated": ts.isoformat(),
        "original_blast_radius": len(original_summary.paths),
        "simulated_blast_radius": (
            len(simulated_summary.paths) if simulated_summary is not None else None
        ),
        "kill_switches": [
            ks.model_dump(exclude={"path_ids_removed"}) for ks in switches
        ],
    }
    return json.dumps(payload, indent=indent) + "\n"
