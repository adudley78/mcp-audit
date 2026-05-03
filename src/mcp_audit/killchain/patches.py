"""Generate governance-policy patch snippets for kill-chain recommendations.

Produces YAML that, if appended to an existing ``.mcp-audit-policy.yml``, adds
the recommended server removals to the ``approved_servers`` denylist, preventing
those servers from being re-introduced without policy review.

Schema gap note
---------------
The current governance schema (:mod:`mcp_audit.governance.models`) does not
have a ``forbidden_capabilities`` field — policy constraints are at the server
level, not the capability level.  This patch uses server-level denylist entries
as the nearest available approximation.  A future governance schema extension
story should add per-server capability restrictions so patches can target the
specific capability (e.g., ``shell-exec`` on ``db-admin-mcp``) rather than
the entire server.  Inline comments in the generated YAML document this gap.
"""

from __future__ import annotations

from datetime import UTC, datetime

from mcp_audit.killchain.recommender import KillSwitch


def generate_yaml_patch(
    switches: list[KillSwitch],
    *,
    timestamp: datetime | None = None,
) -> str:
    """Generate a YAML ``approved_servers`` denylist patch.

    The output is a valid YAML fragment that can be appended to, or merged
    into, an existing ``.mcp-audit-policy.yml``.  Loading it via
    :func:`~mcp_audit.governance.loader.load_policy` will parse without error.

    Args:
        switches: Kill switches whose ``target_server`` values are to be
            added to the denylist.
        timestamp: Override the generation timestamp (useful in tests).
            Defaults to ``datetime.now(UTC)``.

    Returns:
        Multi-line YAML string (always ends with a newline).
    """
    if not switches:
        return "# No kill-chain recommendations — no patch generated.\n"

    ts = (timestamp or datetime.now(UTC)).strftime("%Y-%m-%d")
    change_ids = ", ".join(ks.change_id for ks in switches)

    lines: list[str] = [
        "# mcp-audit killchain — governance policy patch",
        f"# Generated: {ts}  Covers: {change_ids}",
        "#",
        "# Append this block to your .mcp-audit-policy.yml to block",
        "# re-introduction of the flagged servers.",
        "#",
        "# IMPORTANT: The current governance schema enforces server-level",
        "# restrictions only.  Capability-level restrictions (e.g., disabling",
        "# a specific tool on a server) are not yet supported by the schema.",
        "# Each entry below denylists the *entire server* as the closest",
        "# available approximation.  See the governance schema extension story",
        "# for fine-grained capability control.",
        "",
        "approved_servers:",
        "  mode: denylist",
        "  entries:",
    ]

    for ks in switches:
        note = (
            f"{ks.change_id}: {ks.capability} capability — "
            f"breaks {ks.paths_removed} attack path(s)"
        )
        lines.append(f'    - name: "{ks.target_server}"  # {note}')

    lines.append("")  # trailing newline
    return "\n".join(lines) + "\n"


def generate_pr_comment(switches: list[KillSwitch]) -> str:
    """Generate a stub pull-request comment body for the kill-chain changes.

    Returns a Markdown string suitable for posting as a PR description or
    review comment to document the recommended remediation.

    Args:
        switches: Kill switches to document.

    Returns:
        Markdown string (always ends with a newline).
    """
    if not switches:
        return "_No kill-chain recommendations — nothing to document._\n"

    lines: list[str] = [
        "## mcp-audit killchain — recommended changes",
        "",
        "The following changes are recommended by `mcp-audit killchain` to reduce",
        "the attack-path blast radius of this MCP server configuration.",
        "",
        "| Change | Server | Paths removed | Severity reduction |",
        "| --- | --- | --- | --- |",
    ]
    for ks in switches:
        lines.append(
            f"| `{ks.change_id}` | `{ks.target_server}` "
            f"| {ks.paths_removed} | {ks.severity_reduction} |"
        )

    lines += [
        "",
        "### Details",
        "",
    ]
    for ks in switches:
        lines += [
            f"**{ks.change_id}** — {ks.description}",
            "",
            f"> {ks.rationale}",
            "",
        ]

    lines.append("")
    return "\n".join(lines) + "\n"
