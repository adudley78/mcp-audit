"""GitHub Actions workflows that run an AI agent (WORKFLOW-001..003, STORY-0091).

A workflow file says, before anything runs, whether an agent step meets text a
stranger can write (an issue, a comment, a pull request title), the
repository's secrets, a token that can write, and no tool allowlist.  That is
the shape of "Comment and Control" (ACM CCS 2026): three vendors' CI agents
posted their own secrets as a pull-request comment, an issue comment, and a
pushed commit.

- :mod:`.discovery` finds ``.github/workflows/*.yml`` / ``*.yaml`` under a
  directory (the working directory for a default scan, a walked tree for
  ``scan --project``).
- :mod:`.analyzer` parses each file with ``yaml.safe_load`` and emits
  ``Finding`` objects with ``analyzer="ci_workflow"``.

Everything here reads files.  Nothing calls ``git``, ``gh`` or any scanned
command, and nothing touches the network.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.ci_workflows.analyzer import analyze_workflow_files
from mcp_audit.ci_workflows.discovery import WorkflowFile, discover_workflow_files
from mcp_audit.models import Finding

__all__ = [
    "WorkflowFile",
    "analyze_workflow_files",
    "discover_workflow_files",
    "scan_workflows",
]


def scan_workflows(root: Path, *, walk: bool = False) -> list[Finding]:
    """Discover and analyze the GitHub Actions workflows under *root*.

    Never raises for file content: unreadable, oversized or malformed files are
    skipped (GitHub would not run a workflow it cannot parse either).

    Args:
        root: Directory to look in.  Resolved before use.
        walk: When ``False`` (default scan), read only
            ``<root>/.github/workflows``.  When ``True`` (``scan --project``),
            also walk *root* for nested repository roots (see
            :func:`discover_workflow_files`).

    Returns:
        WORKFLOW-001..003 findings in file, job and step order.
    """
    return analyze_workflow_files(discover_workflow_files(root, walk=walk))
