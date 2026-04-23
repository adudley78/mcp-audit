"""Centralised network policy enforcement for mcp-audit.

All CLI commands that may make network calls must construct a NetworkPolicy
and call require_offline_compatible() in their preflight checks. This replaces
the scattered ad-hoc ``if offline and <flag>`` checks.
"""

from __future__ import annotations

from dataclasses import dataclass

import typer


@dataclass(frozen=True)
class NetworkPolicy:
    """Records which network-touching features are active for a scan."""

    verify_hashes: bool = False
    verify_signatures: bool = False
    check_vulns: bool = False
    connect: bool = False

    @property
    def any_network(self) -> bool:
        """True if any network-touching feature is enabled."""
        return any(
            (
                self.verify_hashes,
                self.verify_signatures,
                self.check_vulns,
                self.connect,
            )
        )


def require_offline_compatible(policy: NetworkPolicy, offline: bool) -> None:
    """Raise typer.Exit(2) with a clear message if --offline conflicts with policy.

    Args:
        policy: The active network policy for this invocation.
        offline: Whether the user passed --offline.
    """
    if not offline:
        return

    conflicts: list[str] = []
    if policy.verify_hashes:
        conflicts.append("--verify-hashes")
    if policy.verify_signatures:
        conflicts.append("--verify-signatures")
    if policy.check_vulns:
        conflicts.append("--check-vulns")
    if policy.connect:
        conflicts.append("--connect")

    if conflicts:
        flags = ", ".join(conflicts)
        from rich.console import Console  # noqa: PLC0415

        Console().print(
            f"[red]Error:[/red] --offline cannot be used with {flags} "
            "(these flags require network access)."
        )
        raise typer.Exit(2)
