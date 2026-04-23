"""activate, license, and version commands."""

from __future__ import annotations

import typer

from mcp_audit import __version__
from mcp_audit.cli import app, console
from mcp_audit.licensing import (
    LicenseInfo,
    get_active_license,
    get_last_verify_failure,
    save_license,
)

# ── version ───────────────────────────────────────────────────────────────────


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"mcp-audit {__version__}")


# ── activate ──────────────────────────────────────────────────────────────────


@app.command()
def activate(
    key: str = typer.Argument(help="License key string to activate"),  # noqa: B008
) -> None:
    """Activate a previously issued license key.

    mcp-audit is now fully open source (Apache 2.0) and every feature is
    available to every user — activation is no longer required.  This command
    is retained so users who were issued a key before the open-source pivot
    can still verify and record it on their machine.
    """
    try:
        info: LicenseInfo = save_license(key)
    except ValueError:
        reason = get_last_verify_failure()
        if reason == "revoked":
            console.print(
                "[red]✗ License revoked.[/red] Contact support@mcp-audit.dev with "
                "your order ID if this is in error. [MCPA-LIC-REVOKED]"
            )
        elif reason == "expired":
            console.print("[yellow]✗ License expired.[/yellow] [MCPA-LIC-EXPIRED]")
        else:
            console.print(
                "[red]✗ Invalid license key. Check your key and try again.[/red]"
            )
            console.print(
                "  mcp-audit is fully open source — a license key is not "
                "required; every feature is available to every user."
            )
        raise typer.Exit(2)  # noqa: B904

    tier_label = info.tier.capitalize()
    console.print(f"[green]✓ License activated: {tier_label} tier[/green]")
    console.print(f"  Email:   {info.email}")
    console.print(f"  Expires: {info.expires.isoformat()}")


# ── license ───────────────────────────────────────────────────────────────────


@app.command()
def license() -> None:  # noqa: A001
    """Show current license status."""
    info = get_active_license()
    if info is None:
        console.print("[bold]mcp-audit (Apache 2.0, fully open source)[/bold]")
        console.print(
            "  No license key activated — every feature is already available. "
            "Support development via GitHub Sponsors."
        )
        return

    status = "[green]Active[/green]" if info.is_valid else "[red]Expired[/red]"
    tier_label = info.tier.capitalize()
    console.print(f"[bold]mcp-audit — legacy {tier_label} key[/bold]")
    console.print(f"  Email:   {info.email}")
    console.print(f"  Expires: {info.expires.isoformat()}")
    console.print(f"  Status:  {status}")
    console.print(
        "  Note: gating has been removed; all features are available to all users."
    )
