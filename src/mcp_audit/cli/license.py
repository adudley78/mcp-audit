"""activate, license, and version commands."""

from __future__ import annotations

import typer

from mcp_audit import __version__
from mcp_audit.cli import app, console
from mcp_audit.licensing import (
    LicenseInfo,
    get_active_license,
    save_license,
)

# ── version ───────────────────────────────────────────────────────────────────


@app.command()
def version() -> None:
    """Show version information."""
    info = get_active_license()
    if info is not None and info.is_valid:
        tier_label = info.tier.capitalize()
    else:
        tier_label = "Community"
    console.print(f"mcp-audit {__version__} ({tier_label})")


# ── activate ──────────────────────────────────────────────────────────────────


@app.command()
def activate(
    key: str = typer.Argument(help="License key string to activate"),  # noqa: B008
) -> None:
    """Activate a Pro or Enterprise license key."""
    try:
        info: LicenseInfo = save_license(key)
    except ValueError:
        console.print("[red]✗ Invalid license key. Check your key and try again.[/red]")
        console.print(
            "  Purchase a license at [link=https://mcp-audit.dev/pro]"
            "https://mcp-audit.dev/pro[/link]"
        )
        raise typer.Exit(1)  # noqa: B904

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
        console.print("[bold]mcp-audit Community (free)[/bold]")
        console.print(
            "  Upgrade to Pro: [link=https://mcp-audit.dev/pro]"
            "https://mcp-audit.dev/pro[/link]"
        )
        return

    status = "[green]Active[/green]" if info.is_valid else "[red]Expired[/red]"
    tier_label = info.tier.capitalize()
    console.print(f"[bold]mcp-audit {tier_label}[/bold]")
    console.print(f"  Email:   {info.email}")
    console.print(f"  Expires: {info.expires.isoformat()}")
    console.print(f"  Status:  {status}")
