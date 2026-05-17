"""The ``register`` command — opt-in registration flow."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.rule import Rule

from mcp_audit.cli import app
from mcp_audit.registration import client as _reg_client
from mcp_audit.registration import manager as _reg_manager
from mcp_audit.registration.models import RegistrationConfig


def _truncate_email(email: str) -> str:
    """Return a privacy-safe truncated form: ``sa***@ibm.com``."""
    at = email.find("@")
    if at <= 2:
        return email
    visible = email[:2]
    domain = email[at:]
    return f"{visible}***{domain}"


@app.command("register")
def register(
    clear: bool = typer.Option(  # noqa: B008
        False,
        "--clear",
        help="Remove the registration file and stop sending pings.",
    ),
    status: bool = typer.Option(  # noqa: B008
        False,
        "--status",
        help="Show current registration state without modifying anything.",
    ),
) -> None:
    """Opt-in registration: get new rule notifications and follow-up support.

    Registration is optional and collects only what you provide (name, org,
    email).  No config data, server names, or credentials are ever sent.

    Run with no flags to start the interactive registration flow.
    Use ``--status`` to check current registration.
    Use ``--clear`` to remove the registration file and stop pings.
    """
    console = Console(width=80)

    if clear:
        _handle_clear(console)
        return

    if status:
        _handle_status(console)
        return

    _handle_register(console)


def _handle_clear(console: Console) -> None:
    """Remove the registration file."""
    removed = _reg_manager.clear_registration()
    if removed:
        console.print(
            "[green]Registration removed.[/green] No further pings will be sent."
        )
    else:
        console.print("[dim]No registration file found — nothing to remove.[/dim]")


def _handle_status(console: Console) -> None:
    """Print current registration state."""
    config = _reg_manager.load_registration()
    if config is None:
        console.print("[dim]Not registered.[/dim]")
        console.print(
            "Run [bold]mcp-audit register[/bold] to opt in to new rule notifications."
        )
        return

    console.print()
    console.print(Rule("[bold]Registration Status[/bold]"))
    console.print()
    if config.name:
        console.print(f"  Name:        {config.name}")
    if config.org:
        console.print(f"  Org:         {config.org}")
    console.print(f"  Email:       {_truncate_email(config.email)}")
    console.print(f"  Follow-up:   {'yes' if config.follow_up_requested else 'no'}")
    console.print(f"  Registered:  {config.registered_at.strftime('%Y-%m-%d')}")
    console.print()
    console.print("[dim]Run [bold]mcp-audit register --clear[/bold] to remove.[/dim]")
    console.print()


def _handle_register(console: Console) -> None:
    """Interactive registration flow."""
    existing = _reg_manager.load_registration()
    if existing is not None:
        console.print()
        label = existing.org or existing.name or _truncate_email(existing.email)
        console.print(f"[green]Already registered[/green] as [bold]{label}[/bold].")
        console.print(
            "Run [bold]mcp-audit register --clear[/bold] to remove, "
            "or [bold]mcp-audit register --status[/bold] to view details."
        )
        console.print()
        return

    console.print()
    console.print(Rule("[bold]mcp-audit — Optional Registration[/bold]"))
    console.print()
    console.print(
        "mcp-audit is [bold]free and open source[/bold]."
        " Registration is [bold]optional[/bold]."
    )
    console.print()
    console.print("If you register, you'll get:")
    console.print("  - A weekly digest of new community detection rules")
    console.print("  - Early access to new rule packs before public release")
    console.print("  - (Optional) A follow-up if your scan grade is C or below")
    console.print()
    console.print(
        "Your registration sends: name, org, email, mcp-audit version, and grade only."
    )
    console.print("[dim]No config data. No server names. No credentials. Ever.[/dim]")
    console.print()

    name = typer.prompt("Name (or handle)", default="", show_default=False).strip()
    org = typer.prompt("Org", default="", show_default=False).strip()

    email = ""
    while not email:
        raw = typer.prompt("Email").strip()
        try:
            cfg_test = RegistrationConfig(
                name=name,
                org=org,
                email=raw,
                follow_up_requested=False,
                registered_at=__import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ),
            )
            email = cfg_test.email
        except Exception:  # noqa: BLE001
            console.print(
                f"[red]'{raw}' does not look like a valid email address.[/red]"
                " Please include an @."
            )

    follow_up_raw = (
        typer.prompt(
            "Send a follow-up if my grade is C or below? [y/N]",
            default="n",
            show_default=False,
        )
        .strip()
        .lower()
    )
    follow_up = follow_up_raw in ("y", "yes")

    from mcp_audit.registration.manager import build_registration, save_registration

    config = build_registration(
        name=name,
        org=org,
        email=email,
        follow_up_requested=follow_up,
    )
    path = save_registration(config)

    console.print()
    console.print("[green]Registered.[/green] You'll hear from us when new rules drop.")
    console.print(f"[dim]Registration stored at {path}[/dim]")
    console.print()

    # Fire the initial registration POST (silent on failure)
    ok = _reg_client.post_registration(config, grade="?")
    if not ok:
        console.print(
            "[dim]Registration ping failed (offline?) — your local file is saved.[/dim]"
        )
