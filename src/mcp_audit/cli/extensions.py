"""extensions sub-app: discover / scan."""

from __future__ import annotations

import typer
from rich.table import Table

from mcp_audit.cli import console, extensions_app

# ── extensions discover ───────────────────────────────────────────────────────


@extensions_app.command("discover")
def extensions_discover(
    client: str | None = typer.Option(  # noqa: B008
        None,
        "--client",
        help="Filter to a specific client (e.g. vscode, cursor)",
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json",
    ),
) -> None:
    """Discover installed IDE extensions across supported AI coding clients."""
    import json as _json  # noqa: PLC0415

    from mcp_audit.extensions.discovery import discover_extensions  # noqa: PLC0415

    clients = [client] if client else None
    extensions = discover_extensions(clients=clients)

    if output_format == "json":
        typer.echo(_json.dumps([e.model_dump() for e in extensions], indent=2))
        return

    client_names = sorted({e.client_name for e in extensions})
    summary = (
        f"Found [bold]{len(extensions)}[/bold] extension(s) "
        f"across [bold]{len(client_names)}[/bold] client(s)"
    )

    if not extensions:
        console.print(summary)
        return

    table = Table(
        "Client",
        "Extension ID",
        "Publisher",
        "Version",
        "Last Updated",
        show_header=True,
        header_style="bold",
    )
    for ext in sorted(extensions, key=lambda e: (e.client_name, e.extension_id)):
        table.add_row(
            ext.client_name,
            ext.extension_id,
            ext.publisher,
            ext.version,
            ext.last_updated or "unknown",
        )
    console.print(table)
    console.print(f"\n{summary}")


# ── extensions scan ───────────────────────────────────────────────────────────


@extensions_app.command("scan")
def extensions_scan(
    client: str | None = typer.Option(  # noqa: B008
        None,
        "--client",
        help="Filter to a specific client (e.g. vscode, cursor)",
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, sarif",
    ),
) -> None:
    """Scan installed IDE extensions for security issues."""
    import json as _json  # noqa: PLC0415

    from mcp_audit.extensions.analyzer import analyze_extensions  # noqa: PLC0415
    from mcp_audit.extensions.discovery import discover_extensions  # noqa: PLC0415

    clients = [client] if client else None
    extensions = discover_extensions(clients=clients)
    findings = analyze_extensions(extensions)

    if output_format == "json":
        typer.echo(_json.dumps([f.model_dump() for f in findings], indent=2))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    if output_format == "sarif":
        from mcp_audit.models import ScanResult  # noqa: PLC0415
        from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415

        _mock_result = ScanResult(findings=findings)
        typer.echo(format_sarif(_mock_result))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    # Terminal output
    if not findings:
        console.print(
            f"[green]✓ No issues found[/green] in {len(extensions)} extension(s)."
        )
        return

    sev_colour = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "cyan",
        "LOW": "blue",
        "INFO": "dim",
    }
    table = Table(
        "Extension",
        "Client",
        "Severity",
        "Title",
        show_header=True,
        header_style="bold",
        border_style="blue",
    )
    for f in findings:
        colour = sev_colour.get(f.severity.value, "white")
        table.add_row(
            f.server,
            f.client,
            f"[{colour}]{f.severity.value}[/{colour}]",
            f.title,
        )
    console.print(table)
    console.print(
        f"\n[bold]{len(findings)} finding(s)[/bold] across "
        f"{len(extensions)} extension(s)"
    )
    raise typer.Exit(1)  # noqa: B904
