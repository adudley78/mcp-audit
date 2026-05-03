"""mcp-audit sbom — generate a CycloneDX SBOM for configured MCP servers."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from mcp_audit.cli import app
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import discover_configs
from mcp_audit.models import ScanResult
from mcp_audit.vulnerability.depsdev import fetch_transitive_deps
from mcp_audit.vulnerability.models import ResolvedPackage
from mcp_audit.vulnerability.resolver import extract_ecosystem_and_version


@app.command("sbom")
def sbom(
    path: Path = typer.Argument(  # noqa: B008
        None,
        help="MCP config file or directory. Defaults to auto-discovery.",
        exists=False,
    ),
    format: str = typer.Option(  # noqa: A002
        "cyclonedx",
        "--format",
        "-f",
        help="Output format: cyclonedx (default) or terminal.",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        "-o",
        help="Write SBOM to this file instead of stdout.",
    ),
    offline: bool = typer.Option(  # noqa: B008
        False,
        "--offline",
        help="Use only the bundled registry; skip all network calls.",
    ),
) -> None:
    """Generate a CycloneDX 1.5 SBOM for all MCP servers in PATH.

    Resolves transitive dependencies via deps.dev (requires network unless
    --offline; offline mode uses registry-only data).
    """
    console = Console()

    if offline:
        console.print(
            "[yellow]Warning:[/yellow] --offline mode limits SBOM to "
            "top-level packages only (no transitive dependency resolution)."
        )

    # Validate user-supplied path
    if path is not None and not path.resolve().exists():
        console.print(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(2)

    # Discover and parse configs
    extra_paths = [path] if path else None
    discovered = discover_configs(
        extra_paths=extra_paths,
        skip_auto_discovery=bool(extra_paths),
    )
    servers = []
    for dc in discovered:
        try:
            servers.extend(parse_config(dc))
        except ValueError as exc:
            console.print(f"[yellow]Warning:[/yellow] {exc}")

    if not servers:
        if not discovered:
            console.print("[yellow]No MCP config files found.[/yellow]")
        else:
            console.print(
                f"[yellow]Found {len(discovered)} MCP config file(s) but no servers "
                "are configured in them.[/yellow]"
            )
        raise typer.Exit(0)

    # Resolve packages and (optionally) transitive dependencies
    all_packages: list[ResolvedPackage] = []
    for server in servers:
        result = extract_ecosystem_and_version(server)
        if result is None:
            continue
        ecosystem, name, version = result
        if not offline:
            deps = fetch_transitive_deps(
                ecosystem, name, version, source_server=server.name
            )
        else:
            deps = [
                ResolvedPackage(
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    direct=True,
                    source_server=server.name,
                )
            ]
        all_packages.extend(deps)

    # Build a minimal ScanResult for the formatter
    scan_result = ScanResult(
        servers=servers,
        findings=[],
        clients_scanned=[],
        configs_found=len(discovered),
    )

    if format == "cyclonedx":
        from mcp_audit.output.cyclonedx import CycloneDxFormatter  # noqa: PLC0415

        try:
            content = CycloneDxFormatter().format(scan_result)
        except ImportError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(2) from None
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content)
            console.print(f"SBOM written to {output}")
        else:
            print(content)
    elif format == "terminal":
        from rich.tree import Tree  # noqa: PLC0415

        tree = Tree("[bold]MCP Server Dependencies[/bold]")
        for pkg in all_packages:
            prefix = "→" if pkg.direct else "  ↳"
            tree.add(
                f"{prefix} [cyan]{pkg.name}[/cyan]@{pkg.version}"
                f" ({pkg.ecosystem.value})"
            )
        console.print(tree)
    else:
        console.print(
            f"[red]Error:[/red] Unknown format '{format}'. "
            "Use 'cyclonedx' or 'terminal'."
        )
        raise typer.Exit(2)
