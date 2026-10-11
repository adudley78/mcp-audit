"""``mcp-audit plugins`` — Claude Code plugin inventory and scan (STORY-0080)."""

from __future__ import annotations

import typer
from rich.table import Table

from mcp_audit.cli import console, plugins_app


@plugins_app.command("discover")
def plugins_discover(
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json",
    ),
) -> None:
    """List installed Claude Code plugins, their source pin, and what they ship."""
    import json as _json  # noqa: PLC0415

    from mcp_audit.plugins.discovery import (  # noqa: PLC0415
        discover_installed_plugins,
        plugin_agent_files,
        plugin_mcp_config_paths,
        plugins_root,
    )

    plugins = discover_installed_plugins()
    rows = []
    for plugin in plugins:
        files = plugin_agent_files([plugin])
        rows.append(
            {
                "plugin": plugin.plugin_id,
                "scope": plugin.scope,
                "project_path": plugin.project_path,
                "version": plugin.version,
                "source_type": plugin.source_type,
                "pinned_sha": plugin.pinned_sha,
                "install_path": str(plugin.install_path)
                if plugin.install_path
                else None,
                "skills": sum(
                    1 for f in files if f.surface.value == "claude-code-skills"
                ),
                "commands": sum(
                    1 for f in files if f.surface.value == "claude-command"
                ),
                "mcp_configs": [str(p) for p in plugin_mcp_config_paths([plugin])],
            }
        )

    if output_format == "json":
        typer.echo(_json.dumps(rows, indent=2))
        return

    if not rows:
        console.print(f"No Claude Code plugins installed (looked in {plugins_root()}).")
        return

    table = Table(
        "Plugin",
        "Scope",
        "Version",
        "Source",
        "Pin",
        "Skills",
        "Commands",
        "MCP",
        show_header=True,
        header_style="bold",
        border_style="blue",
    )
    for row in rows:
        table.add_row(
            row["plugin"],
            row["scope"],
            row["version"] or "—",
            row["source_type"] or "unknown",
            (row["pinned_sha"] or "")[:12] or "—",
            str(row["skills"]),
            str(row["commands"]),
            str(len(row["mcp_configs"])),
        )
    console.print(table)
    console.print(
        f"\n{len({r['plugin'] for r in rows})} plugin(s), {len(rows)} install record(s)"
    )


@plugins_app.command("scan")
def plugins_scan(
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, sarif",
    ),
) -> None:
    """Scan installed Claude Code plugins: pin integrity, skills, MCP servers."""
    import json as _json  # noqa: PLC0415

    from mcp_audit.agent_files.analyzer import analyze_agent_files  # noqa: PLC0415
    from mcp_audit.cli import run_scan  # noqa: PLC0415
    from mcp_audit.plugins.analyzer import analyze_plugin_integrity  # noqa: PLC0415
    from mcp_audit.plugins.discovery import (  # noqa: PLC0415
        discover_installed_plugins,
        plugin_agent_files,
    )

    plugins = discover_installed_plugins()
    findings = analyze_plugin_integrity(plugins) + analyze_agent_files(
        plugin_agent_files(plugins)
    )
    if plugins:
        # Plugin MCP servers go through the full analyzer pipeline; keep only
        # the findings attributed to them.
        server_scan = run_scan(include_plugins=True, skip_rug_pull=True)
        findings += [
            f for f in server_scan.findings if f.client == "claude-code-plugin"
        ]

    if output_format == "json":
        typer.echo(_json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    if output_format == "sarif":
        from mcp_audit.models import ScanResult  # noqa: PLC0415
        from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415

        typer.echo(format_sarif(ScanResult(findings=findings)))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    count = len({p.plugin_id for p in plugins})
    if not findings:
        console.print(f"[green]✓ No issues found[/green] in {count} plugin(s).")
        return

    sev_colour = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "cyan",
        "LOW": "blue",
        "INFO": "dim",
    }
    table = Table(
        "Plugin / server",
        "ID",
        "Severity",
        "Title",
        show_header=True,
        header_style="bold",
        border_style="blue",
    )
    for f in findings:
        colour = sev_colour.get(f.severity.value, "white")
        table.add_row(
            f.server, f.id, f"[{colour}]{f.severity.value}[/{colour}]", f.title
        )
    console.print(table)
    console.print(f"\n[bold]{len(findings)} finding(s)[/bold] across {count} plugin(s)")
    raise typer.Exit(1)  # noqa: B904
