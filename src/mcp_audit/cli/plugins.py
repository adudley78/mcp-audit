"""``mcp-audit plugins`` — Claude Code plugin inventory and scan (STORY-0080)."""

from __future__ import annotations

import typer
from rich.table import Table
from rich.text import Text

from mcp_audit.cli import console, plugins_app
from mcp_audit.plugins.mods import Mod


def _mod_row(mod: Mod | None) -> dict | None:
    """JSON-friendly summary of a mod, or ``None`` when the plugin has none."""
    if mod is None:
        return None
    return {
        "origin": mod.origin,
        "module": str(mod.module_path),
        "events": list(mod.events),
        "calls": list(mod.calls),
    }


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
    from mcp_audit.plugins.mods import discover_mods  # noqa: PLC0415

    plugins = discover_installed_plugins()
    mods = discover_mods(plugins)
    mod_by_root = {m.root: m for m in mods if m.origin == "installed"}
    rows = []
    for plugin in plugins:
        files = plugin_agent_files([plugin])
        mod = mod_by_root.get(plugin.install_path) if plugin.install_path else None
        rows.append(
            {
                "plugin": plugin.plugin_id,
                "scope": plugin.scope,
                "project_path": plugin.project_path,
                "version": plugin.version,
                "source_type": plugin.source_type,
                "pinned_sha": plugin.pinned_sha,
                "git_commit_sha": plugin.git_commit_sha,
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
                "mod": _mod_row(mod),
            }
        )
    # Mods that aren't installed plugins: Claude-written dev mods and
    # CLAUDE_CODE_PLUGIN_DIRS directories (STORY-0085).
    for mod in mods:
        if mod.origin == "installed":
            continue
        rows.append(
            {
                "plugin": mod.name,
                "scope": mod.origin,
                "project_path": None,
                "version": None,
                "source_type": None,
                "pinned_sha": None,
                "git_commit_sha": None,
                "install_path": str(mod.root),
                "skills": 0,
                "commands": 0,
                "mcp_configs": [],
                "mod": _mod_row(mod),
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
        "Mod",
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
            f"{len(row['mod']['events'])} hooks" if row["mod"] else "—",
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
    """Scan installed Claude Code plugins: pin integrity, mods, skills, MCP servers."""
    import json as _json  # noqa: PLC0415

    from mcp_audit.agent_files import skill_package  # noqa: PLC0415
    from mcp_audit.agent_files.analyzer import analyze_agent_files  # noqa: PLC0415
    from mcp_audit.cli import run_scan  # noqa: PLC0415
    from mcp_audit.plugins.analyzer import analyze_plugin_integrity  # noqa: PLC0415
    from mcp_audit.plugins.checkout import analyze_plugin_pins  # noqa: PLC0415
    from mcp_audit.plugins.discovery import (  # noqa: PLC0415
        discover_installed_plugins,
        plugin_agent_files,
    )
    from mcp_audit.plugins.mods import (  # noqa: PLC0415
        analyze_mods,
        analyze_plugin_dirs_setting,
        discover_mods,
    )

    plugins = discover_installed_plugins()
    errors: list[str] = []
    try:
        pin_findings = analyze_plugin_pins(plugins, errors=errors)
    except Exception as exc:  # noqa: BLE001 — a bad record must not crash the scan
        pin_findings = []
        errors.append(f"plugin pin check failed: {type(exc).__name__}")
    skill_files = plugin_agent_files(plugins)
    findings = (
        analyze_plugin_integrity(plugins)
        + pin_findings
        + analyze_mods(discover_mods(plugins))
        + analyze_plugin_dirs_setting()
        + analyze_agent_files(skill_files)
    )
    # Every file in each plugin skill, not only its SKILL.md (STORY-0095).
    findings += skill_package.analyze_skill_packages(
        skill_package.packages_for_agent_files(skill_files), prior=findings
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
    for line in errors:
        console.print(Text(f"Note: {line}", style="dim"))
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
