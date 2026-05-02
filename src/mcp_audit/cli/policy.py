"""policy sub-app: validate / init / check."""

from __future__ import annotations

from pathlib import Path

import typer

from mcp_audit import cli as _cli
from mcp_audit.cli import console, policy_app

_POLICY_TEMPLATE = """\
# mcp-audit governance policy
# Reference: https://github.com/adudley78/mcp-audit/blob/main/docs/governance.md
version: 1
name: "My organisation governance policy"

# ── Approved servers ──────────────────────────────────────────────────────────
# mode: "allowlist" (only listed servers allowed) or "denylist" (listed forbidden)
# entries: list of approved/denied servers; name supports fnmatch glob patterns
# approved_servers:
#   mode: allowlist
#   violation_severity: high    # critical | high | medium | low | info
#   message: "Server {server_name} is not on the approved server list"
#   entries:
#     - name: "@modelcontextprotocol/server-filesystem"
#       source: npm    # npm | pip | github | null (any)
#       notes: "Official filesystem server"
#     - name: "@modelcontextprotocol/*"
#       notes: "All official MCP servers"

# ── Minimum scan score ────────────────────────────────────────────────────────
# Fails if the numeric scan score (0-100) falls below `minimum`.
# score_threshold:
#   minimum: 70
#   violation_severity: medium
#   message: "Configuration scored {score} ({grade}), below minimum of {minimum}"

# ── Transport policy ──────────────────────────────────────────────────────────
# Controls which MCP transport types are permitted.
# transport_policy:
#   require_tls: false     # block all unencrypted HTTP URLs
#   allow_stdio: true      # stdio (subprocess) transport
#   allow_sse: true        # Server-Sent Events transport
#   allow_http: true       # HTTP/HTTPS (streamable-http) transport
#   block_http: false      # explicit HTTP block (overrides allow_http)
#   violation_severity: high

# ── Registry membership ───────────────────────────────────────────────────────
# Requires servers to appear in the Known-Server Registry.
# registry_policy:
#   require_known: false    # server must be in the registry
#   require_verified: false # server must be marked verified: true
#   violation_severity: medium
#   message: "Server {server_name} is not in the Known-Server Registry"

# ── Finding count limits ──────────────────────────────────────────────────────
# Cap the number of findings at each severity. null means no limit.
# finding_policy:
#   max_critical: 0   # zero tolerance for critical findings
#   max_high: null    # no high-finding limit
#   max_medium: null
#   violation_severity: high

# ── Per-client overrides ──────────────────────────────────────────────────────
# Override any policy block for a specific MCP client.
# Valid client keys: claude-desktop, cursor, vscode, windsurf, claude-code,
#                    copilot-cli, augment
# client_overrides:
#   cursor:
#     approved_servers:
#       mode: allowlist
#       entries:
#         - name: "my-internal-server"
#           notes: "Cursor-only dev tool"
#   claude-desktop:
#     transport_policy:
#       allow_stdio: true
#       allow_http: false
#       block_http: true

# ── Custom scoring weights ─────────────────────────────────────────────────────
# Override the default severity deductions and positive-signal bonuses.
# All deduction values must be <= 0; all positive-signal values must be >= 0.
# Absent keys fall back to their defaults (partial overrides are valid).
# scoring:
#   deductions:
#     CRITICAL: -25   # default
#     HIGH: -10
#     MEDIUM: -5
#     LOW: -2
#     INFO: -1
#   positive_signals:
#     max_total_bonus: 10   # cap on total bonus points
#     no_credentials: 3     # bonus when no credential findings
#     all_pinned: 3         # bonus when no CRITICAL/HIGH findings
#     registry_only: 4      # bonus when no prompt-injection findings
"""


# ── policy validate ───────────────────────────────────────────────────────────


@policy_app.command(name="validate")
def policy_validate(
    file: Path = typer.Argument(help="Path to the governance policy file"),  # noqa: B008
) -> None:
    """Validate a governance policy file (schema check only).

    Exits 0 on success, 2 on any validation error.
    """
    from mcp_audit.governance.loader import load_policy  # noqa: PLC0415

    try:
        loaded = load_policy(file)
    except ValueError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(2)  # noqa: B904

    if loaded is None:
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(2)  # noqa: B904

    console.print(
        f"[green]✔ Policy valid:[/green] {loaded.name!r}  "
        f"[dim](version {loaded.version})[/dim]"
    )
    if loaded.approved_servers:
        n = len(loaded.approved_servers.entries)
        console.print(
            f"  approved_servers: {loaded.approved_servers.mode.value}, "
            f"{n} entr{'y' if n == 1 else 'ies'}"
        )
    if loaded.score_threshold:
        console.print(f"  score_threshold: minimum={loaded.score_threshold.minimum}")
    if loaded.transport_policy:
        console.print("  transport_policy: configured")
    if loaded.registry_policy:
        console.print(
            f"  registry_policy: require_known={loaded.registry_policy.require_known}, "
            f"require_verified={loaded.registry_policy.require_verified}"
        )
    if loaded.finding_policy:
        console.print("  finding_policy: configured")
    if loaded.client_overrides:
        console.print(
            f"  client_overrides: {', '.join(loaded.client_overrides.keys())}"
        )
    if loaded.scoring is not None:
        d = loaded.scoring.deductions
        ps = loaded.scoring.positive_signals
        console.print(
            f"  scoring: deductions=({d.CRITICAL}/{d.HIGH}/{d.MEDIUM}/{d.LOW}/{d.INFO})"
            f" max_bonus={ps.max_total_bonus}"
        )


# ── policy init ───────────────────────────────────────────────────────────────


@policy_app.command(name="init")
def policy_init(
    output: Path = typer.Option(  # noqa: B008
        Path(".mcp-audit-policy.yml"),
        "--output",
        "-o",
        help="Destination path for the generated policy file",
    ),
) -> None:
    """Write a commented governance policy template to disk.

    Aborts if the destination file already exists.
    """
    if output.exists():
        console.print(
            f"[red]File already exists:[/red] {output}\n"
            "  Delete it manually or choose a different path with --output."
        )
        raise typer.Exit(2)  # noqa: B904

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_POLICY_TEMPLATE, encoding="utf-8")
    console.print(f"[green]✔ Policy template written to:[/green] {output}")
    console.print(
        "\nNext steps:\n"
        "  1. Edit the file to define your organisation's requirements.\n"
        "  2. Run [bold]mcp-audit policy validate[/bold] to check syntax.\n"
        "  3. Run [bold]mcp-audit scan[/bold] — policy is auto-discovered.\n"
    )


# ── policy check ─────────────────────────────────────────────────────────────


@policy_app.command(name="check")
def policy_check(
    policy_pos: Path | None = typer.Argument(  # noqa: B008
        None,
        help="Policy file to check (positional; alternative to --policy)",
    ),
    policy: Path | None = typer.Option(  # noqa: B008
        None,
        "--policy",
        help=(
            "Path to governance policy file "
            "(alternative to positional; auto-discovered when both omitted)"
        ),
    ),
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Additional config path to check"
    ),
) -> None:
    """Evaluate governance policy violations only (no full security scan).

    Fast: skips all security analyzers, hashing, and network calls.
    """
    from mcp_audit.governance.evaluator import evaluate_governance  # noqa: PLC0415
    from mcp_audit.governance.loader import load_policy  # noqa: PLC0415

    # Merge positional and --policy flag; positional takes precedence.
    resolved_policy = policy_pos or policy

    # Load policy.
    try:
        loaded_policy = load_policy(resolved_policy)
    except ValueError as exc:
        console.print(f"[red]Governance policy error:[/red] {exc}")
        raise typer.Exit(2)  # noqa: B904

    if loaded_policy is None:
        console.print(
            "[yellow]No governance policy found.[/yellow]  "
            "Use [bold]mcp-audit policy init[/bold] to create one or "
            "pass [bold]--policy <path>[/bold]."
        )
        raise typer.Exit(0)  # noqa: B904

    # Discover and parse configs (no analyzers, no scoring).
    extra_paths = [path] if path else None
    configs = _cli.discover_configs(extra_paths=extra_paths)

    all_servers = []
    for config in configs:
        try:
            all_servers.extend(_cli.parse_config(config))
        except ValueError as exc:
            console.print(f"[yellow]Warning: {exc}[/yellow]")

    violations = evaluate_governance(
        servers=all_servers,
        policy=loaded_policy,
    )

    console.print(
        f"\n[bold]Governance check:[/bold] {loaded_policy.name!r}\n"
        f"  {len(configs)} client(s), {len(all_servers)} server(s) evaluated\n"
    )

    if not violations:
        console.print("[green]✔ No policy violations found.[/green]\n")
        raise typer.Exit(0)  # noqa: B904

    from mcp_audit.output.terminal import (  # noqa: PLC0415
        SEVERITY_COLORS,
        SEVERITY_ICONS,
    )

    console.print(f"[yellow bold]{len(violations)} violation(s) found:[/yellow bold]\n")
    for v in violations:
        color = SEVERITY_COLORS[v.severity]
        icon = SEVERITY_ICONS[v.severity]
        console.print(
            f"{icon} [{color} bold]{v.severity.value}[/{color} bold]  "
            f"[dim]{v.client}/{v.server}[/dim]"
        )
        console.print(f"   {v.title}")
        console.print(f"   [dim]→ {v.evidence}[/dim]")
        console.print()

    raise typer.Exit(1)  # noqa: B904
