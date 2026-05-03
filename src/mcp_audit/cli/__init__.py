"""mcp-audit CLI — MCP Security Scanner.

Package root.  Defines the top-level ``app`` (plus per-feature sub-apps) and
re-exports module-level attributes that the test suite reaches for through the
``mcp_audit.cli`` namespace (e.g. ``mcp_audit.cli.run_scan``).

Command implementations live in the adjacent submodules (``scan.py``,
``baseline.py``, etc.); importing them at the end of this file triggers the
Typer ``@app.command(...)`` decorators that register each command with ``app``.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import typer
from platformdirs import user_config_dir
from rich.console import Console

from mcp_audit import __version__
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import discover_configs
from mcp_audit.scanner import run_scan


def _force_utf8_std_streams() -> None:
    """Reconfigure stdout/stderr to UTF-8.

    Windows' default console codepage is cp1252, which cannot encode the emoji
    (✅ 🔴 🟠 …) and box-drawing characters baked into
    ``mcp_audit.output.terminal``.  Rich's Console inherits its output
    encoding from ``sys.stdout.encoding`` (queried lazily), so promoting the
    streams to UTF-8 before the first ``console.print`` is enough to prevent
    UnicodeEncodeError inside ``print_results()`` on Windows (cmd.exe,
    PowerShell, and the bash.exe shell GitHub Actions uses for the release
    smoke test).

    Guarded with ``contextlib.suppress`` because non-default streams
    (captured pipes, embedded interpreters, etc.) may not expose
    ``.reconfigure()``.
    """
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, OSError):
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]


_force_utf8_std_streams()

# TODO(schema-version): after fetch, compare the downloaded JSON's
# "schema_version" field against the binary's expected schema version.
# If the fetched schema_version > expected, warn and skip the update to
# avoid loading a schema with unknown fields into an older binary.
_UPDATE_REGISTRY_URL = (
    f"https://raw.githubusercontent.com/adudley78/mcp-audit/"
    f"v{__version__}/registry/known-servers.json"
)
_USER_CONFIG_DIR = Path(user_config_dir("mcp-audit"))
_REGISTRY_CACHE_PATH = _USER_CONFIG_DIR / "registry" / "known-servers.json"

app = typer.Typer(
    name="mcp-audit",
    help="Privacy-first security scanner for MCP server configurations.",
    no_args_is_help=True,
)
console = Console()

# ── baseline sub-app ──────────────────────────────────────────────────────────

baseline_app = typer.Typer(
    name="baseline",
    help="Save and compare MCP configuration baselines.",
    no_args_is_help=True,
)
app.add_typer(baseline_app, name="baseline")

# ── rule sub-app ──────────────────────────────────────────────────────────────

rule_app = typer.Typer(
    name="rule",
    help="Manage and test policy-as-code detection rules.",
    no_args_is_help=True,
)
app.add_typer(rule_app, name="rule")

# ── policy sub-app ────────────────────────────────────────────────────────────

policy_app = typer.Typer(
    name="policy",
    help="Manage governance policy files (.mcp-audit-policy.yml).",
    no_args_is_help=True,
)
app.add_typer(policy_app, name="policy")

# ── extensions sub-app ────────────────────────────────────────────────────────

extensions_app = typer.Typer(
    name="extensions",
    help="Discover and scan installed IDE extensions for security issues.",
    no_args_is_help=True,
)
app.add_typer(extensions_app, name="extensions")


# ── entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """Entry point."""
    app()


# ── Submodule imports — must come last ────────────────────────────────────────
# Each submodule attaches its commands to ``app`` (or a sub-app) at import time
# via Typer decorators, so we import them after ``app`` and the sub-apps are
# defined.  Ordering among submodules does not matter.
from mcp_audit.cli import (  # noqa: E402, F401  — side-effect imports register commands
    baseline,
    dashboard,
    diff,
    extensions,
    fleet,
    killchain,
    policy,
    push_nucleus,
    registry,
    rules,
    sast,
    sbom,
    scan,
    shadow,
    version,
)

if __name__ == "__main__":
    main()


__all__ = [
    "__version__",
    "_REGISTRY_CACHE_PATH",
    "_UPDATE_REGISTRY_URL",
    "_USER_CONFIG_DIR",
    "app",
    "baseline_app",
    "console",
    "diff",
    "discover_configs",
    "extensions_app",
    "killchain",
    "main",
    "parse_config",
    "policy_app",
    "rule_app",
    "run_scan",
    "shadow",
]
