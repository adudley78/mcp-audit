"""Shared helper for Pro/Enterprise feature gating at the CLI layer.

Analyzers and ``scanner.py`` never call this — gating is CLI-only.  Scans
always execute in full; gating only restricts which CLI features (custom
rules, SAST integration, extension scanning, dashboard rendering, etc.) are
exposed to the operator.

Every CLI gate site should funnel through :func:`gate` so the upsell panel
wording stays consistent across commands.  A future Pro flag is a one-liner:

.. code-block:: python

    if not gate("my_feature", console, message="--my-flag skipped."):
        return  # or: raise typer.Exit(2) for hard-gated commands
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

_UPSELL_BODY_PRO = (
    "[bold]⚡ Pro feature required[/bold]\n"
    "This requires a Pro or Enterprise license.\n"
    "Activate with: [bold]mcp-audit activate <key>[/bold]\n"
    "Upgrade at [link=https://mcp-audit.dev/pro]"
    "https://mcp-audit.dev/pro[/link]"
)

_UPSELL_BODY_ENTERPRISE = (
    "[bold]🏢 Enterprise feature required[/bold]\n"
    "This requires an Enterprise license.\n"
    "Activate with: [bold]mcp-audit activate <key>[/bold]\n"
    "Upgrade at [link=https://mcp-audit.dev/pro]"
    "https://mcp-audit.dev/pro[/link]"
)


def gate(
    feature: str,
    console: Console,
    message: str | None = None,
) -> bool:
    """Return ``True`` when *feature* is available for the active license.

    When the feature is not available, prints the standard Pro or Enterprise
    upsell panel to *console* (chosen based on the minimum required tier for
    *feature*) and returns ``False``.  Callers decide whether to continue
    (soft gate — skip the feature) or exit (hard gate — ``raise typer.Exit(2)``).

    Args:
        feature: Feature key from ``_FEATURE_TIERS`` in ``licensing.py``
            (e.g. ``"custom_rules"``, ``"sast"``, ``"fleet_merge"``).
        console: Rich console used to render the upsell panel.
        message: Optional context-specific hint rendered in dim text below
            the panel body — typically a single line explaining what the
            caller is about to skip (e.g. ``"--rules-dir skipped; bundled
            community rules still apply."``).

    Returns:
        ``True`` when the feature is available; ``False`` otherwise.
    """
    # Resolve the license check through the ``cli`` module attribute so that
    # existing tests patching ``mcp_audit.cli.cached_is_pro_feature_available``
    # intercept the check.  Late-imported to avoid a circular dependency at
    # module load (``cli`` imports ``gate``).
    from mcp_audit import cli as _cli  # noqa: PLC0415

    if _cli.cached_is_pro_feature_available(feature):
        return True

    # Choose upsell wording based on the minimum required tier.  Features
    # whose tier set includes only "enterprise" (not "pro") get the Enterprise
    # label; everything else uses the standard Pro label.
    from mcp_audit.licensing import _FEATURE_TIERS  # noqa: PLC0415

    tiers = _FEATURE_TIERS.get(feature, frozenset({"pro", "enterprise"}))
    is_enterprise_only = "pro" not in tiers and bool(tiers)
    body = _UPSELL_BODY_ENTERPRISE if is_enterprise_only else _UPSELL_BODY_PRO
    if message:
        body = f"{body}\n[dim]{message}[/dim]"

    console.print(Panel(body, style="yellow", border_style="yellow"))
    return False
