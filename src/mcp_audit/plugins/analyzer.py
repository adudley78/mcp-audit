"""Plugin integrity checks: PLUGIN-001 (pin mismatch) and PLUGIN-002 (unpinned).

Background: Plugin4Shell (AIR Security, 2026-09-17) — Claude Code, Codex,
Copilot and Gemini CLI checked out a marketplace-pinned commit without
verifying ``HEAD``, so a hostile plugin repository could swap the code while
the pin still looked honored.  Claude Code records a git-sourced plugin's
version as the commit SHA shortened to 12 characters when neither
``plugin.json`` nor the marketplace entry sets ``version`` (docs:
plugins/loading, "How Claude Code computes the version").

PLUGIN-001 compares that record with the marketplace's *current* pin.  A
mismatch means the plugin has not been updated since the pin moved, or the
record does not match the pin.  It does not hash plugin files, so it cannot
see a swap that Claude Code recorded at the requested commit — which is how
the agents reported a Plugin4Shell install.  It is a pin-drift check, not a
Plugin4Shell detector.
"""

from __future__ import annotations

from mcp_audit.models import Finding, Severity
from mcp_audit.plugins.models import GIT_SOURCE_TYPES, InstalledPlugin

_PLUGIN4SHELL_REF = "https://www.air.security/blog-posts/plugin4shell"


def _mismatch(plugin: InstalledPlugin, sha: str) -> Finding:
    where = f"scope {plugin.scope}" + (
        f", project {plugin.project_path}" if plugin.project_path else ""
    )
    return Finding(
        id="PLUGIN-001",
        severity=Severity.MEDIUM,
        analyzer="plugins",
        client="claude-code",
        server=plugin.plugin_id,
        title=(
            f"Installed plugin does not match its marketplace pin: {plugin.plugin_id}"
        ),
        description=(
            f"The marketplace pins {plugin.plugin_id} to commit {sha[:12]}, but"
            f" Claude Code recorded version {plugin.version} for this install"
            f" ({where}). Either the plugin has not been updated since the"
            " marketplace moved its pin, or the install record does not match"
            " the pin. This compares records only; it does not hash plugin"
            " files, so it cannot confirm what code is installed."
        ),
        evidence=(
            f"plugin: {plugin.plugin_id} | pinned sha: {sha} | installed version:"
            f" {plugin.version} | install path: {plugin.install_path}"
        ),
        remediation=(
            f"Run `claude plugin update {plugin.plugin_id}` on Claude Code 2.1.179"
            " or later (patched for Plugin4Shell). If the version still differs"
            " from the pin, uninstall the plugin and report it to the marketplace"
            f" owner. See {_PLUGIN4SHELL_REF}."
        ),
        cwe="CWE-494",
        owasp_mcp_top_10=["MCP04"],
        finding_path=str(plugin.record_path),
    )


def _unpinned(plugin: InstalledPlugin) -> Finding:
    return Finding(
        id="PLUGIN-002",
        severity=Severity.LOW,
        analyzer="plugins",
        client="claude-code",
        server=plugin.plugin_id,
        title=f"Plugin source is not pinned to a commit: {plugin.plugin_id}",
        description=(
            f"The marketplace entry for {plugin.plugin_id} fetches a"
            f" {plugin.source_type} source with no `sha`, so each install or update"
            " takes whatever the branch or tag points at then. A pin is what lets"
            " a reviewed commit stay the commit you run."
        ),
        evidence=(
            f"plugin: {plugin.plugin_id} | source type: {plugin.source_type}"
            " | sha: none"
        ),
        remediation=(
            "Ask the marketplace owner to pin the entry with a full 40-character"
            " `sha`, or install from a marketplace you control that does."
        ),
        cwe="CWE-829",
        owasp_mcp_top_10=["MCP04"],
        finding_path=str(plugin.record_path),
    )


def analyze_plugin_integrity(plugins: list[InstalledPlugin]) -> list[Finding]:
    """Return PLUGIN-001/002 findings for installed git-sourced plugins.

    PLUGIN-001 is skipped, never guessed, when the comparison is not meaningful:
    a ``version`` set in ``plugin.json`` or the marketplace entry (the recorded
    version is then that string, not a SHA), a ``git-subdir`` source (its version
    also carries a path hash in an undocumented form), or a recorded version of
    ``unknown`` (a known Claude Code bug, anthropics/claude-code#17032).

    Args:
        plugins: Install records from
            :func:`~mcp_audit.plugins.discovery.discover_installed_plugins`.

    Returns:
        Findings, at most one PLUGIN-002 per plugin id and one PLUGIN-001 per
        distinct (plugin id, recorded version).
    """
    findings: list[Finding] = []
    unpinned_seen: set[str] = set()
    mismatch_seen: set[tuple[str, str]] = set()
    for plugin in plugins:
        if plugin.source_type not in GIT_SOURCE_TYPES:
            continue
        sha = plugin.pinned_sha
        if sha is None:
            if plugin.plugin_id not in unpinned_seen:
                unpinned_seen.add(plugin.plugin_id)
                findings.append(_unpinned(plugin))
            continue
        if plugin.source_type == "git-subdir":
            continue
        if plugin.manifest_version or plugin.entry_version:
            continue
        version = (plugin.version or "").strip().lower()
        if not version or version == "unknown" or version == sha[:12]:
            continue
        key = (plugin.plugin_id, version)
        if key not in mismatch_seen:
            mismatch_seen.add(key)
            findings.append(_mismatch(plugin, sha))
    return findings
