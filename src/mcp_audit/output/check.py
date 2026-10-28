"""One-page security verdict formatter for `mcp-audit check`."""

from __future__ import annotations

from rich.console import Console
from rich.rule import Rule

from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.registration.models import RegistrationConfig

# ── Severity colour map (Rich markup) ─────────────────────────────────────────

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "orange1 bold",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

# ── Auto-fixable finding IDs ───────────────────────────────────────────────────
# These IDs map to remediations that `mcp-audit fix --apply` can handle.

_AUTO_FIXABLE: frozenset[str] = frozenset(
    {
        "CRED-001",
        "CRED-002",
        "CRED-003",
        "TRANSPORT-001",
        "SC-001",
        "SC-002",
        "LOCK-004",
    }
)

# ── Static remediation hints, keyed on finding ID ────────────────────────────
# Plain English, no OWASP codes, no analyzer names.
# Auto-fixable IDs resolve to the fix command; others get a specific action.

_HINTS: dict[str, str] = {
    # Credentials
    "CRED-001": "Run `mcp-audit fix --apply` to redact automatically.",
    "CRED-002": "Run `mcp-audit fix --apply` to redact automatically.",
    "CRED-003": "Run `mcp-audit fix --apply` to redact automatically.",
    # Transport
    "TRANSPORT-001": "Run `mcp-audit fix --apply` to upgrade to HTTPS automatically.",
    "TRANSPORT-002": "Bind this server to 127.0.0.1 (localhost) instead of 0.0.0.0.",
    "TRANSPORT-003": "Host this server over HTTPS to encrypt traffic in transit.",
    "TRANSPORT-004": (
        "Enable TLS certificate validation — do not set rejectUnauthorized: false."
    ),
    # Supply chain / typosquatting
    "SC-001": "Run `mcp-audit fix --apply` to replace with the verified package name.",
    "SC-002": "Run `mcp-audit fix --apply` to replace with the verified package name.",
    "SC-003": "Verify this package name against the official MCP registry before use.",
    "SC-007": (
        "This name copies a known package without its scope. Switch the launch "
        "command to the package named in the finding, or confirm the publisher."
    ),
    "SC-009": (
        "Check the pinned release's date against the fix on the package "
        "registry (npm: `npm view <pkg> time`); if it predates the fix, upgrade."
    ),
    "SC-008": (
        "OSV lists malicious releases of this package; follow the finding: "
        "remove it, or pin a release the record does not list."
    ),
    "VULN-UNRESOLVED": (
        "The vulnerability lookup for this package could not finish; re-run "
        "`scan --check-vulns` later or look it up at https://osv.dev."
    ),
    # Poisoning / prompt injection
    "POISON-001": (
        "Remove or sanitise the suspicious instruction from the tool description."
    ),
    "POISON-002": (
        "Remove hidden text or invisible characters from the tool description."
    ),
    "POISON-003": "Remove data exfiltration instructions from the tool description.",
    "POISON-010": (
        "Remove the prompt that instructs the model to ignore prior context."
    ),
    "POISON-011": (
        "Remove the override directive that attempts to reassign the model's role."
    ),
    "POISON-020": ("Remove the encoded payload from the tool or resource description."),
    "POISON-021": (
        "Remove the obfuscated instruction from the tool or resource description."
    ),
    "POISON-030": "Remove the tool-chaining manipulation instruction.",
    "POISON-040": (
        "Remove the shadow-tool registration instruction from the description."
    ),
    "POISON-050": (
        "Remove the capability escalation directive from the tool description."
    ),
    "POISON-060": (
        "Remove the memory-poisoning instruction from the tool description."
    ),
    "POISON-012": (
        "Remove the privilege-escalation instruction from the tool description."
    ),
    # Rug-pull
    "RUGPULL-000": (
        "A server disappeared since the last scan"
        " — verify it was intentionally removed."
    ),
    "RUGPULL-001": (
        "A server's command changed unexpectedly — verify the update is legitimate."
    ),
    "RUGPULL-002": (
        "A server's description changed since the last scan — review the change."
    ),
    "RUGPULL-003": "Server arguments changed — verify the change is intentional.",
    # Toxic flow / capability combinations
    "TOXIC-001": (
        "Separate file-system and network-egress servers to prevent exfiltration."
    ),
    "TOXIC-002": (
        "Review whether both code-execution and file-system access are needed together."
    ),
    "TOXIC-003": (
        "Consider whether both code-execution and network access are required."
    ),
    "TOXIC-004": "Separate secret-store access from network-egress servers.",
    "TOXIC-005": (
        "Review this server pair"
        " — together they form a dangerous capability combination."
    ),
    "TOXIC-006": "Separate credential access from code-execution servers.",
    "TOXIC-007": (
        "Review this cross-server capability chain for unintended escalation paths."
    ),
    "TOXIC-008": (
        "Don't load a file server and a posting server (GitHub, Slack, Jira) in"
        " one session, or scope the posting token to the repos/channels it needs."
    ),
    "TOXIC-009": (
        "Keep secret-store servers away from servers that post to GitHub, Slack"
        " or Jira."
    ),
    "TOXIC-010": (
        "Don't load a database server and a posting server together, or give"
        " the database a read-only role and scope the posting token."
    ),
    "TOXIC-011": (
        "Remove the shell server or the posting server, or allowlist the shell"
        " commands; output can leave as a comment or a push."
    ),
    "INTEG-001": (
        "Separate file-writing and shell-execution servers to prevent a"
        " plant-then-execute chain."
    ),
    # Config hygiene
    "CFHYG-001": (
        "Restrict the config file permissions (chmod 600) so other users"
        " cannot read it."
    ),
    "CFHYG-002": (
        "Move the config out of this world-writable directory, or restrict"
        " the directory's write permissions."
    ),
    "CFHYG-003": (
        "Replace the inline secret with an environment-variable reference"
        " (e.g. ${MY_API_KEY})."
    ),
    "CFHYG-004": (
        "No action needed — environment-variable references are the right"
        " way to hold credentials."
    ),
    "CFHYG-005": (
        "Review every hook command in this file; Claude Code will execute them"
        " as shell. Restrict who can write the hooks section."
    ),
    "PLUGIN-001": (
        "Run `claude plugin update <plugin>` on Claude Code 2.1.179+; if the"
        " version still differs from the pin, uninstall the plugin."
    ),
    "MOD-001": (
        "Remove the mod unless you have read its tool.check hook; organizations can"
        " set allowManagedModsOnly on the built-in guard."
    ),
    "MOD-002": (
        "Read what the mod reads and where it sends it; remove it if you can't tell."
    ),
    "MOD-003": "Read the mod's prompt and description hooks and diff them on update.",
    "MOD-004": "Check which programs the mod starts and why before keeping it.",
    "MOD-005": "Review installed mods with `claude plugin validate <dir>`.",
    "MANAGED-001": "Run /status in Claude Code to see which managed source applies.",
    "MANAGED-002": (
        "Remove the server, or ask the policy owner to allowlist it by serverUrl or"
        " serverCommand."
    ),
    "MANAGED-003": (
        "Add deniedMcpServers, or allowedMcpServers with allowManagedMcpServersOnly,"
        " to managed settings."
    ),
    "MANAGED-004": (
        "Set allowManagedMcpServersOnly: true in managed settings; drop"
        " allowedMcpServers from committed settings."
    ),
    "MANAGED-005": (
        "Add serverUrl and serverCommand allowlist entries; names alone admit"
        " any server."
    ),
    "MOD-006": (
        "Remove CLAUDE_CODE_PLUGIN_DIRS from settings; load dev plugins with"
        " --plugin-dir only when needed."
    ),
    "PLUGIN-002": (
        "Ask the marketplace owner to pin the plugin entry with a full commit sha."
    ),
    "HARNESS-001": (
        "Remove permissions.defaultMode: bypassPermissions (Claude Code 2.1.257+"
        " ignores it in project settings; older versions don't); keep bypass for"
        " one session in an isolated container."
    ),
    "HARNESS-002": (
        "Remove enableAllProjectMcpServers; approve trusted servers by name with"
        " enabledMcpjsonServers."
    ),
    "HARNESS-003": (
        "Remove skipDangerousModePermissionPrompt so bypass mode stays a confirmed"
        " step."
    ),
    "HARNESS-004": ("Replace the blanket Bash allow rule with specific command rules."),
    "HARNESS-005": (
        "Narrow the allow rule to the subcommands you need, e.g. Bash(gh pr view:*)."
    ),
    "HARNESS-006": (
        "Add deny rules for rm -rf / rm -r or a PreToolUse hook that blocks deletes."
    ),
    "PERM-001": (
        "Rewrite the rule in a form Claude Code applies, e.g. Bash(rm *) instead of"
        " Bash(command:rm *); see docs/permission-rules.md."
    ),
    "PERM-002": "Use two slashes for an absolute path, e.g. Read(//Users/you/...).",
    "PERM-003": "Put a space before the *, e.g. Bash(ls *) instead of Bash(ls*).",
    "PERM-004": (
        "Turn on the sandbox (sandbox.enabled: true) or add a PreToolUse hook;"
        " the deny rule alone misses /usr/bin/curl and sh -c forms."
    ),
    "PERM-005": (
        "Replace WebFetch(domain:*) with a bare WebFetch rule or named hosts so"
        " the sandbox allowlist stays in force."
    ),
    "PERM-006": (
        "Set sandbox.autoAllowBashIfSandboxed to false, or use content-scoped ask"
        " rules such as Bash(git push *)."
    ),
    "PERM-007": (
        "Remove the mcp__<server> allow rule until the server's findings are fixed,"
        " or allow only tools you have checked."
    ),
    "SANDBOX-001": (
        "Remove the sandbox-weakening keys from the repository's .claude settings;"
        " a machine that needs one sets it in ~/.claude/settings.json."
    ),
    "SANDBOX-002": (
        "Drop the excludedCommands or allowUnixSockets entry from the repository's"
        " settings; keep the tool sandboxed and grant one path or host instead."
    ),
    "SANDBOX-003": (
        "Remove the code-host, paste or webhook domain from the repository's"
        " sandbox.network.allowedDomains; allow only the hosts tools need."
    ),
    "SANDBOX-004": (
        "Move the key to managed or user settings, or delete it: Claude Code"
        " ignores it in this file; see docs/permission-rules.md."
    ),
    "SANDBOX-005": (
        "Add .claude/settings.local.json to .gitignore (git rm --cached it if"
        " committed) and use ~/ instead of home paths with a username."
    ),
    "AGENT-001": (
        "Remove permissionMode from the subagent file so it inherits your session's"
        " mode; keep Claude Code at 2.1.267+."
    ),
    "AGENT-002": (
        "Put the specifier rule in permissions.deny instead; disallowedTools"
        " removes the whole tool."
    ),
    "AGENT-003": (
        "Read the subagent's hook commands before trusting the folder; remove"
        " any you did not add."
    ),
    "AGENT-004": (
        "Review the subagent's inline MCP server like a .mcp.json entry; write"
        " rules for it as mcp__<full-name>__*."
    ),
    "CFHYG-008": (
        "Confirm the named Azure Foundry resource belongs to your organisation;"
        " set the Foundry variables in user or managed settings instead."
    ),
    "CFHYG-006": (
        "Unset ANTHROPIC_BASE_URL or point it at https://api.anthropic.com"
        " — a third-party base URL receives every API call and its secrets."
    ),
    # Git can run code (STORY-0089)
    "TRUST-006": (
        "Delete the git config line in a text editor before running git or an"
        " agent here; run one-off git with -c (e.g. -c core.fsmonitor=false)."
    ),
    "TRUST-007": (
        "Remove the embedded bare repo or the post-index-change hook before"
        " opening this folder in an agent; set safe.bareRepository=explicit."
    ),
    # CI workflows (STORY-0091)
    "WORKFLOW-001": (
        "Allow only the commands this CI agent needs, make its job read-only,"
        " and do writes in a separate job."
    ),
    "WORKFLOW-002": (
        "Replace the CI agent's deny list with an allowlist of the commands it needs."
    ),
    "WORKFLOW-003": (
        "Use run-gemini-cli 0.1.22+ with Gemini CLI 0.39.1+, and don't trust a"
        " workspace that holds pull request code."
    ),
    # Skill packages (STORY-0095)
    "SKILL-005": (
        "Read the install command this skill tells the agent to run; remove the"
        " skill if you cannot vouch for what it downloads or decodes."
    ),
    "SKILL-006": (
        "Review what this skill adds to Claude Code (servers, hooks, programs,"
        " settings) and remove anything you did not ask for."
    ),
    "SKILL-007": (
        "Find out what this file in the skill is; a skill should ship only"
        " content you can read."
    ),
    "SKILL-008": (
        "Resolve the other findings on this skill, then read the code it"
        " bundles before using it."
    ),
    # Baseline drift
    "DRIFT": (
        "Review this change. If intentional,"
        " run `mcp-audit baseline save` to update your baseline."
    ),
    # Attestation
    "ATTEST": (
        "The package hash does not match the registry"
        " — do not use this server until verified."
    ),
    # Lock (mcp-lock.json drift — STORY-0070)
    "LOCK-001": (
        "This server's config no longer matches the lock."
        " Review the change, then run `mcp-audit lock --accept`."
    ),
    "LOCK-002": (
        "This server is not in the lock."
        " Run `mcp-audit lock` to approve it (or `lock --accept` after review)."
    ),
    "LOCK-003": (
        "This server is in the lock but no longer in your config."
        " If the removal was intended, run `mcp-audit lock --accept`."
    ),
    "LOCK-004": "Run `mcp-audit fix --apply` to re-pin to the locked version.",
    "LOCK-005": (
        "The lock file itself looks tampered or corrupted."
        " Inspect `git diff mcp-lock.json` before trusting it."
    ),
    # Tool definitions (`lock --verify --connect` — STORY-0086)
    "LOCK-006": (
        "This server now offers tools the lock never approved."
        " Review them, then run `mcp-audit lock --accept --connect`."
    ),
    "LOCK-007": (
        "A tool's schema or annotations changed since the lock."
        " Review the change, then run `mcp-audit lock --accept --connect`."
    ),
    "LOCK-008": (
        "A tool's description changed since the lock; read the new text"
        " (`mcp-audit scan --connect` checks it), then re-lock with --connect."
    ),
    "LOCK-009": (
        "A locked tool is gone. If expected, run `mcp-audit lock --accept --connect`."
    ),
    # lock_version 2 (STORY-0116)
    "LOCK-010": (
        "The registry's `latest` or deprecation notice changed since the lock;"
        " informational. Re-lock with `mcp-audit lock --accept` to record it."
    ),
    "LOCK-011": (
        "A section of mcp-lock.json changed without its digest. Inspect"
        " `git diff mcp-lock.json`; re-run whichever tool wrote that section."
    ),
    "LOCK-012": (
        "Something reformatted mcp-lock.json. Run `mcp-audit lock --accept` to"
        " rewrite it canonically."
    ),
    # Instruction-file reach (STORY-0098)
    "MEM-003": (
        "Move the imported instructions into the repository (or delete the"
        " @import); decline Claude Code's external-imports prompt if unsure."
    ),
    "MEM-004": (
        "Open HEARTBEAT.md: remove any step you didn't write and the line that"
        " silences its result; reply HEARTBEAT_OK only if nothing needs attention."
    ),
}


#: Clients whose configs ``fix`` never edits.
_NOT_FIXED_CLIENTS = frozenset({"claude-code-skill"})


def _is_auto_fixable(finding: Finding) -> bool:
    """True when ``mcp-audit fix`` can remediate *finding* in place.

    ``fix`` edits MCP JSON config files only, so an auto-fixable ID found in
    another file (a CRED-001 in ``.gemini/.env``, STORY-0090) is not, nor one
    in an MCP config a skill carries but Claude Code does not load
    (client ``claude-code-skill``, STORY-0095), which ``fix`` never selects.
    """
    if finding.id not in _AUTO_FIXABLE or finding.client in _NOT_FIXED_CLIENTS:
        return False
    path = finding.finding_path or ""
    return not path or path.lower().endswith(".json")


def _remediation_hint(finding: Finding) -> str:
    """Return a one-line plain-English remediation hint for *finding*.

    Checks the static :data:`_HINTS` table first, falling back to the
    first sentence of ``finding.remediation`` when the ID is unknown.  An
    auto-fixable ID in a file ``fix`` cannot edit gets a manual hint instead.

    Args:
        finding: A :class:`~mcp_audit.models.Finding` from the scan pipeline.

    Returns:
        A single-line plain-English instruction suitable for non-expert users.
    """
    if finding.id in _AUTO_FIXABLE and not _is_auto_fixable(finding):
        if finding.id.startswith("CRED-"):
            return (
                "Move the secret out of this file into your shell or a credential"
                " manager, then rotate it (`mcp-audit fix` edits MCP JSON configs"
                " only)."
            )
        sentences = finding.remediation.split(". ")
        return sentences[0].rstrip(".") + "."

    # Exact match
    if finding.id in _HINTS:
        return _HINTS[finding.id]

    # Prefix match (e.g. "DRIFT-001" → "DRIFT", "ATTEST-…" → "ATTEST")
    prefix = finding.id.split("-")[0]
    if prefix in _HINTS:
        return _HINTS[prefix]

    # Fallback: first sentence of the stored remediation text
    sentences = finding.remediation.split(". ")
    return sentences[0].rstrip(".") + "."


def _grade_color(grade: str) -> str:
    """Return the Rich colour tag for a letter grade."""
    if grade in ("A", "B"):
        return "bold green"
    if grade in ("C", "D"):
        return "bold yellow"
    return "bold red"


MAX_FINDINGS_SHOWN = 5

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def print_check_results(
    result: ScanResult,
    console: Console | None = None,
    registration: RegistrationConfig | None = None,
) -> None:
    """Print the one-page security verdict to the terminal.

    Renders a clean, 80-column-max summary with:
    - Letter grade and numeric score
    - Optional registration line (when *registration* is provided)
    - Up to :data:`MAX_FINDINGS_SHOWN` findings (highest severity first)
    - Per-finding remediation hints
    - Footer with ``mcp-audit fix`` and ``mcp-audit scan`` guidance

    Args:
        result: Completed scan result from :func:`~mcp_audit.scanner.run_scan`.
        console: Rich console to write to.  A new one is created if omitted.
        registration: Current registration config, if the user is registered.
            When provided, a ``Registered as: <org>`` line appears beneath the
            grade panel.
    """
    if console is None:
        console = Console(width=80)

    grade = result.score.grade if result.score else "?"
    score_num = result.score.numeric_score if result.score else 0
    grade_style = _grade_color(grade)

    console.print()
    console.print(Rule("[bold]mcp-audit — Security Check[/bold]"))

    if not result.findings:
        console.print()
        console.print(
            f"  Grade: [{grade_style}]{grade}[/{grade_style}]  ✓ No issues found"
        )
        if registration:
            _print_registered_as(console, registration)
        _print_lock_line(console, result)
        console.print()
        console.print("  Your MCP configuration looks clean.")
        console.print()
        console.print(Rule())
        return

    # ── Grade line ────────────────────────────────────────────────────────────
    console.print()
    console.print(
        f"  Grade: [{grade_style}]{grade}[/{grade_style}]  "
        f"(Score: [bold]{score_num}[/bold]/100)"
    )
    if registration:
        _print_registered_as(console, registration)
    _print_lock_line(console, result)
    console.print()

    # ── Attack path warning ───────────────────────────────────────────────────
    has_attack_paths = bool(
        result.attack_path_summary and result.attack_path_summary.paths
    )
    if grade == "F" and has_attack_paths:
        console.print(
            "  [bold red]⛔ Active attack path detected.[/bold red]"
            "  Run [bold]mcp-audit scan[/bold] for full details."
        )
        console.print()

    # ── Findings list ─────────────────────────────────────────────────────────
    sorted_findings = sorted(
        result.findings,
        key=lambda f: _SEVERITY_ORDER.index(f.severity),
    )

    total = len(sorted_findings)
    shown = sorted_findings[:MAX_FINDINGS_SHOWN]
    remainder = total - len(shown)

    fixable_ids = sorted({f.id for f in shown if _is_auto_fixable(f)})
    fixable_shown = len(fixable_ids)

    issue_word = "issue" if total == 1 else "issues"
    need_word = "needs" if total == 1 else "need"
    console.print(f"  [bold]⚠  {total} {issue_word} {need_word} your attention:[/bold]")
    console.print()

    for i, finding in enumerate(shown, start=1):
        color = _SEVERITY_COLORS[finding.severity]
        sev_badge = f"[{color}]{finding.severity.value}[/{color}]"
        hint = _remediation_hint(finding)
        console.print(f"  {i}. [{sev_badge}] {finding.title}")
        console.print(f"     → {hint}")
        console.print()

    if remainder > 0:
        console.print(
            f"  [dim]… and {remainder} more — run [bold]mcp-audit scan[/bold]"
            " to see all.[/dim]"
        )
        console.print()

    # ── Fix summary line ──────────────────────────────────────────────────────
    if fixable_shown > 0:
        ids_str = ", ".join(fixable_ids)
        n_word = "finding" if fixable_shown == 1 else "findings"
        console.print(
            f"  → Run [bold]mcp-audit fix --apply[/bold] to auto-remediate "
            f"[{ids_str}] ({fixable_shown} {n_word})"
        )
        console.print()

    # ── Footer ────────────────────────────────────────────────────────────────
    console.print(Rule())
    console.print("[dim]To see all findings:  mcp-audit scan[/dim]")
    if fixable_shown > 0:
        console.print("[dim]To apply auto-fixes:  mcp-audit fix --apply[/dim]")


def _print_lock_line(console: Console, result: ScanResult) -> None:
    """Print the ``Lock:`` line beneath the grade, when a lock was found.

    Silent (prints nothing) when ``result.lock_status.present`` is ``False``
    — a project with no ``mcp-lock.json`` must see no output change at all
    (STORY-0070). Emits one WARN line per unresolved entry so a clean
    ``verified`` line can never silently hide one.
    """
    status = result.lock_status
    if not status.present:
        return
    n = status.checked_servers
    server_word = "server" if n == 1 else "servers"
    not_verified = (
        f"; not verified: {', '.join(status.unverified_sections)}"
        if status.unverified_sections
        else ""
    )
    if status.tools_recorded:
        # Recorded tool definitions are only compared by an explicit
        # `lock --verify --connect`, never by check/scan (STORY-0086).
        not_verified += "; tool definitions not compared (lock --verify --connect)"
    if status.verified:
        console.print(f"  [dim]Lock: verified ({n} {server_word}){not_verified}[/dim]")
    else:
        console.print(
            f"  [yellow]Lock:[/yellow] {status.findings} finding(s) across "
            f"{n} locked {server_word}{not_verified} — see `mcp-audit lock --verify`."
        )
    for key in status.unresolved_entries:
        console.print(
            f"  [yellow]WARN:[/yellow] {key!r} was locked offline — "
            "version/hash not confirmed."
        )
    if status.outside_root:
        console.print(
            "  [yellow]WARN:[/yellow] config(s) outside the lock root "
            "were skipped (no LOCK findings)."
        )
    if status.not_covered:
        console.print(
            f"  [yellow]WARN:[/yellow] {len(status.not_covered)} MCP server(s)"
            " from subagent definitions or skill folders not covered by"
            " mcp-lock.json (AGENT-004, SKILL-006)."
        )


def _print_registered_as(console: Console, registration: RegistrationConfig) -> None:
    """Print a single dim registration line beneath the grade.

    Prefers org name, falls back to display name, then truncated email.
    """
    label = registration.org or registration.name
    if not label:
        at = registration.email.find("@")
        if at > 2:
            label = registration.email[:2] + "***" + registration.email[at:]
        else:
            label = registration.email
    console.print(f"  [dim]Registered as: {label}[/dim]")
