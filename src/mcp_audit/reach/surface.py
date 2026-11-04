"""The closed surface ``reach`` reasons about: allowlists, not denylists.

A fact makes READY possible only when it is on an explicit allowlist here.
Anything else is unknown, and unknown is COULDN'T CHECK, never PASS.  Four
allowlists: the settings keys known to be inert, the environment variable names
known to be benign, the one launch shape a declared server may have, and the
one program shape a command may have to count as known local.

Nothing here reads the network or runs a process.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.analyzers.supply_chain import (
    _NPX_LIKE,
    _is_python_interpreter,
    normalize_launch,
)
from mcp_audit.reach.context import Env, read_capped

SETTINGS_DOC = "https://code.claude.com/docs/en/settings-reference"

# ── Settings keys ─────────────────────────────────────────────────────────────

#: Keys ``reach`` reads and models itself.
HANDLED_KEYS = frozenset(
    {
        "permissions",
        "sandbox",
        "env",
        "hooks",
        "enabledPlugins",
        "disableClaudeAiConnectors",
        "allowAllClaudeAiMcps",
        "allowedMcpServers",
        "deniedMcpServers",
        "managedMcpServers",
        "allowManagedMcpServersOnly",
        "managedSourcesBehavior",
        "strictPluginOnlyCustomization",
        "disableAllHooks",
        "allowManagedHooksOnly",
    }
)

#: Keys whose value is a command Claude Code runs (settings reference, "Keys
#: that run commands or scripts").  Each is classified like a hook command.
COMMAND_KEYS = frozenset(
    {
        "apiKeyHelper",
        "awsAuthRefresh",
        "awsCredentialExport",
        "gcpAuthRefresh",
        "otelHeadersHelper",
        "fileSuggestion",
        "statusLine",
        "subagentStatusLine",
        "processWrapper",
        "policyHelper",
        "sshHostCommands",
    }
)

#: Sub-keys of ``sandbox`` that name an executable Claude Code runs.
SANDBOX_EXECUTABLE_KEYS = ("ripgrep", "bwrapPath", "socatPath")

#: Keys known to be inert for ``reach``: they set a model, a look, a limit or a
#: switch and neither run code nor change what runs.  A key not here, not
#: handled and not a command key is unknown.
INERT_KEYS = frozenset(
    {
        "advisorModel", "agent", "agentPushNotifEnabled", "alwaysThinkingEnabled",
        "askUserQuestionTimeout", "attribution", "autoCompactEnabled",
        "autoCompactWindow", "autoConnectIde", "autoContinueAtUsageLimit",
        "autoInstallIdeExtension", "autoMemoryDirectory", "autoMemoryEnabled",
        "autoScrollEnabled", "autoUpdatesChannel", "availableModels",
        "availableModelsMatch", "awaySummaryEnabled", "axScreenReader",
        "bashEditDiffEnabled", "bashOutputMaxChars", "channelsEnabled",
        "claudeInChromeDefaultEnabled", "claudeMd", "claudeMdExcludes",
        "cleanupPeriodDays", "companyAnnouncements", "copyFullResponse",
        "copyOnSelect", "defaultToAgentsView", "deniedModels",
        "desktopSessionCleanupPeriodDays", "dialogExpiry", "disableAgentView",
        "disableAutoMode", "disableBundledSkills", "disableDeepLinkRegistration",
        "disableMobileSimulatorTools", "disableSkillShellExecution",
        "disableWorkflows", "editorMode", "effortLevel", "emojiCompletionEnabled",
        "enforceAvailableModels", "externalEditorContext", "fallbackModel",
        "fastMode", "fastModePerSessionOptIn", "feedbackDrafts",
        "feedbackSurveyRate", "fileCheckpointingEnabled", "footerLinksRegexes",
        "httpHookAllowedEnvVars", "allowedHttpHookUrls", "idleCompaction",
        "includeCoAuthoredBy", "includeGitInstructions",
        "inputNeededNotifEnabled", "keybindingFlavor", "language",
        "leftArrowOpensAgents", "maxEffortLevel", "maxProseWidth", "minimumVersion",
        "model", "modelOverrides", "modelPicker", "modelPricing", "modelSettings",
        "outputStyle", "permissionExplainerEnabled", "plansDirectory",
        "preferredNotifChannel", "prefersReducedMotion", "promptCacheTtl",
        "promptSuggestionEnabled", "prStatusFooterEnabled", "prUrlTemplate",
        "requiredMaximumVersion", "requiredMinimumVersion", "respectGitignore",
        "respondToBashCommands", "showClearContextOnPlanAccept",
        "showThinkingSummaries", "showTurnDuration", "skillListingBudgetFraction",
        "skillListingMaxDescChars", "skillOverrides",
        "skipAutoPermissionPrompt", "skipDangerousModePermissionPrompt",
        "skipWebFetchPreflight", "spellcheck", "spinnerTipsEnabled",
        "spinnerTipsOverride", "spinnerVerbs", "subagentPromptCacheTtl",
        "switchModelsOnFlag", "syntaxHighlightingDisabled", "taskOutputMaxChars",
        "teammateDefaultModel", "teammateMode", "terminalProgressBarEnabled",
        "terminalTitleFromRename", "theme", "timeFormat", "timeZone", "tui",
        "useAutoModeDuringPlan", "verbose", "viewMode", "vimInsertModeRemaps",
        "voice", "voiceEnabled", "wheelScrollAccelerationEnabled",
        "workflowKeywordTriggerEnabled", "workflowSizeGuideline",
        "wslInheritsWindowsSettings", "$schema",
    }
)  # fmt: skip


def unknown_settings_keys(data: dict) -> list[str]:
    """Top-level keys of one settings file that ``reach`` does not understand."""
    known = HANDLED_KEYS | COMMAND_KEYS | INERT_KEYS
    return sorted(str(k) for k in data if k not in known)[:10]


# ── Environment variable names ────────────────────────────────────────────────

#: Names that load code or change what a program runs, in any ``env``.
_CODE_LOADING_RE = re.compile(
    r"^(?:LD_|DYLD_|NODE_OPTIONS$|NODE_PATH$|NODE_EXTRA_CA_CERTS$|PYTHON|PERL5?"
    r"|RUBY|GEM_|JAVA_TOOL_OPTIONS$|_JAVA_OPTIONS$|JDK_JAVA_OPTIONS$|CLASSPATH$"
    r"|BASH_ENV$|ENV$|PATH$|PATHEXT$|IFS$|SHELL$|GIT_|npm_config_|NPM_CONFIG_"
    r"|UV_|PIP_|BUN_|DENO_|CARGO_|GOFLAGS$|GOPATH$|HOME$|USERPROFILE$|XDG_)",
    re.IGNORECASE,
)

#: Names known to be benign in a settings ``env`` block: Claude Code's own
#: switches and limits, telemetry, proxies, locale.  Anything else is unknown.
_BENIGN_ENV_RE = re.compile(
    r"^(?:OTEL_[A-Z0-9_]+|ANTHROPIC_[A-Z0-9_]+|DISABLE_[A-Z0-9_]+"
    r"|ENABLE_[A-Z0-9_]+|CLAUDE_CODE_(?:ENABLE|DISABLE|USE|MAX|SKIP)_[A-Z0-9_]+"
    r"|MAX_THINKING_TOKENS|MAX_MCP_OUTPUT_TOKENS|MCP_TIMEOUT|MCP_TOOL_TIMEOUT"
    r"|BASH_DEFAULT_TIMEOUT_MS|BASH_MAX_TIMEOUT_MS|BASH_MAX_OUTPUT_LENGTH"
    r"|(?:HTTPS?|NO|ALL)_PROXY|TZ|LANG|LANGUAGE|LC_[A-Z]+|NO_COLOR|FORCE_COLOR)$",
    re.IGNORECASE,
)


def code_loading_name(name: str) -> bool:
    """True for a variable name that loads code or changes what runs."""
    return bool(_CODE_LOADING_RE.match(name))


def benign_env_name(name: str) -> bool:
    """True for a name on the benign allowlist (and not code-loading)."""
    return not code_loading_name(name) and bool(_BENIGN_ENV_RE.match(name))


#: Credential-shaped variable names (a service token a server needs, or a
#: secret in settings ``env``, which is a credentials finding of its own).
SECRET_NAME_RE = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY"
    r"|CREDENTIALS?|PAT)(?:$|_)",
    re.IGNORECASE,
)


def settings_env_unsafe(env_block: object) -> list[str]:
    """Names in a settings ``env`` block that are not provably benign.

    A secret-shaped name is reported separately as a credential finding, but
    it is still unknown here unless it is on the benign list.
    """
    if not isinstance(env_block, dict):
        return []
    return sorted(str(n) for n in env_block if not benign_env_name(str(n)))[:10]


def server_env_declared(env_block: object) -> bool:
    """May a server with this ``env`` still be declared by the registry?

    Allowed: benign names, and credential-shaped names that load no code (a
    service token the server needs).  Any other name makes it undeclared.
    """
    if not env_block:
        return True
    if not isinstance(env_block, dict):
        return False
    for name in env_block:
        text = str(name)
        if code_loading_name(text):
            return False
        if not (benign_env_name(text) or SECRET_NAME_RE.search(text)):
            return False
    return True


# ── Launch shape ──────────────────────────────────────────────────────────────


def launch_tail(command: str | None, args: list[str]) -> list[str] | None:
    """The arguments after the package when the launch has the one allowed shape.

    ``<runner> [-y|--yes] <package> <args...>`` for npx, bunx and pnpx;
    ``uvx <package> <args...>``; ``pipx run <package> <args...>``;
    ``python -m <module> <args...>``.  Any other flag before the package
    (``--registry``, ``-p``, ``--from``, ``--with``, ``--userconfig``...)
    returns ``None``: the server is not provably the registry's package.
    """
    launcher, rest = normalize_launch(command, list(args))
    if launcher == "yarn":
        if not rest or rest[0] != "dlx":
            return None
        launcher, rest = "npx", rest[1:]
    if launcher in _NPX_LIKE:
        i = 0
        while i < len(rest) and rest[i] in ("-y", "--yes"):
            i += 1
        if i >= len(rest) or rest[i].startswith("-"):
            return None
        return rest[i + 1 :]
    if launcher == "uvx":
        if not rest or rest[0].startswith("-"):
            return None
        return rest[1:]
    if launcher == "pipx":
        if len(rest) < 2 or rest[0] != "run" or rest[1].startswith("-"):
            return None
        return rest[2:]
    if _is_python_interpreter(launcher):
        if len(rest) < 2 or rest[0] != "-m" or rest[1].startswith("-"):
            return None
        return rest[2:]
    return None


def path_candidates(tail: list[str]) -> list[str]:
    """Every argument after the package that could be a path.

    Each non-flag argument, and the value of every ``--flag=value``.
    """
    out: list[str] = []
    for arg in tail:
        if not isinstance(arg, str):
            continue
        if arg.startswith("-"):
            if "=" in arg:
                value = arg.split("=", 1)[1]
                if value:
                    out.append(value)
            continue
        out.append(arg)
    return out


# ── Commands ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Cmd:
    """One thing Claude Code runs outside the sandbox.

    ``kind``: ``command`` (a shell command), ``http`` (an HTTP hook) or
    ``other`` (anything reach cannot classify: it counts as not known local).
    """

    what: str
    text: str
    ref: str
    kind: str = "command"


def hook_items(hooks: object, what: str, ref: str) -> list[Cmd]:
    """Every handler in a ``hooks`` table, by type.

    ``command`` handlers keep their text; ``http`` handlers are network
    routes; any other type, and any handler that is not an object, is ``other``.
    """
    out: list[Cmd] = []
    if not isinstance(hooks, dict):
        return [Cmd(what, "?", ref, "other")] if hooks else out
    for _event, groups in hooks.items():
        if not isinstance(groups, list):
            out.append(Cmd(what, "?", ref, "other"))
            continue
        for group in groups:
            handlers = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(handlers, list):
                out.append(Cmd(what, "?", ref, "other"))
                continue
            for handler in handlers:
                kind = handler.get("type") if isinstance(handler, dict) else None
                if kind == "command":
                    text = handler.get("command")
                    if isinstance(text, str) and text.strip():
                        out.append(Cmd(what, text, ref))
                    else:
                        out.append(Cmd(what, "?", ref, "other"))
                elif kind == "http":
                    out.append(Cmd(what, str(handler.get("url", "")), ref, "http"))
                else:
                    out.append(Cmd(what, "?", ref, "other"))
    return out


def command_texts(value: object) -> list[str]:
    """The command strings in a command-key value (a string or an object)."""
    if isinstance(value, str):
        return [value] if value.strip() else []
    texts: list[str] = []
    if isinstance(value, dict):
        for key in ("command", "path", "script", "executable"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                texts.append(item)
        if not texts and value:
            texts.append("?")
    elif isinstance(value, list):
        for item in value:
            texts += command_texts(item)
    elif value not in (None, False, ""):
        texts.append("?")
    return texts


# ── Frontmatter files ─────────────────────────────────────────────────────────

MAX_FRONTMATTER_FILES = 300


def ancestor_dirs(env: Env) -> list[Path]:
    """The working directory and its parents up to the repository root.

    The repository root is the nearest directory holding ``.git``; with none,
    the walk ends at the home directory (or the filesystem root outside home).
    """
    out: list[Path] = []
    current = env.cwd
    for _ in range(64):
        out.append(current)
        try:
            if (current / ".git").exists():
                break
        except OSError:
            break
        if current == env.home or current.parent == current:
            break
        current = current.parent
    return out


def _files(base: Path, pattern: str) -> tuple[list[Path], bool]:
    """Up to the cap of files under *base*; ``True`` when the cap was hit."""
    found: list[Path] = []
    try:
        for path in base.glob(pattern):
            if len(found) >= MAX_FRONTMATTER_FILES:
                return found, True
            found.append(path)
    except OSError:
        return found, False
    return found, False


def frontmatter_items(root: Path, label: str | None, env: Env) -> list[Cmd]:
    """Hook handlers in the skills, agents and commands under ``root/{...}``.

    A scan that hits the file cap, or a frontmatter block that names ``hooks``
    but cannot be read, adds an ``other`` item: the answer is unknown.
    """
    from mcp_audit.agent_files.subagents import (  # noqa: PLC0415
        parse_agent_frontmatter,
    )

    out: list[Cmd] = []
    for kind, folder, pattern in (
        ("skill", "skills", "**/SKILL.md"),
        ("agent", "agents", "**/*.md"),
        ("command", "commands", "**/*.md"),
    ):
        paths, capped = _files(root / folder, pattern)
        what = label or f"{kind} hook"
        if capped:
            out.append(
                Cmd(what, "?", f"{env.mask(root / folder)} (too many files)", "other")
            )
        for path in paths:
            ref = f"{env.mask(path)}:hooks"
            raw, why = read_capped(path)
            if raw is None:
                if why:
                    out.append(Cmd(what, "?", ref, "other"))
                continue
            text = raw.decode("utf-8", errors="replace")
            try:
                parsed = parse_agent_frontmatter(text)
            except Exception:  # noqa: BLE001 — unreadable frontmatter is unknown
                out.append(Cmd(what, "?", ref, "other"))
                continue
            if parsed.unreadable_reason and "hooks" in text:
                out.append(Cmd(what, "?", ref, "other"))
            for reading in parsed.readings:
                if "hooks" in reading:
                    out += hook_items(reading["hooks"], what, ref)
    return out


def plugin_hook_tables(install: Path) -> list[object]:
    """The hook tables a plugin ships: ``hooks/hooks.json`` and ``plugin.json``."""
    docs: list[object] = []
    manifest: dict = {}
    raw, _why = read_capped(install / ".claude-plugin" / "plugin.json")
    if raw is not None:
        try:
            loaded = json.loads(raw.decode("utf-8-sig", errors="replace"))
            manifest = loaded if isinstance(loaded, dict) else {}
        except (ValueError, RecursionError):
            manifest = {}
    paths: list[Path] = [install / "hooks" / "hooks.json"]
    declared = manifest.get("hooks")
    items = declared if isinstance(declared, list) else [declared]
    for item in items:
        if isinstance(item, dict):
            docs.append(item)
        elif isinstance(item, str) and item.strip():
            target = Path(_normpath(install / item))
            if install in target.parents:
                paths.append(target)
    for path in paths:
        raw, _why = read_capped(path)
        if raw is None:
            continue
        try:
            doc = json.loads(raw.decode("utf-8-sig", errors="replace"))
        except (ValueError, RecursionError):
            docs.append("?")  # a hooks file that cannot be read is unknown
            continue
        table = doc.get("hooks") if isinstance(doc, dict) else None
        docs.append(table if isinstance(table, dict) else doc)
    return docs


def _normpath(path: Path) -> str:
    import os  # noqa: PLC0415

    return os.path.normpath(path)


def all_frontmatter_items(env: Env) -> list[Cmd]:
    """Hooks in every skill, agent and command Claude Code would load.

    The user's config directory, ``.claude`` in the working directory and each
    ancestor up to the repository root (or home), and the managed directory's
    ``.claude``.
    """
    roots: list[Path] = [env.config_dir]
    roots += [d / ".claude" for d in ancestor_dirs(env)]
    if env.managed_dir is not None:
        roots.append(env.managed_dir / ".claude")
    out: list[Cmd] = []
    seen: set[Path] = set()
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        out += frontmatter_items(root, None, env)
    return out
