"""Claude Code mods: discovery, static read, and MOD-001..006 (STORY-0085).

A mod is a Claude Code plugin whose ``hooks/hooks.json`` has a ``modules`` key
naming a JavaScript or TypeScript hooks module (docs: plugins/mods/reference,
"Files").  Mods shipped in Claude Code 2.1.287 (2026-10-01).  They run inside
Claude Code with the user's permissions and aren't sandboxed: a mod can read
files and environment variables, start processes, make network requests,
rewrite prompts and tool descriptions, and approve a tool call before the
permission prompt appears (docs: plugins/mods/admin).

**Why a static read is sound.**  Claude Code refuses to load a hooks module
unless every event name passed to ``on()`` is a string literal and every mods
API call is written in full (``$.fs.read``, never ``const fs = $.fs``), so the
same static read Claude Code's own ``claude plugin validate`` does sees every
event and call (docs: plugins/mods/create, "Check what Claude Code reads from
your mod").  This module reads the source and never executes it.

**Where mods come from**, all offline:

* installed plugins (``installed_plugins.json`` install paths);
* mods Claude writes during a session, under ``~/.claude/dev-mods/<session>/<mod>/``;
* directories named in ``CLAUDE_CODE_PLUGIN_DIRS``, from the environment or
  the ``env`` block of ``~/.claude/settings.json`` (loaded in every session).

**The built-in guard.**  ``sec-default@builtin`` stops user mods overriding
deny rules and managed hooks, but loads only on a machine with managed
settings or for a Team/Enterprise sign-in.  mcp-audit can see a managed
settings *file*; it can't see MDM, registry or server-delivered policy, or how
the user signs in, so "no managed settings file found" is reported as
"guard not detected", never as "guard off".

The review checklist the findings follow is Anthropic's own, from
"Review what a mod can do" in the mods admin docs.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_audit.models import Finding, Severity
from mcp_audit.plugins.models import InstalledPlugin

_DOCS_ADMIN = "https://code.claude.com/docs/en/plugins/mods/admin"
_MODULE_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_FILES_PER_MOD = 64

# Anthropic's review checklist, mapped to the findings below.
_APPROVES_CALLS = frozenset({"tool.check"})
_REWRITES_WHAT_CLAUDE_READS = frozenset(
    {
        "tool.describe",
        "prompt.compose",
        "prompt.section",
        "prompt.context",
        "prompt.attachment",
        "skill.prompt",
        "session.append",
    }
)
_SECRET_READS = frozenset({"env.get", "settings.read"})
_FILE_READS = frozenset({"fs.read"})
# Network sink only.  A started program could also send data, but that is
# MOD-004's finding; counting process.run here flagged Anthropic's own /diff
# mod (env.get + process.run for git) as a HIGH exfiltration risk.
_SENDS_OUT = frozenset({"http.fetch"})
_RUNS_PROGRAMS = frozenset({"process.run", "process.spawn", "env.set"})
_SUBMITS_AS_USER = frozenset({"prompt.submit"})


# ── Model ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Mod:
    """One mod found on disk, with what its hooks module reads as.

    Attributes:
        name: Plugin id (``name@marketplace``) for an installed plugin, else
            the directory name.
        origin: ``installed``, ``dev`` (written by Claude in a session) or
            ``plugin-dir`` (``CLAUDE_CODE_PLUGIN_DIRS``).
        root: The plugin directory.
        module_path: The hooks module named by ``hooks/hooks.json``.
        events: Event names passed to ``on()``, sorted.
        calls: Mods API calls as ``namespace.method``, sorted.
        files: Source files read (the module plus its relative imports).
    """

    name: str
    origin: str
    root: Path
    module_path: Path
    events: tuple[str, ...] = ()
    calls: tuple[str, ...] = ()
    files: tuple[Path, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class GuardState:
    """What mcp-audit can see of the built-in mod guard on this machine.

    Attributes:
        managed_settings_path: The managed settings file found, if any.
        allow_override_deny_rules: ``allowModsToOverrideDenyRules`` is true.
        allow_managed_mods_only: ``allowManagedModsOnly`` is true, so user
            mods don't load.
    """

    managed_settings_path: Path | None = None
    allow_override_deny_rules: bool = False
    allow_managed_mods_only: bool = False

    @property
    def guard_detected(self) -> bool:
        """True when a managed settings file exists, so the guard loads."""
        return self.managed_settings_path is not None


# ── Static read ────────────────────────────────────────────────────────────────

_ON_CALL = re.compile(r"(?<![\w.$])on\(\s*S(\d+)\b")
_API_CALL = re.compile(r"(?<![\w$])\$\.([A-Za-z_]\w*)\.([A-Za-z_]\w*)\b")
_IMPORT = re.compile(r"\bimport\b[^;]*?\bfrom\s+S(\d+)|\bimport\s+S(\d+)")


def _strip(source: str) -> tuple[str, list[str]]:
    """Remove comments and replace string literals with ``S<n>`` tokens.

    Returns the rewritten code and the literal values by index.  Template
    literals are treated as strings whole; a ``${...}`` inside one is not
    scanned (Claude Code's own validator rejects most dynamic shapes anyway).
    """
    out: list[str] = []
    literals: list[str] = []
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            end = source.find("\n", i)
            i = n if end == -1 else end
            continue
        if ch == "/" and nxt == "*":
            end = source.find("*/", i + 2)
            i = n if end == -1 else end + 2
            out.append(" ")
            continue
        if ch in "'\"`":
            quote, j, buf = ch, i + 1, []
            while j < n and source[j] != quote:
                if source[j] == "\\" and j + 1 < n:
                    buf.append(source[j + 1])
                    j += 2
                    continue
                buf.append(source[j])
                j += 1
            literals.append("".join(buf))
            out.append(f" S{len(literals) - 1} ")
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), literals


def read_module_source(source: str) -> tuple[set[str], set[str], list[str]]:
    """Return (events, calls, relative import specifiers) for one source file."""
    code, literals = _strip(source)
    events = {literals[int(m.group(1))] for m in _ON_CALL.finditer(code)}
    calls = {f"{m.group(1)}.{m.group(2)}" for m in _API_CALL.finditer(code)}
    imports: list[str] = []
    for m in _IMPORT.finditer(code):
        idx = m.group(1) or m.group(2)
        spec = literals[int(idx)]
        if spec.startswith(("./", "../")):
            imports.append(spec)
    return events, calls, imports


def _resolve_import(base: Path, spec: str, root: Path) -> Path | None:
    target = (base.parent / spec).resolve()
    candidates = [target]
    if target.suffix not in _MODULE_SUFFIXES:
        candidates += [target.with_name(target.name + s) for s in _MODULE_SUFFIXES]
        candidates += [target / f"index{s}" for s in _MODULE_SUFFIXES]
    for cand in candidates:
        try:
            cand.relative_to(root.resolve())
        except ValueError:
            return None
        if cand.is_file():
            return cand
    return None


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_SOURCE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def module_path_for(root: Path) -> Path | None:
    """Return the hooks module a plugin directory names, or ``None`` if not a mod."""
    hooks_json = root / "hooks" / "hooks.json"
    data = _load_json(hooks_json)
    if not isinstance(data, dict):
        return None
    modules = data.get("modules")
    if not isinstance(modules, list) or not modules:
        return None
    first = modules[0]
    if not isinstance(first, str) or not first.strip():
        return None
    return (hooks_json.parent / first.strip()).resolve()


def read_mod(root: Path, name: str, origin: str) -> Mod | None:
    """Read a mod at ``root``: its hooks module plus relatively imported files."""
    module = module_path_for(root)
    if module is None:
        return None
    events: set[str] = set()
    calls: set[str] = set()
    seen: list[Path] = []
    queue = [module]
    while queue and len(seen) < _MAX_FILES_PER_MOD:
        path = queue.pop(0)
        if path in seen or path.name.endswith((".test.ts", ".test.tsx")):
            continue
        source = _read_text(path)
        if source is None:
            continue
        seen.append(path)
        ev, ca, imports = read_module_source(source)
        events |= ev
        calls |= ca
        for spec in imports:
            resolved = _resolve_import(path, spec, root)
            if resolved is not None and resolved not in seen:
                queue.append(resolved)
    return Mod(
        name=name,
        origin=origin,
        root=root,
        module_path=module,
        events=tuple(sorted(events)),
        calls=tuple(sorted(calls)),
        files=tuple(seen),
    )


# ── Discovery ──────────────────────────────────────────────────────────────────


def claude_config_dir(home: Path | None = None) -> Path:
    """Claude Code's config directory: ``CLAUDE_CONFIG_DIR`` or ``~/.claude``."""
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    return (home or Path.home()) / ".claude"


def _settings_plugin_dirs(home: Path | None) -> list[str]:
    data = _load_json(claude_config_dir(home) / "settings.json")
    env = data.get("env") if isinstance(data, dict) else None
    value = env.get("CLAUDE_CODE_PLUGIN_DIRS") if isinstance(env, dict) else None
    return [value] if isinstance(value, str) and value.strip() else []


def plugin_dirs_setting(home: Path | None = None) -> list[Path]:
    """Directories in ``CLAUDE_CODE_PLUGIN_DIRS`` (environment or user settings)."""
    raw = [os.environ.get("CLAUDE_CODE_PLUGIN_DIRS", "")] + _settings_plugin_dirs(home)
    dirs: list[Path] = []
    for value in raw:
        for part in value.split(os.pathsep):
            part = part.strip()
            if part:
                path = Path(part).expanduser()
                if path not in dirs:
                    dirs.append(path)
    return dirs


def discover_mods(
    plugins: list[InstalledPlugin], home: Path | None = None
) -> list[Mod]:
    """Return every mod found among installed plugins, dev mods and plugin dirs."""
    mods: list[Mod] = []
    seen_roots: set[Path] = set()

    def add(root: Path, name: str, origin: str) -> None:
        key = root.resolve() if root.exists() else root
        if key in seen_roots or not root.is_dir():
            return
        seen_roots.add(key)
        mod = read_mod(root, name, origin)
        if mod is not None:
            mods.append(mod)

    for plugin in plugins:
        if plugin.install_path is not None:
            add(plugin.install_path, plugin.plugin_id, "installed")

    dev_root = claude_config_dir(home) / "dev-mods"
    if dev_root.is_dir():
        for session in sorted(p for p in dev_root.iterdir() if p.is_dir()):
            for mod_dir in sorted(p for p in session.iterdir() if p.is_dir()):
                add(mod_dir, mod_dir.name, "dev")

    for directory in plugin_dirs_setting(home):
        add(directory, directory.name, "plugin-dir")
    return mods


def managed_settings_dir() -> Path:
    """Claude Code's file-based managed settings directory for this OS."""
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    if sys.platform.startswith("win"):
        return Path("C:/Program Files/ClaudeCode")
    return Path("/etc/claude-code")


def read_guard_state(directory: Path | None = None) -> GuardState:
    """Read ``managed-settings.json`` and ``managed-settings.d/*.json``.

    Later drop-in files override earlier ones and the main file, matching
    Claude Code's merge order closely enough for the two guard options.
    """
    directory = directory or managed_settings_dir()
    main = directory / "managed-settings.json"
    docs: list[tuple[Path, Any]] = []
    if main.is_file():
        docs.append((main, _load_json(main)))
    dropins = directory / "managed-settings.d"
    if dropins.is_dir():
        docs += [(p, _load_json(p)) for p in sorted(dropins.glob("*.json"))]
    if not docs:
        return GuardState()
    override = managed_only = False
    for _path, data in docs:
        if not isinstance(data, dict):
            continue
        configs = data.get("pluginConfigs")
        guard = (
            configs.get("cc-plugin-sec-default@builtin")
            if isinstance(configs, dict)
            else None
        )
        options = guard.get("options") if isinstance(guard, dict) else None
        if isinstance(options, dict):
            if "allowModsToOverrideDenyRules" in options:
                override = options["allowModsToOverrideDenyRules"] is True
            if "allowManagedModsOnly" in options:
                managed_only = options["allowManagedModsOnly"] is True
    return GuardState(
        managed_settings_path=docs[0][0],
        allow_override_deny_rules=override,
        allow_managed_mods_only=managed_only,
    )


# ── Findings ───────────────────────────────────────────────────────────────────


def _finding(
    mod: Mod,
    fid: str,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
    owasp: list[str],
    cwe: str,
) -> Finding:
    evidence = (
        f"mod: {mod.name} ({mod.origin}) | module: {mod.module_path} | "
        f"events: {', '.join(mod.events) or 'none'} | "
        f"calls: {', '.join('$.' + c for c in mod.calls) or 'none'}"
    )
    return Finding(
        id=fid,
        severity=severity,
        analyzer="plugins",
        client="claude-code",
        server=mod.name,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        owasp_mcp_top_10=owasp,
        finding_path=str(mod.module_path),
    )


def _guard_note(guard: GuardState) -> str:
    if guard.allow_override_deny_rules:
        return (
            " Managed settings set allowModsToOverrideDenyRules, so a mod can also"
            " approve calls your deny rules refuse."
        )
    if guard.guard_detected:
        return (
            " A managed settings file is present, so Claude Code's built-in guard"
            " (sec-default) loads and deny rules still take precedence."
        )
    return (
        " No managed settings file was found. Claude Code's built-in guard"
        " (sec-default) loads only with managed settings or a Team/Enterprise"
        " sign-in; without it, a mod can also approve calls your deny rules refuse."
    )


def analyze_mods(mods: list[Mod], guard: GuardState | None = None) -> list[Finding]:
    """Return MOD-001..005 findings for ``mods``.

    Args:
        mods: Mods from :func:`discover_mods`.
        guard: What mcp-audit can see of the built-in guard; read from the
            managed settings directory when omitted.
    """
    guard = guard or read_guard_state()
    findings: list[Finding] = []
    for mod in mods:
        events, calls = set(mod.events), set(mod.calls)
        blocked = guard.allow_managed_mods_only

        inventory = (
            f"Claude Code mod {mod.name} ({mod.origin}) hooks "
            f"{', '.join(mod.events) or 'no events'} and calls "
            f"{', '.join('$.' + c for c in mod.calls) or 'no mods API methods'}."
            f"{_guard_note(guard)}"
        )
        if blocked:
            inventory += (
                " Managed settings set allowManagedModsOnly, so this mod does not load"
                " unless it is one of your organization's."
            )
        findings.append(
            _finding(
                mod,
                "MOD-005",
                Severity.INFO,
                f"Claude Code mod installed: {mod.name}",
                inventory,
                "Review the mod's source before each update, or run "
                "`claude plugin validate <dir>`, which prints the same hooks and "
                "calls. "
                f"See {_DOCS_ADMIN}.",
                ["MCP04"],
                "CWE-1357",
            )
        )
        if blocked:
            continue

        if events & _APPROVES_CALLS:
            findings.append(
                _finding(
                    mod,
                    "MOD-001",
                    Severity.HIGH,
                    "Mod can approve tool calls before the permission prompt: "
                    f"{mod.name}",
                    f"{mod.name} hooks tool.check, so it can allow or deny Claude's"
                    " tool"
                    " calls before you are asked. In auto mode, a call a mod approves"
                    f" runs without the classifier check.{_guard_note(guard)}",
                    "Remove the mod unless you have read its tool.check hook and trust"
                    " its author. Organizations can block user mods with the built-in"
                    " guard's allowManagedModsOnly option.",
                    ["MCP07", "MCP04"],
                    "CWE-863",
                )
            )

        secrets = calls & _SECRET_READS
        files = calls & _FILE_READS
        sinks = calls & _SENDS_OUT
        if sinks and (secrets or files):
            sources = sorted(secrets | files)
            severity = Severity.HIGH if secrets else Severity.MEDIUM
            findings.append(
                _finding(
                    mod,
                    "MOD-002",
                    severity,
                    f"Mod can read secrets or files and send data out: {mod.name}",
                    f"{mod.name} calls {', '.join('$.' + s for s in sources)} and"
                    f" {', '.join('$.' + s for s in sorted(sinks))}. One mod that can"
                    " read environment variables, settings or files and also make"
                    " network requests can move secrets off the machine."
                    " Deny rules such as Read(.env) do not cover a mod's own"
                    " $.fs.read calls.",
                    "Read what the mod reads and where it sends it before keeping it."
                    " Keep secrets out of environment variables and settings the mod"
                    " can read.",
                    ["MCP01", "MCP04"],
                    "CWE-201",
                )
            )

        rewrites = events & _REWRITES_WHAT_CLAUDE_READS
        submits = calls & _SUBMITS_AS_USER
        if rewrites or submits:
            what = sorted(rewrites) + [f"$.{c}" for c in sorted(submits)]
            findings.append(
                _finding(
                    mod,
                    "MOD-003",
                    Severity.MEDIUM,
                    f"Mod can change what Claude reads: {mod.name}",
                    f"{mod.name} uses {', '.join(what)}, so it can rewrite tool"
                    " descriptions, the system prompt, context or stored conversation"
                    " rows, or submit a prompt as if you typed it. That is the same"
                    " effect as a poisoned tool description, from inside Claude Code.",
                    "Read those hooks before keeping the mod, and diff them on every"
                    " update.",
                    ["MCP03", "MCP06"],
                    "CWE-1427",
                )
            )

        runs = calls & _RUNS_PROGRAMS
        if runs:
            findings.append(
                _finding(
                    mod,
                    "MOD-004",
                    Severity.MEDIUM,
                    f"Mod starts programs or changes their environment: {mod.name}",
                    f"{mod.name} calls {', '.join('$.' + c for c in sorted(runs))}."
                    " Programs a mod starts run as you, outside Claude Code's sandbox"
                    " and network policy, and $.env.set changes what every later"
                    " command and"
                    " MCP server runs with.",
                    "Check which programs the mod starts and why. Prefer mods that"
                    " don't need to start programs.",
                    ["MCP05", "MCP04"],
                    "CWE-250",
                )
            )
    return findings


def analyze_plugin_dirs_setting(home: Path | None = None) -> list[Finding]:
    """MOD-006: ``CLAUDE_CODE_PLUGIN_DIRS`` set in ``~/.claude/settings.json``."""
    settings = claude_config_dir(home) / "settings.json"
    values = _settings_plugin_dirs(home)
    if not values:
        return []
    return [
        Finding(
            id="MOD-006",
            severity=Severity.MEDIUM,
            analyzer="plugins",
            client="claude-code",
            server="CLAUDE_CODE_PLUGIN_DIRS",
            title="Plugin directories load in every Claude Code session",
            description=(
                "The env block of your Claude Code settings sets"
                " CLAUDE_CODE_PLUGIN_DIRS,"
                " so every session loads plugins (and their mods) from those"
                " directories without installing them from a marketplace. Marketplace"
                " allowlists don't cover them."
            ),
            evidence=f"CLAUDE_CODE_PLUGIN_DIRS={values[0]}",
            remediation=(
                "Remove CLAUDE_CODE_PLUGIN_DIRS from settings and load development"
                " plugins with --plugin-dir only when you need them. Organizations can"
                " set disableSideloadFlags in managed settings."
            ),
            cwe="CWE-829",
            owasp_mcp_top_10=["MCP04"],
            finding_path=str(settings),
        )
    ]
