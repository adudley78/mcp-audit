"""Detect supply-chain attacks via typosquatting of known MCP npm and PyPI packages.

Research basis: single-edit-distance substitutions, additions, and deletions
are the dominant typosquatting technique for scoped npm packages, and the same
technique applies to Python packages installed via uvx / pipx / pip.
Ref: "Typosquatting in Package Managers" — Vu et al., NDSS 2021
  https://www.ndss-symposium.org/ndss-paper/detecting-node-js-package-name-squatting/

STORY-0097 adds two checks edit distance cannot make:

* ``SC-007`` (MEDIUM) — an unscoped twin: the configured name copies a known
  package's name without its scope (``mcp-server-github`` for
  ``@modelcontextprotocol/server-github``).  See :mod:`mcp_audit.registry.twins`.
  It takes precedence over ``SC-001``..``SC-003`` for the same server: the
  exact relationship explains the name better than whichever registry entry
  happens to be a few edits away, so a server never gets both.
* ``SC-008`` (CRITICAL / MEDIUM) — the exact package is an OSV ``MAL-*``
  record in the bundled ``registry/known-malicious.json``.  See
  :mod:`mcp_audit.registry.malicious`.  It answers a different question (what
  OSV knows about this package, not what its name resembles), so it is
  reported alongside any name finding rather than replacing it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from packaging.version import InvalidVersion, Version

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.registry.loader import (
    KnownServerRegistry,
    RegistryEntry,
    levenshtein,
    load_registry,
    normalize_pypi_name,
)
from mcp_audit.registry.malicious import (
    KnownMaliciousPackages,
    MaliciousMatch,
    assess,
    load_known_malicious,
)
from mcp_audit.registry.twins import Twin, TwinIndex

# Commands that download and execute npm packages at runtime.
_NPX_LIKE: frozenset[str] = frozenset({"npx", "bunx", "pnpx"})

# Flags that consume the following token as their value, not as a package name.
_FLAGS_WITH_VALUE: frozenset[str] = frozenset({"-p", "--package", "--call", "-c"})

# Commands that download and execute Python packages at runtime.
_PYPI_LIKE: frozenset[str] = frozenset({"uvx", "pipx"})

# Recognises the CPython interpreter under every common spelling so a
# ``python -m <pkg>`` typosquat cannot evade detection simply by being launched
# as ``python3`` / ``python3.11`` / ``/usr/bin/python3`` — the same word-boundary
# false-negative class as the historic ``nc -e`` and HOOK-001 ``python3`` misses.
_PY_INTERPRETER_RE: re.Pattern[str] = re.compile(r"^(?:python(?:[23](?:\.\d+)?)?|py)$")


def _is_python_interpreter(command: str | None) -> bool:
    """Return True if *command* is a CPython interpreter under any common spelling.

    Matches bare names (``python``, ``python3``, ``python3.11``, ``py``) as well
    as absolute / relative paths whose basename is one of those (e.g.
    ``/usr/bin/python3``).  Used to gate the ``python -m`` typosquat path so that
    the dominant real-world spelling ``python3`` is not silently skipped.

    Args:
        command: The ``command`` field from a :class:`~mcp_audit.models.ServerConfig`.

    Returns:
        ``True`` when *command* resolves to a Python interpreter.
    """
    if not command:
        return False
    return bool(_PY_INTERPRETER_RE.match(_launcher_basename(command)))


# Windows launch wrappers that npm, uv and pip install next to the real binary.
_LAUNCHER_SUFFIXES: tuple[str, ...] = (".cmd", ".exe", ".bat", ".ps1")
# ``cmd /c <command> …`` (or ``/k``) runs the next argument as the command.
_CMD_RUN_FLAGS: frozenset[str] = frozenset({"/c", "/k"})
# Bound on nested ``cmd /c cmd /c …`` unwrapping.
_MAX_CMD_UNWRAP = 3
# CreateProcess limits a command line to 32,767 characters (learn.microsoft.com,
# CreateProcessW, lpCommandLine), so nothing past that can be launched.
_MAX_WINDOWS_CMDLINE = 32_767
_WINDOWS_ARG_SPACE = " \t"


def _launcher_basename(command: str) -> str:
    """Return a launcher's bare, lowercase name: path, case and Windows suffix removed.

    ``/usr/local/bin/npx``, ``C:\\Program Files\\nodejs\\npx.cmd`` and
    ``NPX.CMD`` all become ``npx``.  Both ``/`` and ``\\`` count as separators
    whatever the host OS, because a config written on Windows is scanned on
    Linux too.
    """
    base = command.strip().rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    for suffix in _LAUNCHER_SUFFIXES:
        if base.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)]
    return base


def _read_windows_program_name(text: str, i: int) -> tuple[str, int]:
    """Read the first argument (the program name) of a Windows command line.

    Double quotes group and are dropped; backslashes are always literal.
    Returns the name and the index just past it.
    """
    buf: list[str] = []
    in_quotes = False
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            in_quotes = not in_quotes
        elif ch in _WINDOWS_ARG_SPACE and not in_quotes:
            break
        else:
            buf.append(ch)
        i += 1
    return "".join(buf), i


def _read_windows_argument(text: str, i: int) -> tuple[str, int]:
    """Read one later argument of a Windows command line, starting at *i*.

    Applies the backslash and quote rules described in
    :func:`split_windows_command_line`. Returns the argument and the index
    just past it. Each character is visited once.
    """
    buf: list[str] = []
    in_quotes = False
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            j = i
            while j < n and text[j] == "\\":
                j += 1
            count = j - i
            if j < n and text[j] == '"':
                buf.append("\\" * (count // 2))
                if count % 2:
                    buf.append('"')  # odd: the last backslash escapes the quote
                    j += 1
                # even: the quote at j is read next, as a delimiter
            else:
                buf.append("\\" * count)
            i = j
        elif ch == '"':
            if in_quotes and i + 1 < n and text[i + 1] == '"':
                buf.append('"')  # "" inside quotes is one literal quote
                i += 2
            else:
                in_quotes = not in_quotes
                i += 1
        elif ch in _WINDOWS_ARG_SPACE and not in_quotes:
            break
        else:
            buf.append(ch)
            i += 1
    return "".join(buf), i


def split_windows_command_line(line: str) -> list[str]:
    """Split a Windows command line into arguments the way Windows programs do.

    Follows the Microsoft C runtime rules ("Parsing C command-line
    arguments", learn.microsoft.com), which ``CommandLineToArgvW`` shares
    for backslashes and quotes:

    * spaces and tabs outside double quotes separate arguments;
    * the first argument is the program name: double quotes group (so
      ``"C:\\Program Files\\nodejs\\npx.cmd"`` is one argument) and are
      dropped, and backslashes are literal;
    * in later arguments, 2n backslashes before a ``"`` give n backslashes
      and the quote opens or closes a quoted part; 2n+1 give n backslashes
      and a literal ``"``; backslashes not before a quote are literal; inside
      quotes, ``""`` is a literal ``"``; an unclosed quote runs to the end.

    Leading spaces and tabs are skipped, as ``cmd /c`` skips them. Only the
    first 32,767 characters are read (the CreateProcess limit). One pass,
    linear in the input.

    Args:
        line: A whole command line, such as the single argument after
            ``cmd /c``.

    Returns:
        The arguments, in order; empty when *line* is blank.
    """
    text = line[:_MAX_WINDOWS_CMDLINE]
    n = len(text)
    i = 0
    while i < n and text[i] in _WINDOWS_ARG_SPACE:
        i += 1
    if i >= n:
        return []
    program, i = _read_windows_program_name(text, i)
    args = [program]
    while True:
        while i < n and text[i] in _WINDOWS_ARG_SPACE:
            i += 1
        if i >= n:
            return args
        arg, i = _read_windows_argument(text, i)
        args.append(arg)


def normalize_launch(
    command: str | None, args: list[str] | None
) -> tuple[str, list[str]]:
    """Return ``(launcher, args)`` the way the OS will actually run the server.

    The supply-chain checks gate on the launcher name (``npx``, ``uvx``,
    ``python3`` …).  Before STORY-0097's review, only the bare spelling
    matched, so ``/usr/local/bin/npx``, an nvm path, ``npx.cmd`` or
    ``cmd /c npx -y <pkg>`` (the form Claude Desktop documents on Windows)
    skipped every SC-00x check.  This one normaliser is shared by
    :meth:`SupplyChainAnalyzer.analyze`, :func:`_pinned_version` and
    :func:`extract_pypi_package`:

    * the launcher is reduced by :func:`_launcher_basename`;
    * ``cmd``/``cmd.exe`` followed by ``/c`` or ``/k`` (any case, after any
      other ``/x`` switches such as ``/d /s``) is unwrapped so the next
      argument is the launcher.  A single argument holding the whole command
      line (``cmd /c "npx -y pkg"``), or an argument with double quotes in it
      (``"C:\\Program Files\\nodejs\\npx.cmd" -y pkg``), is split with
      :func:`split_windows_command_line`.  An argument with spaces and no
      quotes followed by more arguments is one path, as the launching program
      quotes it.  ``cmd``'s own ``/s`` quote stripping is not modelled.

    Args:
        command: The server's ``command``.
        args: The server's ``args``.

    Returns:
        The normalised launcher name and the arguments that follow it.
        Anything unrecognised comes back with only the basename rules applied.
    """
    launcher = _launcher_basename(command or "")
    rest = list(args or [])
    for _ in range(_MAX_CMD_UNWRAP):
        if launcher != "cmd":
            break
        i = 0
        while (
            i < len(rest)
            and rest[i].startswith("/")
            and rest[i].lower() not in _CMD_RUN_FLAGS
        ):
            i += 1
        if i >= len(rest) - 1 or rest[i].lower() not in _CMD_RUN_FLAGS:
            break
        target, rest = rest[i + 1], rest[i + 2 :]
        if '"' in target or (not rest and any(ch.isspace() for ch in target)):
            tokens = split_windows_command_line(target)
            if tokens:
                target, rest = tokens[0], tokens[1:] + rest
        launcher = _launcher_basename(target)
    return launcher, rest


# uvx/pipx flags whose *next* token is a value rather than a package name.
_UVX_FLAGS_WITH_VALUE: frozenset[str] = frozenset(
    {
        "--from",
        "-f",
        "--python",
        "--with",
        "--index-url",
        "--extra-index-url",
        "--default-index",
        "--override-index",
    }
)


def strip_npm_version_suffix(name: str) -> str:
    """Strip a trailing ``@version`` from an npm package token.

    :func:`extract_npm_package` deliberately returns the whole token (its test
    suite pins that), so callers that look a package up by name strip the
    version first.  For a scoped package the version sits after the *second*
    ``@`` (``@scope/name@1.2.3``); for an unscoped one, after the first.

    Args:
        name: An npm package token, with or without a version suffix.

    Returns:
        The bare package name.
    """
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        pkg_name = rest.rsplit("@", 1)[0] if "@" in rest else rest
        return f"{scope}/{pkg_name}"
    return name.rsplit("@", 1)[0] if "@" in name else name


def extract_npm_package(args: list[str]) -> str | None:
    """Return the first npm package name found in an npx-style argument list.

    Skips flag arguments (``-y``, ``--yes``, etc.) and their associated values.
    Rejects anything that looks like a local path or URL.

    Args:
        args: The ``args`` list from a :class:`~mcp_audit.models.ServerConfig`.

    Returns:
        Lowercase package name, or ``None`` if no package-like token is found.
    """
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in _FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        # Reject local paths and URLs — not npm packages.
        if arg.startswith(("/", ".", "http://", "https://", "file:")):
            continue
        # Accept scoped (@org/name) or plain package names.
        return arg.lower()
    return None


# A PyPI requirement token ends its name at the first PEP 508 specifier,
# extras bracket, marker, or ``@`` (uvx's ``pkg@1.2.3`` form).
_PYPI_NAME_END_RE: re.Pattern[str] = re.compile(r"[=<>!~;\[@\s]")


def _bare_pypi_name(token: str) -> str:
    """Return the name from ``pkg``, ``pkg==1.2``, ``pkg@1.2`` or ``pkg[x]>=1``."""
    return _PYPI_NAME_END_RE.split(token, maxsplit=1)[0]


def extract_pypi_package(command: str, args: list[str]) -> str | None:
    """Return the Python package name from a uvx, pipx, or ``python -m`` invocation.

    Parsing rules:

    * ``uvx <pkg>[@ver]`` → *pkg* is the first non-flag positional argument.
    * ``uvx --from <pkg> <executable>`` → *pkg* is the token after ``--from``/``-f``;
      the ``--from`` flag takes precedence over the positional scan so the
      *executable* name is not mistakenly used.
    * ``uvx --python 3.11 <pkg>`` → ``--python`` and its value are skipped; the
      first remaining non-flag token is *pkg*.
    * ``uvx <pkg>@<version>`` → the ``@<version>`` suffix is stripped before checking.
    * ``pipx run <pkg>`` / ``pipx install <pkg>`` → the ``run``/``install`` sub-command
      is consumed and the remaining args are parsed with the same uvx rules.
    * ``python -m <module>`` → *module* is PEP 503-normalised and returned.

    All names are normalised via :func:`~mcp_audit.registry.loader.normalize_pypi_name`
    before being returned so callers receive a canonical form for registry lookups.

    Args:
        command: The ``command`` field from a :class:`~mcp_audit.models.ServerConfig`.
        args: The ``args`` list from the same config.

    Returns:
        Normalised package name, or ``None`` if no package-like token is found.
    """
    command, args = normalize_launch(command, args)
    if _is_python_interpreter(command):
        try:
            m_idx = args.index("-m")
            module = args[m_idx + 1]
        except (ValueError, IndexError):
            return None
        return normalize_pypi_name(module)

    if command == "pipx":
        # Consume the sub-command token (run / install / inject / …) so that
        # the remaining args can be parsed by the same flag-scanning logic below.
        # Only strip tokens that are known pipx sub-commands to avoid accidentally
        # consuming a package name when no sub-command is present.
        _pipx_subcommands = frozenset(
            {"run", "install", "inject", "upgrade", "upgrade-all", "uninstall"}
        )
        effective = args[1:] if args and args[0] in _pipx_subcommands else args
    elif command == "uvx":
        effective = args
    else:
        return None

    # Check for --from / -f flag first — it explicitly names the package even
    # when a separate executable name follows it.
    for i, arg in enumerate(effective):
        if arg in ("--from", "-f") and i + 1 < len(effective):
            return normalize_pypi_name(_bare_pypi_name(effective[i + 1]))

    # General flag-skipping scan: consume known-value flags and their arguments,
    # ignore bare flags, and take the first remaining positional as the package.
    skip_next = False
    for arg in effective:
        if skip_next:
            skip_next = False
            continue
        if arg in _UVX_FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if arg.startswith("--"):
            # --flag=value style embeds the value — no token to skip.
            if "=" not in arg:
                # Unknown --flag without =; treat as a bare flag (no value skip).
                pass
            continue
        if arg.startswith("-"):
            continue
        # First non-flag positional: strip an optional version pin or specifier.
        return normalize_pypi_name(_bare_pypi_name(arg))

    return None


def launch_package(server: ServerConfig) -> tuple[Literal["npm", "pypi"], str] | None:
    """Return ``(ecosystem, package)`` for the package *server*'s launch installs.

    An npm launcher (``npx``, ``bunx``, ``pnpx``, ``yarn dlx``, under any path
    or ``cmd /c`` spelling) gives the npm name with any version suffix
    stripped; ``uvx``, ``pipx`` and ``python -m`` give the PEP 503 name with
    any version or specifier stripped.

    Args:
        server: The MCP server configuration to inspect.

    Returns:
        The ecosystem and bare package name, or ``None`` when the launch
        command installs no package mcp-audit can name.
    """
    launcher, args = normalize_launch(server.command, server.args)
    if launcher == "yarn":
        if not args or args[0] != "dlx":
            return None
        launcher, args = "npx", args[1:]
    if launcher in _NPX_LIKE:
        spec = extract_npm_package(args)
        return ("npm", strip_npm_version_suffix(spec)) if spec else None
    if launcher in _PYPI_LIKE or _is_python_interpreter(launcher):
        package = extract_pypi_package(launcher, args)
        return ("pypi", package) if package else None
    return None


def resolve_launch_entry(
    server: ServerConfig, registry: KnownServerRegistry
) -> RegistryEntry | None:
    """Return the registry entry for the package *server*'s launch command installs.

    The one resolver for "which registry entry is this server": TRANSPORT-003's
    tiering and the rule engine's ``exempt_known_servers`` both call it, so
    they can no longer disagree (Q-016: COMM-004 missed every
    ``@scope/name@version`` launch that TRANSPORT-003 recognised).  The lookup
    is ecosystem-scoped (:func:`launch_package`): npm names resolve through
    :meth:`KnownServerRegistry.get_npm`, PyPI names through
    :meth:`KnownServerRegistry.get_pypi`, so a package listed only for the
    other ecosystem never matches.

    Args:
        server: The MCP server configuration to resolve.
        registry: The known-server registry.

    Returns:
        The matching :class:`RegistryEntry`, or ``None`` when the launch
        installs no package or the package is not in the registry for that
        ecosystem.
    """
    found = launch_package(server)
    if found is None:
        return None
    ecosystem, package = found
    return (
        registry.get_npm(package) if ecosystem == "npm" else registry.get_pypi(package)
    )


# An exact npm version: MAJOR.MINOR.PATCH with optional pre-release/build.
# Anything else (ranges, dist-tags, ``latest``) is not a pin.
_NPM_EXACT_VERSION_RE: re.Pattern[str] = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)

# Characters that make a PyPI version string a specifier rather than a pin.
_PYPI_SPECIFIER_CHARS: frozenset[str] = frozenset("<>=!~*,")


def _pinned_version(server: ServerConfig) -> str | None:
    """Return the exact package version the launch command pins, or ``None``.

    Only an exact pin counts.  A range, a dist-tag, ``latest``, or no version
    at all returns ``None``, because mcp-audit never resolves ranges and an
    offline scan cannot know what an unpinned launch will install.

    Handles ``npx [flags] pkg@1.2.3`` / ``@scope/pkg@1.2.3`` (and ``yarn dlx``,
    ``bunx``, ``pnpx``) and ``uvx pkg==1.2.3`` / ``uvx pkg@1.2.3`` (and
    ``pipx run``, ``uvx --from``).

    Args:
        server: The MCP server configuration to inspect.

    Returns:
        The pinned version string, or ``None`` when the version is not pinned.
    """
    command, args = normalize_launch(server.command, server.args)

    if command == "yarn" and args[:1] == ["dlx"]:
        command, args = "npx", args[1:]

    if command in _NPX_LIKE:
        spec = extract_npm_package(args)
        if spec is None:
            return None
        if spec.startswith("@"):
            _scope, _slash, rest = spec.partition("/")
            _name, sep, version = rest.rpartition("@")
        else:
            _name, sep, version = spec.rpartition("@")
        if sep and _NPM_EXACT_VERSION_RE.match(version):
            return version
        return None

    if command in _PYPI_LIKE:
        package = extract_pypi_package(command, args)
        if package is None:
            return None
        for token in args:
            if token.startswith("-"):
                continue
            base, version = token, ""
            if "==" in token:
                base, version = token.split("==", 1)
            elif "@" in token:
                base, version = token.split("@", 1)
            if normalize_pypi_name(base) != package or not version:
                continue
            if any(ch in _PYPI_SPECIFIER_CHARS for ch in version):
                return None
            try:
                Version(version)
            except InvalidVersion:
                return None
            return version
        return None

    return None


def _version_lt(a: str, b: str) -> bool | None:
    """Return ``a < b`` under PEP 440 ordering, or ``None`` if either won't parse."""
    try:
        return Version(a) < Version(b)
    except InvalidVersion:
        return None


# A version whose first number is at least this is a calendar version
# (``2025.7.1``): no semantic-version major release reaches four digits.
_CALVER_MIN_MAJOR = 1000


def _is_calendar_version(version: str) -> bool | None:
    """Return whether *version* is a calendar version, or ``None`` if unparsable."""
    try:
        return Version(version).release[0] >= _CALVER_MIN_MAJOR
    except InvalidVersion:
        return None


def _schemes_differ(pinned: str, fixed: str) -> bool:
    """Return ``True`` when one version is calendar-based and the other is not.

    ``@modelcontextprotocol/server-filesystem`` published ``2026.8.31`` and then
    ``1.0.0`` and ``2.0.0`` (Q-010).  Ordered as numbers, ``2.0.0`` sorts below
    the recorded fix ``2025.7.1`` although it was published later, and the
    reverse switch would hide an affected release.
    """
    a, b = _is_calendar_version(pinned), _is_calendar_version(fixed)
    return a is not None and b is not None and a != b


def _fix_status(
    pinned: str, fixed: str, semver_resumed_at: str | None
) -> Literal["affected", "fixed", "undecidable"]:
    """Order a pinned version against one CVE's recorded fix.

    Same scheme: PEP 440 order, as before (a version that won't parse counts
    as affected).  Different schemes (calendar vs semantic):

    * semantic pin, calendar fix: with ``semver_resumed_at`` recorded, a pin
      below it is from the semantic line that preceded the calendar releases
      (affected) and a pin at or above it came after them (fixed).  Without
      it, a ``0.x`` pin is affected: both registry packages that use calendar
      versions (server-filesystem, mcp-server-git) published ``0.x`` first,
      so this is what ``main`` reported before STORY-0105.  Anything else is
      undecidable offline (SC-009).
    * calendar pin, semantic fix: with ``semver_resumed_at``, a fix below it
      is on the earlier semantic line (the calendar pin came later: fixed),
      and a fix at or above it came after every calendar release
      (affected).  Without it: undecidable.

    Args:
        pinned: The exact version pinned in the launch command.
        fixed: The recorded fixed version for one advisory.
        semver_resumed_at: The registry entry's ``semver_resumed_at``.

    Returns:
        ``"affected"``, ``"fixed"`` or ``"undecidable"``.
    """
    if not _schemes_differ(pinned, fixed):
        return "fixed" if _version_lt(pinned, fixed) is False else "affected"
    resumed = semver_resumed_at
    if resumed is not None and _is_calendar_version(resumed) is not False:
        resumed = None  # unparsable or itself calendar-shaped: ignore it
    if _is_calendar_version(fixed):
        if resumed is not None:
            return "affected" if _version_lt(pinned, resumed) else "fixed"
        if Version(pinned).release[0] == 0:
            return "affected"
        return "undecidable"
    if resumed is not None:
        return "fixed" if _version_lt(fixed, resumed) else "affected"
    return "undecidable"


def _highest_version(versions: set[str]) -> str | None:
    """Return the highest of *versions*, or ``None`` if any fails to parse."""
    try:
        return str(max(versions, key=Version)) if versions else None
    except InvalidVersion:
        return None


# Longest CVE list written into one SC-004 description; `vet` shows the rest.
_MAX_LISTED_CVES = 10


def _advisory_url(advisory_id: str) -> str:
    """Public page for an advisory ID: NVD for CVEs, GitHub for GHSA, OSV otherwise."""
    if advisory_id.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{advisory_id}"
    if advisory_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{advisory_id}"
    return f"https://osv.dev/vulnerability/{advisory_id}"


def _emit_known_cve_findings(
    server: ServerConfig,
    entry: RegistryEntry,
) -> list[Finding]:
    """Emit one SC-004 finding for the CVEs recorded against *entry*.

    Called when an exact-match package has public CVE advisories recorded in
    the bundled registry (``known_vulnerabilities`` and/or the structured
    ``known_vulns`` records).  Severity is HIGH.

    One finding per package, not one per CVE (STORY-0078): a package with
    two dozen advisories used to produce two dozen HIGH findings, and every
    SC-004 for the same package already shares one advisory ID in the feed.

    Version-aware when it can be: if the launch command pins an exact version
    and a structured record gives ``fixed_in`` for a CVE, that CVE is dropped
    when the pinned version is at or above the fix.  A CVE with no recorded
    ``fixed_in``, or a version that won't parse, is kept.  When nothing
    remains, no finding is emitted.

    Severity (STORY-0083): HIGH when the config pins an affected version, or
    when any listed CVE has no recorded fix.  MEDIUM when the launch is
    unpinned and every listed CVE has a fix: the launcher normally installs a
    patched release, but npx and uvx can reuse a cached older install, so the
    finding stays as a prompt to pin.  This keeps long-fixed advisories on
    official servers from raising HIGH on every unpinned config once the
    registry carries their full history.

    Args:
        server: The MCP server configuration that references this package.
        entry: Registry entry for the matched package.

    Returns:
        A list with at most one SC-004 :class:`~mcp_audit.models.Finding`.
    """
    cves: list[str] = []
    fixed_in: dict[str, str] = {}
    for cve_id in entry.known_vulnerabilities or []:
        if cve_id and cve_id not in cves:
            cves.append(cve_id)
    for record in entry.known_vulns or []:
        cve_id = record.get("cve") if isinstance(record, dict) else None
        if not cve_id:
            continue
        if cve_id not in cves:
            cves.append(cve_id)
        if record.get("fixed_in"):
            fixed_in[cve_id] = str(record["fixed_in"])
    if not cves:
        return []

    pinned = _pinned_version(server)
    undecidable: list[str] = []
    if pinned is None:
        affected = cves
    else:
        status = {
            c: _fix_status(pinned, fixed_in[c], entry.semver_resumed_at)
            for c in cves
            if c in fixed_in
        }
        undecidable = [c for c in cves if status.get(c) == "undecidable"]
        affected = [c for c in cves if c not in fixed_in or status[c] == "affected"]
    if not affected:
        if undecidable and pinned is not None:
            return [_undecidable_finding(server, entry, pinned, undecidable, fixed_in)]
        return []

    fixes = {fixed_in[c] for c in affected if c in fixed_in}
    all_fixed_known = len(fixes) > 0 and all(c in fixed_in for c in affected)
    highest_fix = _highest_version(fixes) if all_fixed_known else None

    if pinned is not None:
        version_note = (
            f" The config pins version {pinned}, which is below the fixed "
            f"version {highest_fix}."
            if highest_fix
            else f" The config pins version {pinned}."
        )
        if undecidable:
            version_note += (
                f" Not counted here: {', '.join(undecidable)}, whose recorded fix "
                "uses a different version numbering scheme (calendar versus "
                "semantic), so mcp-audit cannot tell offline whether "
                f"{pinned} includes it."
            )
        severity = Severity.HIGH
    else:
        version_note = (
            " The config does not pin an exact version, so mcp-audit cannot "
            "tell offline whether the installed release is affected."
        )
        if highest_fix:
            version_note += (
                f" Every advisory listed here is fixed in {highest_fix} or later. "
                "An unpinned launch normally installs a patched release, but npx "
                "and uvx can reuse a cached older install."
            )
            severity = Severity.MEDIUM
        else:
            version_note += (
                " At least one advisory listed here has no recorded fix, so the "
                "latest release may still be affected."
            )
            severity = Severity.HIGH

    if len(affected) == 1:
        cve_id = affected[0]
        listed = cve_id
        title = f"Known CVE advisory: {entry.name} ({cve_id})"
        description = (
            f"Package {entry.name!r} has a public CVE advisory "
            f"({cve_id}) recorded in the mcp-audit known-server registry."
            f"{version_note} The full advisory is at {_advisory_url(cve_id)}."
        )
        evidence = f"package: {entry.name} | cve: {cve_id}"
    else:
        listed = ", ".join(affected[:_MAX_LISTED_CVES])
        if len(affected) > _MAX_LISTED_CVES:
            listed += (
                f" and {len(affected) - _MAX_LISTED_CVES} more"
                f" (`mcp-audit vet {entry.name}` lists them all)"
            )
        title = f"Known CVE advisories: {entry.name} ({len(affected)} CVEs)"
        description = (
            f"Package {entry.name!r} has {len(affected)} public CVE advisories "
            f"recorded in the mcp-audit known-server registry: {listed}."
            f"{version_note} Each advisory is at "
            "https://nvd.nist.gov/vuln/detail/<CVE-ID>."
        )
        evidence = f"package: {entry.name} | cves: {listed}"
    if pinned is not None:
        evidence += f" | pinned: {pinned}"
    if highest_fix:
        evidence += f" | fixed_in: {highest_fix}"
    evidence += f" | maintainer: {entry.maintainer}"

    if highest_fix:
        remediation = (
            f"Upgrade {entry.name!r} to {highest_fix} or later and pin that "
            "version in the launch command so the scan can confirm it."
        )
    else:
        remediation = (
            f"Review the advisories ({listed}) and upgrade {entry.name!r} to a "
            "patched version; if an advisory has no fix yet, consider removing "
            "the server until one ships."
        )

    return [
        Finding(
            id="SC-004",
            severity=severity,
            analyzer="supply_chain",
            client=server.client,
            server=server.name,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cwe="CWE-1104",
            owasp_mcp_top_10=["MCP04"],
            finding_path=str(server.config_path),
        )
    ]


def _undecidable_finding(
    server: ServerConfig,
    entry: RegistryEntry,
    pinned: str,
    cves: list[str],
    fixed_in: dict[str, str],
) -> Finding:
    """Build SC-009 (INFO): a pinned version that cannot be ordered against its fix.

    Emitted instead of SC-004 when every CVE left for a pinned launch has a
    recorded fix in a different numbering scheme from the pin (calendar
    versus semantic, Q-010).  The check is not dropped: the advisories are
    listed, and the user is told how to settle it.

    Args:
        server: The MCP server configuration that references this package.
        entry: Registry entry for the matched package.
        pinned: The exact version pinned in the launch command.
        cves: The advisory IDs whose fix could not be compared.
        fixed_in: Recorded fixed version per advisory ID.

    Returns:
        One SC-009 :class:`~mcp_audit.models.Finding`.
    """
    listed = ", ".join(f"{c} (fixed in {fixed_in[c]})" for c in cves)
    return Finding(
        id="SC-009",
        severity=Severity.INFO,
        analyzer="supply_chain",
        client=server.client,
        server=server.name,
        title=f"Known CVE fix not comparable with pinned version: {entry.name}",
        description=(
            f"Package {entry.name!r} has public advisories recorded in the "
            f"mcp-audit known-server registry: {listed}. The config pins "
            f"version {pinned}, which uses a different version numbering scheme "
            "from the recorded fix (calendar versions such as 2025.7.1 versus "
            "semantic versions such as 2.0.0). A package that changes scheme "
            "can publish a lower-numbered release after the fix, so mcp-audit "
            "cannot tell offline whether the pinned release is affected."
        ),
        evidence=(
            f"package: {entry.name} | cves: {', '.join(cves)} | pinned: {pinned}"
            f" | fixed_in: {', '.join(sorted({fixed_in[c] for c in cves}))}"
            f" | maintainer: {entry.maintainer}"
        ),
        remediation=(
            f"Check the release dates of {entry.name} {pinned} and of the fixed "
            "version on the package registry (npm: `npm view "
            f"{entry.name} time`), or read the advisory. If {pinned} was "
            "published after the fix, it is not affected."
        ),
        cwe="CWE-1104",
        owasp_mcp_top_10=["MCP04"],
        finding_path=str(server.config_path),
    )


_ECOSYSTEM_LABEL: dict[str, str] = {"npm": "npm", "pypi": "PyPI"}

#: What :func:`redact_args` / :func:`redact_command` put in place of a secret.
REDACTION_MARKER = "[REDACTED]"
_REDACTED = REDACTION_MARKER
# An authority (userinfo@host:port) ends at the first of these after "://".
_AUTHORITY_END = frozenset("/?#")
# Longest launch command quoted in evidence; the rest is elided.
_MAX_EVIDENCE_COMMAND = 300


def _redact_userinfo(text: str) -> str:
    """Replace the userinfo of every ``scheme://user:pass@host`` with ``[REDACTED]``.

    The authority runs from ``://`` to the first ``/``, ``?`` or ``#``; the
    userinfo is everything before the *last* ``@`` in it, so a password that
    contains ``@`` or a space (``admin:p@ss w0rd@db``) is redacted whole.
    Called once per argument, so a URL never spans two arguments.  A
    hand-written scan rather than a regex: each character is visited a
    bounded number of times, so it stays linear on any input.
    SECRET_PATTERNS' database-URL rule does not cover ``postgresql://``, the
    scheme ``@modelcontextprotocol/server-postgres`` documents.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    while True:
        j = text.find("://", i)
        if j < 0:
            out.append(text[i:])
            return "".join(out)
        k = j + 3
        end = k
        while end < n and text[end] not in _AUTHORITY_END:
            end += 1
        at = text.rfind("@", k, end)
        out.append(text[i:k])
        if at >= k:
            out.append(_REDACTED)
            i = at
        else:
            i = k


# A flag whose name contains one of these carries a secret as its value.
_SECRET_FLAG_WORDS: tuple[str, ...] = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "credential",
)


def secret_arg_values(args: list[str]) -> list[str]:
    """Return values given to secret-named flags in a launch command.

    ``--api-key VALUE``, ``--token=VALUE``, ``-password VALUE``: the flag
    name (case-insensitive) contains ``key``, ``token``, ``secret``,
    ``password``, ``passwd``, ``pwd``, ``auth`` or ``credential``.  The value
    is the text after ``=``, or the next argument when it is not itself a
    flag.  Used to redact those values from text that quotes them (STORY-0105).

    Args:
        args: The server's ``args``.

    Returns:
        The non-empty values, in argument order.
    """
    values: list[str] = []
    for i, arg in enumerate(args):
        if not arg.startswith("-"):
            continue
        name, eq, inline = arg.lstrip("-").partition("=")
        if not any(word in name.lower() for word in _SECRET_FLAG_WORDS):
            continue
        if eq:
            if inline:
                values.append(inline)
        elif i + 1 < len(args) and not args[i + 1].startswith("-"):
            values.append(args[i + 1])
    return values


def _redact_secret_flag_values(args: list[str], parts: list[str]) -> list[str]:
    """Replace the values of secret-named flags in *args* within each of *parts*.

    The values come from :func:`secret_arg_values` (``--password VALUE``,
    ``--token=VALUE``); values shorter than 4 characters are left alone so a
    flag like ``--auth on`` doesn't blank out every ``on``.
    """
    secrets = sorted(
        {v for v in secret_arg_values(args) if len(v) >= 4}, key=len, reverse=True
    )
    if not secrets:
        return parts
    out: list[str] = []
    for part in parts:
        for secret in secrets:
            part = part.replace(secret, _REDACTED)
        out.append(part)
    return out


def redact_command(command: str | None, args: list[str]) -> str:
    """Return ``command args[:4]`` for evidence, with secrets redacted.

    Launch arguments can carry credentials (a connection string, a token
    flag).  Each argument has its URL userinfo replaced with ``[REDACTED]``
    (:func:`_redact_userinfo`) and the value of every secret-named flag
    (:func:`secret_arg_values`) is replaced, then every SECRET_PATTERNS match
    in the joined string is replaced too, and the result is capped at 300
    characters (after redacting, so a cut can't expose a secret's prefix).

    Args:
        command: The server's ``command``.
        args: The server's ``args``.

    Returns:
        A redacted, length-capped command string.
    """
    parts = [_redact_userinfo(command or "")]
    parts.extend(_redact_userinfo(arg) for arg in args[:4])
    parts = _redact_secret_flag_values(list(args), parts)
    text = " ".join(part for part in parts if part)
    for _label, pattern, _provider in SECRET_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    if len(text) > _MAX_EVIDENCE_COMMAND:
        text = text[:_MAX_EVIDENCE_COMMAND] + "…"
    return text


def redact_args(args: list[str]) -> list[str]:
    """Return *args* with credentials redacted, one output item per argument.

    The serialised form of a server's launch arguments (``servers[].args`` in
    JSON scan output and snapshots, STORY-0108).  Each argument has its URL
    userinfo replaced (:func:`_redact_userinfo`) and the value of every
    secret-named flag (:func:`secret_arg_values`) replaced; then every SECRET_PATTERNS
    match in the space-joined arguments is replaced in each argument it
    overlaps, so a secret split across two arguments (``Bearer``, ``<token>``)
    is caught the way :func:`redact_command` catches it.  Unlike
    :func:`redact_command`, every argument is kept and nothing is truncated.

    Args:
        args: The server's ``args``.

    Returns:
        A new list of the same length.
    """
    cleaned = _redact_secret_flag_values(
        list(args), [_redact_userinfo(arg) for arg in args]
    )
    joined = " ".join(cleaned)
    hits: list[tuple[int, int]] = []
    for _label, pattern, _provider in SECRET_PATTERNS:
        hits.extend(
            (m.start(), m.end())
            for m in pattern.finditer(joined)
            if m.end() > m.start()
        )
    if not hits:
        return cleaned
    out: list[str] = []
    pos = 0
    for arg in cleaned:
        start, end = pos, pos + len(arg)
        pos = end + 1
        local = sorted(
            (max(hs, start) - start, min(he, end) - start)
            for hs, he in hits
            if hs < end and he > start
        )
        if not local:
            out.append(arg)
            continue
        pieces: list[str] = []
        cursor = 0
        for lo, hi in local:
            if hi <= cursor:
                continue
            lo = max(lo, cursor)
            pieces.append(arg[cursor:lo])
            pieces.append(_REDACTED)
            cursor = hi
        pieces.append(arg[cursor:])
        out.append("".join(pieces))
    return out


def redact_url(url: str | None) -> str | None:
    """Return *url* with its userinfo and any SECRET_PATTERNS match redacted.

    For a remote server's ``url`` in evidence and serialised output
    (STORY-0108); ``None`` stays ``None``.
    """
    if url is None:
        return None
    return redact_args([url])[0]


def build_twin_finding(
    server: ServerConfig,
    package: str,
    ecosystem: Literal["npm", "pypi"],
    twins: list[Twin],
) -> Finding:
    """Return the SC-007 finding for a configured unscoped twin.

    Args:
        server: The MCP server configuration that launches *package*.
        package: The configured package name (no version suffix).
        ecosystem: ``"npm"`` or ``"pypi"`` — where the launch installs from.
        twins: Non-empty output of :meth:`TwinIndex.find`, best first.

    Returns:
        One SC-007 (MEDIUM) :class:`~mcp_audit.models.Finding`.

    MEDIUM, not HIGH (coordinator decision, 2026-10-26): measured on
    2026-10-25, 6 of the 21 twin names published on npm and 2 of the 5 on
    PyPI were small live community packages, and SC-008 already reports the
    OSV-listed malicious twins at CRITICAL.
    """
    primary, others = twins[0], twins[1:]
    eco = _ECOSYSTEM_LABEL[ecosystem]
    official = primary.entry
    verified = "verified" if official.verified else "unverified"
    kind = "scoped package" if official.name.startswith("@") else "PyPI package"
    also = (
        " It is also " + "; and ".join(t.explain() for t in others) + "."
        if others
        else ""
    )
    article = "an" if eco == "npm" else "a"
    description = (
        f"This unscoped name mirrors the {kind} {official.name!r}, which the "
        f"mcp-audit registry lists (maintainer: {official.maintainer}, "
        f"{verified}): {package!r} is {primary.explain()}, and it is not in the "
        f"registry as {article} {eco} package.{also} Confirm the publisher. Some "
        "names of this shape are squats that receive installs meant for the "
        "original (in June 2026 OSV listed ten unscoped npm names like this as "
        "malicious, among them mcp-server-github, MAL-2026-5479; SC-008 reports "
        "any name OSV lists). Others are small community packages that took the "
        "known package's name. Edit-distance checks miss this because the two "
        "names differ by a scope or a naming convention, not by a few letters."
    )
    if primary.rule == "same-name":
        fix = (
            f"If you meant the PyPI package {official.name!r}, launch it with "
            f"uvx (for example `uvx {official.name}`)."
        )
    elif primary.other_ecosystem:
        fix = (
            f"If you meant the npm package {official.name!r}, launch it with "
            f"npx (for example `npx -y {official.name}`)."
        )
    else:
        fix = f"If you meant {official.name!r}, change the launch command to use it."
    others_note = (
        " | also twin of: " + ", ".join(repr(t.entry.name) for t in others)
        if others
        else ""
    )
    return Finding(
        id="SC-007",
        severity=Severity.MEDIUM,
        analyzer="supply_chain",
        client=server.client,
        server=server.name,
        title=f"Unscoped twin of a known package: {package!r}",
        description=description,
        evidence=(
            f"command: {redact_command(server.command, server.args)} | "
            f"twin of: {official.name!r} (rule={primary.rule}, "
            f"ecosystem={official.package_ecosystem}, "
            f"maintainer={official.maintainer}, verified={official.verified})"
            f"{others_note}"
        ),
        remediation=(
            f"Confirm who publishes {package!r} on {eco} and where its source "
            f"lives. {fix} If you intended the community package, allowlist it "
            "in your governance policy (`approved_servers`, see "
            "docs/governance.md) to record that choice; SC-007 still reports "
            "the name."
        ),
        cwe="CWE-829",
        owasp_mcp_top_10=["MCP04"],
        finding_path=str(server.config_path),
    )


def _affected_phrase(match: MaliciousMatch) -> str:
    """Describe which releases a match covers, in plain words."""
    record = match.record
    starts = [
        dict(events).get("introduced")
        for events in record.ranges
        if not any(kind in ("fixed", "last_affected") for kind, _ in events)
    ]
    if match.latest_affected:
        if "0" in starts or not starts or starts[0] is None:
            return "every release"
        return f"every release from {starts[0]} on"
    if record.versions:
        listed = ", ".join(record.versions[:6])
        if len(record.versions) > 6:
            listed += f" and {len(record.versions) - 6} more"
        return f"release(s) {listed}"
    return "some releases"


def build_malicious_finding(
    server: ServerConfig,
    package: str,
    ecosystem: Literal["npm", "pypi"],
    matches: list[MaliciousMatch],
    twins: list[Twin] | None = None,
) -> Finding:
    """Return the SC-008 finding for a package OSV lists as malicious.

    Severity is CRITICAL when the launch installs a listed release: it pins
    one, or OSV marks every release (or every release from some version on)
    so an unpinned launch gets one.  It is MEDIUM when only past releases are
    listed and the launch is unpinned: the registry normally removes a
    malicious release, but npx and uvx can reuse a cached copy (the same
    reasoning as SC-004's unpinned MEDIUM).

    Args:
        server: The MCP server configuration that launches *package*.
        package: The configured package name (no version suffix).
        ecosystem: ``"npm"`` or ``"pypi"``.
        matches: Non-empty list of :func:`~mcp_audit.registry.malicious.assess`
            results for this package.
        twins: SC-007 twins of *package*, used only to name the package the
            user probably meant.

    Returns:
        One SC-008 :class:`~mcp_audit.models.Finding`.
    """
    eco = _ECOSYSTEM_LABEL[ecosystem]
    ids = [m.record.id for m in matches]
    id_list = ", ".join(ids)
    critical = any(m.affects_this_launch for m in matches)
    pinned = matches[0].pinned
    first = matches[0].record

    if pinned is not None:
        launch = f" The config pins version {pinned}, which the record covers."
    elif critical:
        latest = next(m for m in matches if m.latest_affected)
        launch = (
            f" OSV marks {_affected_phrase(latest)} as affected, so whatever an "
            "unpinned launch installs is covered."
        )
    else:
        launch = (
            f" OSV lists {_affected_phrase(matches[0])}. The config does not pin a "
            "version, so mcp-audit cannot tell offline which release this launch "
            "installs. A registry normally removes a malicious release, but npx "
            "and uvx can reuse a cached copy."
        )
    curated_note = ""
    if any(m.blanket_range_ignored for m in matches):
        curated_note = (
            " The record also carries a range covering every version; mcp-audit's "
            "registry lists this package as legitimate, so the record's explicit "
            "version list is used instead."
        )
    notes = []
    for m in matches:
        if m.record.note and m.record.note not in notes:
            notes.append(m.record.note)
    note_text = "".join(f" Note: {n}" for n in notes)
    aliases = sorted({a for m in matches for a in m.record.aliases})

    description = (
        f"OSV lists the {eco} package {package!r} as malicious ({id_list}"
        + (f"; aliases {', '.join(aliases)}" if aliases else "")
        + ")"
        + (f": {first.summary!r}." if first.summary else ".")
        + launch
        + curated_note
        + note_text
    )
    meant = ""
    if twins:
        meant = f" If you meant {twins[0].entry.name!r}, launch that instead."
    if critical:
        remediation = (
            f"Remove this server from the config and do not install {package!r}."
            f"{meant} If the package was installed or run on this machine, follow "
            f"the advisory at {first.link}."
        )
        severity = Severity.CRITICAL
    else:
        remediation = (
            f"Pin {package!r} to a release the record does not list, so the scan "
            "can confirm it, and clear any cached copy of the listed releases "
            f"(advisory: {first.link})."
        )
        severity = Severity.MEDIUM

    evidence = f"package: {package} | ecosystem: {eco} | osv: {id_list}"
    if aliases:
        evidence += f" | aliases: {', '.join(aliases)}"
    if pinned is not None:
        evidence += f" | pinned: {pinned}"
    return Finding(
        id="SC-008",
        severity=severity,
        analyzer="supply_chain",
        client=server.client,
        server=server.name,
        # The MEDIUM case is a package with malicious *past* releases (often a
        # real package whose release was compromised), so it must not read as
        # "this package is malware".
        title=(
            f"Known malicious package: {package} ({id_list})"
            if critical
            else f"Malicious releases listed in OSV: {package} ({id_list})"
        ),
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe="CWE-506",
        owasp_mcp_top_10=["MCP04"],
        finding_path=str(server.config_path),
    )


def build_deprecated_package_finding(
    *,
    client: str,
    server: str,
    config_path: str,
    package: dict,
) -> Finding | None:
    """Return an SC-005 finding when *package* carries a deprecation notice.

    Shared builder (STORY-0073/R58) for the two call sites that can see a
    freshly network-resolved ``package`` dict carrying a non-null
    ``deprecated``: the ``lock`` write path (``cli/lock.py``, iterating a
    just-regenerated ``mcp-lock.json`` document) and ``lock --verify
    --resolve`` (``lock/verifier.py``, re-resolving each locked entry).
    Deliberately **not** wired into ``vet --online`` or ``scan
    --check-vulns`` — that is STORY-0074 (icebox, post-window); see
    ``GAPS.md``.

    Args:
        client: The MCP client name (e.g. ``"cursor"``).
        server: The MCP server name as configured (``Finding.server``).
        config_path: Path to the config file, for ``Finding.finding_path``.
        package: A lock ``package`` sub-object (or equivalent dict)
            carrying at least ``name``, ``resolved_version``, and
            ``deprecated``.

    Returns:
        One SC-005 (MEDIUM) :class:`~mcp_audit.models.Finding`, or ``None``
        when ``package["deprecated"]`` is falsy/absent.
    """
    deprecated = package.get("deprecated")
    if not deprecated:
        return None

    pkg_name = package.get("name", "")
    version = package.get("resolved_version") or "unknown"

    return Finding(
        id="SC-005",
        severity=Severity.MEDIUM,
        analyzer="supply_chain",
        client=client,
        server=server,
        title=f"Deprecated package: {pkg_name} ({version})",
        description=(
            f"Package {pkg_name!r} version {version} is marked deprecated "
            f"by its registry: {deprecated!r}. A deprecated package may be "
            "unmaintained, superseded, or withdrawn without further "
            "security patches."
        ),
        evidence=(
            f"package: {pkg_name} | version: {version} | deprecated: {deprecated}"
        ),
        remediation=(
            f"Check {pkg_name!r}'s registry page for a maintained "
            "replacement and migrate off the deprecated package/version."
        ),
        owasp_mcp_top_10=["MCP04"],
        finding_path=config_path,
    )


class SupplyChainAnalyzer(BaseAnalyzer):
    """Detect typosquatting of known-legitimate MCP npm and PyPI packages.

    For each server that invokes a package-manager command, the analyzer:

    1. Extracts the package name from the argument list.
    2. Skips it if it matches a known-good package exactly (via registry).
    3. Finds the closest registry entry by Levenshtein distance.
    4. Emits a finding if the distance is ≤ threshold, with severity scaled
       to proximity.

    Supported package managers:
    - npm ecosystem: ``npx``, ``bunx``, ``pnpx``, ``yarn dlx``
    - Python ecosystem: ``uvx``, ``pipx``, ``python -m``

    Name findings, at most one per server: SC-004 for an exact registry
    match with CVEs, else SC-007 for an unscoped twin, else SC-001..003 by
    edit distance.  SC-008 (known malicious, OSV ``MAL-*``) is added on top.
    """

    def __init__(
        self,
        registry: KnownServerRegistry | None = None,
        registry_path: Path | None = None,
        offline_registry: bool = False,
        malicious: KnownMaliciousPackages | None = None,
        malicious_path: Path | None = None,
    ) -> None:
        """Initialise the analyzer with an optional pre-loaded registry.

        Args:
            registry: Pre-built :class:`~mcp_audit.registry.loader.KnownServerRegistry`
                instance.  When supplied, *registry_path* and *offline_registry*
                are both ignored.
            registry_path: Path to a custom registry JSON file.  Falls back to
                the user-cached or bundled registry when ``None``.
            offline_registry: When ``True``, skip the user-local cache and load
                from the bundled registry only.  Ignored when *registry* or
                *registry_path* is supplied.
            malicious: Pre-built known-malicious index (tests).  When ``None``
                the bundled ``known-malicious.json`` is loaded.
            malicious_path: Path to a custom ``known-malicious.json``.
                Ignored when *malicious* is supplied.
        """
        if registry is not None:
            self._registry = registry
        else:
            self._registry = load_registry(registry_path, offline=offline_registry)
        self._twins: TwinIndex | None = None
        self._malicious: KnownMaliciousPackages | None = malicious
        self._malicious_path = malicious_path

    @property
    def registry(self) -> KnownServerRegistry:
        """The registry instance used by this analyzer."""
        return self._registry

    @property
    def malicious(self) -> KnownMaliciousPackages:
        """The known-malicious index used by this analyzer (SC-008).

        Loaded on first use (the bundled file unless a path or index was
        given), so an analyzer built without ``__init__`` still works.
        """
        malicious = getattr(self, "_malicious", None)
        if malicious is None:
            malicious = load_known_malicious(getattr(self, "_malicious_path", None))
            self._malicious = malicious
        return malicious

    @property
    def twins(self) -> TwinIndex:
        """The unscoped-twin index built from :attr:`registry` (SC-007)."""
        twins = getattr(self, "_twins", None)
        if twins is None:
            twins = TwinIndex(self._registry)
            self._twins = twins
        return twins

    @property
    def name(self) -> str:
        return "supply_chain"

    @property
    def description(self) -> str:
        return "Detect typosquatting of known-legitimate MCP npm and PyPI packages"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """Analyze a server config for supply-chain typosquatting and known CVEs.

        Dispatches to the npm or Python detection path based on the command
        field.  Both paths apply the same Levenshtein threshold logic and
        produce findings with the same SC-00x IDs.  Exact registry matches are
        further checked for ``known_vulnerabilities`` entries (SC-004).

        Args:
            server: The MCP server configuration to analyze.

        Returns:
            List of :class:`~mcp_audit.models.Finding` objects (empty if clean).
        """
        # Any spelling of the launcher: a path, a Windows .cmd/.exe wrapper,
        # or `cmd /c <launcher> …` (STORY-0097 review).
        launcher, launch_args = normalize_launch(server.command, server.args)

        # Python ecosystem: uvx, pipx, python -m (any interpreter spelling)
        if launcher in _PYPI_LIKE or _is_python_interpreter(launcher):
            findings = self._check_pypi_typosquatting(server)
            package = extract_pypi_package(launcher, launch_args)
            if package is not None:
                findings.extend(self._check_known_malicious(server, "pypi", package))
            return findings

        # npm ecosystem: npx / bunx / pnpx / yarn dlx
        # ``yarn dlx <pkg>`` is semantically identical to ``npx <pkg>`` for
        # typosquatting purposes; normalise it before the command gate.
        if launcher == "yarn":
            if not launch_args or launch_args[0] != "dlx":
                return []
            effective_args = launch_args[1:]
        elif launcher in _NPX_LIKE:
            effective_args = launch_args
        else:
            return []

        spec = extract_npm_package(effective_args)
        if spec is None:
            return []
        # A pinned spec (``@scope/pkg@1.2.3``) must match its registry entry
        # by name; before STORY-0078 a pin silently skipped every check here.
        package = strip_npm_version_suffix(spec)
        findings = self._check_npm_name(server, package)
        findings.extend(self._check_known_malicious(server, "npm", package))
        return findings

    def _check_known_malicious(
        self,
        server: ServerConfig,
        ecosystem: Literal["npm", "pypi"],
        package: str,
    ) -> list[Finding]:
        """Return SC-008 when *package* is an OSV ``MAL-*`` record (exact name).

        Args:
            server: The MCP server configuration to analyse.
            ecosystem: ``"npm"`` or ``"pypi"`` — where the launch installs from.
            package: The configured package name, version suffix stripped.

        Returns:
            A list with at most one SC-008 finding.
        """
        records = self.malicious.lookup(ecosystem, package)
        if not records:
            return []
        curated = (
            self._registry.is_known_npm(package)
            if ecosystem == "npm"
            else self._registry.is_known_pypi(package)
        )
        pinned = _pinned_version(server)
        matches = [
            m
            for m in (assess(r, pinned, curated=curated) for r in records)
            if m is not None
        ]
        if not matches:
            return []
        twins = self.twins.find(package, ecosystem)
        return [build_malicious_finding(server, package, ecosystem, matches, twins)]

    def _check_npm_name(self, server: ServerConfig, package: str) -> list[Finding]:
        """Run the npm name checks: SC-004, then SC-007, then SC-001..003.

        Args:
            server: The MCP server configuration to analyse.
            package: The configured npm package name, version suffix stripped.

        Returns:
            At most one name finding.
        """
        if self._registry.is_known_npm(package):
            entry = self._registry.get_npm(package)
            if entry and (entry.known_vulnerabilities or entry.known_vulns):
                return _emit_known_cve_findings(server, entry)
            return []

        twins = self.twins.find(package, "npm")
        if twins:
            return [build_twin_finding(server, package, "npm", twins)]

        # Short names (≤5 chars) are too close to almost any other short name
        # at distance 3, producing high FP rates. Use a tighter threshold of 1
        # for those; long names keep the standard threshold of 3.
        typo_threshold = 1 if len(package) <= 5 else 3
        closest_entry = self._registry.find_closest_npm(
            package, threshold=typo_threshold
        )

        if closest_entry is None:
            return []

        # Compute actual distance so severity mapping stays accurate.
        min_dist = levenshtein(package, closest_entry.name.lower())
        severity, finding_id = _severity_for_distance(min_dist)

        verified_label = "verified" if closest_entry.verified else "unverified"

        # Optional provenance metadata surfaced in the description to help
        # analysts quickly distinguish suspicious newcomers from established
        # packages with a long publish history.
        meta_parts: list[str] = []
        if closest_entry.first_published:
            meta_parts.append(f"first published {closest_entry.first_published}")
        if closest_entry.weekly_downloads is not None:
            meta_parts.append(f"~{closest_entry.weekly_downloads:,} weekly downloads")
        meta_blurb = f"; {'; '.join(meta_parts)}" if meta_parts else ""

        return [
            Finding(
                id=finding_id,
                severity=severity,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title=f"Possible typosquatting: {package!r}",
                description=(
                    f"Package {package!r} is {min_dist} edit(s) away from the "
                    f"known-legitimate package {closest_entry.name!r} "
                    f"(maintainer: {closest_entry.maintainer}, {verified_label}"
                    f"{meta_blurb})."
                    " This pattern is consistent with a typosquatting"
                    " supply-chain attack."
                ),
                evidence=(
                    f"command: {redact_command(server.command, server.args)} | "
                    f"closest: {closest_entry.name!r} (maintainer="
                    f"{closest_entry.maintainer},"
                    f" verified={closest_entry.verified})"
                ),
                remediation=(
                    f"Verify {package!r} is intentional. "
                    f"If you meant {closest_entry.name!r}, "
                    "correct the configuration. Inspect the package's npm page"
                    " and source repository before trusting it."
                ),
                cwe="CWE-829",
                owasp_mcp_top_10=["MCP04"],
            )
        ]

    def _check_pypi_typosquatting(self, server: ServerConfig) -> list[Finding]:
        """Run the Python-ecosystem typosquat check for *server*.

        Extracts the package name from uvx / pipx / ``python -m`` invocations,
        checks it against the PyPI sub-index of the known-server registry, and
        emits a finding if the name is suspiciously close to a known-good entry.

        Args:
            server: The MCP server configuration to analyse.

        Returns:
            List of :class:`~mcp_audit.models.Finding` objects (empty if clean).
        """
        package = extract_pypi_package(server.command or "", server.args)
        if package is None:
            return []

        if self._registry.is_known_pypi(package):
            entry = self._registry.get_pypi(package)
            if entry and (entry.known_vulnerabilities or entry.known_vulns):
                return _emit_known_cve_findings(server, entry)
            return []

        twins = self.twins.find(package, "pypi")
        if twins:
            return [build_twin_finding(server, package, "pypi", twins)]

        typo_threshold = 1 if len(package) <= 5 else 3
        closest_entry = self._registry.find_closest_pypi(
            package, threshold=typo_threshold
        )
        if closest_entry is None:
            return []

        min_dist = levenshtein(package, normalize_pypi_name(closest_entry.name))
        severity, finding_id = _severity_for_distance(min_dist)

        verified_label = "verified" if closest_entry.verified else "unverified"

        meta_parts: list[str] = []
        if closest_entry.first_published:
            meta_parts.append(f"first published {closest_entry.first_published}")
        if closest_entry.weekly_downloads is not None:
            meta_parts.append(f"~{closest_entry.weekly_downloads:,} weekly downloads")
        meta_blurb = f"; {'; '.join(meta_parts)}" if meta_parts else ""

        return [
            Finding(
                id=finding_id,
                severity=severity,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title=f"Possible Python package typosquat: {package!r}",
                description=(
                    f"Python package {package!r} is {min_dist} edit(s) away from the "
                    f"known-legitimate package {closest_entry.name!r} "
                    f"(maintainer: {closest_entry.maintainer}, {verified_label}"
                    f"{meta_blurb})."
                    " This pattern is consistent with a typosquatting"
                    " supply-chain attack targeting Python MCP packages."
                ),
                evidence=(
                    f"command: {redact_command(server.command, server.args)} | "
                    f"closest: {closest_entry.name!r} (maintainer="
                    f"{closest_entry.maintainer},"
                    f" verified={closest_entry.verified})"
                ),
                remediation=(
                    f"Verify {package!r} is intentional. "
                    f"If you meant {closest_entry.name!r}, "
                    "correct the configuration. Check the package's PyPI page"
                    " and source repository before trusting it."
                ),
                cwe="CWE-829",
                owasp_mcp_top_10=["MCP04"],
            )
        ]


# ── Private helpers ────────────────────────────────────────────────────────────


def _severity_for_distance(distance: int) -> tuple[Severity, str]:
    """Map a Levenshtein distance to a (Severity, finding_id) pair.

    Args:
        distance: Edit distance to the nearest known-good package (1–3).

    Returns:
        Tuple of severity and finding ID string.
    """
    if distance == 1:
        return Severity.CRITICAL, "SC-001"
    if distance == 2:
        return Severity.HIGH, "SC-002"
    return Severity.MEDIUM, "SC-003"
