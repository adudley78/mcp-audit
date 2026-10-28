"""Credential files a Claude Code session can read without asking (REACH-001..003).

STORY-0114 (queue Q-003).  Privacy design: ``humans/decisions``
``2026-10-28-secrets-reach.md`` (marcus repo).

**What this module never does.**  It never opens a credential store: every
store is looked at with ``stat()`` only (exists, regular file, size, mode
bits), so no secret value is ever loaded into memory.  It never lists the
home directory or ``~/.ssh``; the store paths are a fixed list.  The only
directory it lists is the working directory's root, by entry name, to find
``.env`` files.  It never writes, sends or runs anything, and its findings
show paths as ``~/...`` (no username) or as a bare file name.

**What it reads.**  The JSON of the Claude Code settings files a session in
this directory loads: managed (``managed-settings.json`` and
``managed-settings.d/*.json``), user (``settings.json`` in
``$CLAUDE_CONFIG_DIR`` or ``~/.claude``), and the working directory's
``.claude/settings.json`` and ``.claude/settings.local.json`` — 1 MiB per
file, 256 drop-ins, 8 MiB per scan.  Only the keys that decide whether a path
is readable are consulted.

**Why it matters** (code.claude.com/docs, fetched 2026-10-28):

- permissions doc, "Read-only commands": Claude Code "runs them without a
  permission prompt in every mode, except as
  ``permissions.blockReadsOutsideWorkingDirectories`` changes for paths
  outside your working directories. The set includes ``ls``, ``cat`` ...
  ``head``, ``tail``".
- sandboxing doc: the sandbox's default read access is "Most of the machine,
  including credential files such as ``~/.ssh`` and ``~/.aws/credentials``";
  "There is no built-in credential deny list".
- permissions doc, "Read and Edit": "Read and Edit deny rules apply to
  Claude's built-in file tools, to file commands Claude Code recognizes in
  Bash, such as ``cat``, ``head``, ``tail``".  The permission table: file
  reads need no approval "within the working directory and additional
  directories".

So a path is *covered* when a ``Read`` deny rule matches it (or the file it
resolves to), when ``blockReadsOutsideWorkingDirectories`` is ``true`` in any
file and the path is outside the working directory, or when the sandbox is
enabled and ``sandbox.filesystem.denyRead`` / a ``sandbox.credentials.files``
``deny`` entry covers it (the Read tool still prompts for a path outside the
working directory).  Rules are merged across the files, as Claude Code merges
deny rules.

Findings:

- **REACH-001** (LOW): well-known credential stores under the home directory
  that no rule covers — one finding listing them.
- **REACH-002** (MEDIUM): Claude Code's own login store,
  ``.credentials.json``, readable by another local account (POSIX mode bits).
- **REACH-003** (LOW): ``.env`` files at the working directory's root that no
  ``Read`` deny rule covers.

All three run only in a default scan (no explicit path) and only when a
Claude Code config directory exists.  :func:`secret_reach_findings` never
raises; problems go to the caller's ``errors``.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from mcp_audit.analyzers.permissions import parse_permission_rule
from mcp_audit.models import Finding, Severity

ANALYZER = "secret_reach"
CLIENT = "claude-code"

#: Largest settings file read, and the per-call byte and drop-in budgets.
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_DROPINS = 256

#: Bounds on rule text so matching stays cheap on hostile settings files.
_MAX_RULES_PER_FILE = 4096
_MAX_PATTERN_CHARS = 4096
_MAX_PATTERN_SEGMENTS = 128
_MAX_SEGMENT_CHARS = 512

#: Cwd-root entries examined for ``.env`` names.
_MAX_ROOT_ENTRIES = 10_000

_PERMISSIONS_DOC = "https://code.claude.com/docs/en/permissions#read-and-edit"
_SANDBOX_DOC = "https://code.claude.com/docs/en/sandboxing#protect-credentials"
_AUTH_DOC = "https://code.claude.com/docs/en/authentication"


@dataclass(frozen=True)
class SecretStore:
    """One well-known credential store under the home directory.

    Attributes:
        rel: Path relative to the home directory, POSIX separators.
        label: What it holds, for finding text.
        certain: ``True`` when the file exists only to hold a credential;
            ``False`` when it may or may not hold one (a config file with an
            optional token).
        platforms: ``"posix"``, ``"windows"`` or ``"any"``.
    """

    rel: str
    label: str
    certain: bool
    platforms: str = "any"


#: Every path, and what it holds, is from the tool's own documentation
#: (PROVENANCE.md, STORY-0114).  Fixed list: nothing else under home is read.
HOME_STORES: tuple[SecretStore, ...] = (
    # ssh-keygen(1) FILES: the default private key names.
    SecretStore(".ssh/id_rsa", "SSH private key", True),
    SecretStore(".ssh/id_ecdsa", "SSH private key", True),
    SecretStore(".ssh/id_ecdsa_sk", "SSH private key (security key)", True),
    SecretStore(".ssh/id_ed25519", "SSH private key", True),
    SecretStore(".ssh/id_ed25519_sk", "SSH private key (security key)", True),
    # AWS CLI: "a local file named credentials, in a folder named .aws".
    SecretStore(".aws/credentials", "AWS credentials", True),
    # Google Cloud application default credentials (user credentials file).
    SecretStore(
        ".config/gcloud/application_default_credentials.json",
        "Google Cloud application default credentials",
        True,
        "posix",
    ),
    SecretStore(
        "AppData/Roaming/gcloud/application_default_credentials.json",
        "Google Cloud application default credentials",
        True,
        "windows",
    ),
    # git-credential-store(1): plain-text credentials in ~/.git-credentials.
    SecretStore(".git-credentials", "git stored credentials", True),
    # curl / netrc(5); Windows also checks _netrc.
    SecretStore(".netrc", "netrc login credentials", True),
    SecretStore("_netrc", "netrc login credentials", True, "windows"),
    # PyPA .pypirc specification: index passwords / API tokens.
    SecretStore(".pypirc", "Python package index credentials", True),
    # Claude Code authentication doc: the login store on Linux/Windows (and
    # macOS when the Keychain rejects the write).
    SecretStore(".claude/.credentials.json", "Claude Code login", True),
    # May hold a token, depending on how the tool was set up.
    SecretStore(".npmrc", "npm config (may hold an auth token)", False),
    SecretStore(".docker/config.json", "Docker config (may hold registry auth)", False),
    SecretStore(".kube/config", "kubeconfig (may hold cluster credentials)", False),
    SecretStore(
        ".config/gh/hosts.yml", "GitHub CLI hosts (may hold a token)", False, "posix"
    ),
)

#: ``.env`` file names at the cwd root; template suffixes never hold secrets.
_ENV_NAME_RE = re.compile(r"^\.env(?:\.[A-Za-z0-9_-]{1,64}){0,4}$")
_ENV_TEMPLATE_PARTS = frozenset(
    {"example", "examples", "sample", "template", "tmpl", "dist", "defaults", "schema"}
)

_ON_WINDOWS = sys.platform.startswith("win")


# ── Settings ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SettingsSource:
    """One settings file a session in this directory loads.

    Attributes:
        path: The file.
        scope: ``"managed"``, ``"user"``, ``"project"`` or ``"local"``.
        data: Its parsed JSON object.
    """

    path: Path
    scope: str
    data: dict


@dataclass
class _Budget:
    remaining: int = MAX_TOTAL_BYTES


def _label(path: Path, home: Path) -> str:
    """``~/...`` for a path under *home*, else the bare file name."""
    try:
        return "~/" + path.relative_to(home).as_posix()
    except ValueError:
        return path.name


def _read_settings(
    path: Path, budget: _Budget, errors: list[str], home: Path
) -> dict | None:
    """Parse one settings file, or ``None`` (reason to *errors*).  Never raises."""
    label = _label(path, home)
    try:
        if not path.is_file():
            return None
        with path.open("rb") as handle:
            data = handle.read(min(MAX_FILE_BYTES, budget.remaining) + 1)
    except OSError as exc:
        errors.append(
            f"secret reach: cannot read {label}: {exc.strerror or type(exc).__name__}"
        )
        return None
    if len(data) > MAX_FILE_BYTES or len(data) > budget.remaining:
        errors.append(
            f"secret reach: {label} is over the read limit; its rules were not counted"
        )
        return None
    budget.remaining -= len(data)
    try:
        raw = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError):
        # Claude Code skips a broken settings file, so it protects nothing.
        return None
    return raw if isinstance(raw, dict) else None


def _same_file(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except (OSError, RuntimeError):
        return a == b


def load_settings_sources(
    cwd: Path,
    home: Path,
    config_dir: Path,
    managed_dir: Path | None,
    errors: list[str],
) -> list[SettingsSource]:
    """Read every settings file a Claude Code session started in *cwd* loads.

    A project file that is the same file as the user file (the scan runs in
    the home directory) is read once, as the user file.  Never raises.
    """
    budget = _Budget()
    sources: list[SettingsSource] = []
    seen: list[Path] = []

    def add(path: Path, scope: str) -> None:
        if any(_same_file(path, other) for other in seen):
            return
        data = _read_settings(path, budget, errors, home)
        if data is not None:
            seen.append(path)
            sources.append(SettingsSource(path, scope, data))

    if managed_dir is not None:
        add(managed_dir / "managed-settings.json", "managed")
        dropin_dir = managed_dir / "managed-settings.d"
        try:
            dropins = (
                sorted(p for p in dropin_dir.glob("*.json"))
                if dropin_dir.is_dir()
                else []
            )
        except OSError as exc:
            errors.append(
                f"secret reach: cannot list managed-settings.d: {type(exc).__name__}"
            )
            dropins = []
        if len(dropins) > MAX_DROPINS:
            errors.append(
                f"secret reach: more than {MAX_DROPINS} managed drop-in files;"
                " the rest were not read"
            )
        for path in dropins[:MAX_DROPINS]:
            add(path, "managed")
    add(config_dir / "settings.json", "user")
    add(cwd / ".claude" / "settings.json", "project")
    add(cwd / ".claude" / "settings.local.json", "local")
    return sources


# ── Path patterns ─────────────────────────────────────────────────────────────


def _posix(path: Path) -> PurePosixPath:
    """*path* in the POSIX form Claude Code matches rules against.

    Permissions doc: "On Windows, paths are normalized to POSIX form before
    matching. ``C:\\Users\\alice`` becomes ``/c/Users/alice``".
    """
    text = str(path)
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        rest = text[2:].replace("\\", "/")
        return PurePosixPath("/" + text[0].lower() + rest)
    return PurePosixPath(text.replace("\\", "/") if _ON_WINDOWS else text)


def _segments(pattern: str) -> list[str] | None:
    parts = [p for p in pattern.split("/") if p not in ("", ".")]
    if len(parts) > _MAX_PATTERN_SEGMENTS or any(
        len(p) > _MAX_SEGMENT_CHARS for p in parts
    ):
        return None
    return parts


def _match_segments(pattern: list[str], path: tuple[str, ...]) -> bool:
    """gitignore-style whole-path match; ``**`` spans segments, ``*`` does not.

    Dynamic programming over (pattern index, path index): O(len(pattern) *
    len(path)) segment comparisons, never backtracking.
    """
    n, m = len(pattern), len(path)
    # reach[j] is True when pattern[:i] can match path[:j].
    reach = [False] * (m + 1)
    reach[0] = True
    for i in range(n):
        seg = pattern[i]
        nxt = [False] * (m + 1)
        if seg == "**":
            running = False
            for j in range(m + 1):
                running = running or reach[j]
                nxt[j] = running
        else:
            for j in range(m):
                if reach[j] and fnmatchcase(path[j], seg):
                    nxt[j + 1] = True
        reach = nxt
        if not any(reach):
            return False
    return reach[m]


def _covers(anchor: PurePosixPath, pattern: list[str], target: PurePosixPath) -> bool:
    """True when *anchor*/*pattern* matches *target* or a directory above it.

    A pattern that matches a directory covers everything under it, as in
    gitignore (permissions doc: rules "use gitignore pattern syntax").
    """
    try:
        rel = target.relative_to(anchor)
    except ValueError:
        return False
    parts = rel.parts
    return any(_match_segments(pattern, parts[:k]) for k in range(1, len(parts) + 1))


@dataclass(frozen=True)
class _ReadRule:
    """A ``Read`` deny rule reduced to an anchor and pattern segments."""

    anchor: PurePosixPath
    pattern: tuple[str, ...]
    negated: bool
    source_index: int
    everything: bool = False
    relative: bool = False


def _read_rule(
    text: str, source: SettingsSource, index: int, cwd: Path, home: Path
) -> _ReadRule | None:
    """Turn one deny-list entry into a :class:`_ReadRule`, or ``None``.

    Permissions doc, "Read and Edit": ``//path`` is absolute, ``~/path`` is
    from home, ``/path`` is relative to the settings source (project and local
    settings: the primary working directory; user settings: ``~/.claude``),
    ``path`` or ``./path`` is relative to the current directory, and a bare
    file name or single-directory deny pattern matches at any depth below it.
    A managed file's ``/path`` anchoring is not documented, so it is not
    counted.
    """
    rule = parse_permission_rule(text, "deny")
    if rule is None or len(rule.text) > _MAX_PATTERN_CHARS:
        return None
    if not fnmatchcase("Read", rule.tool):
        return None
    if rule.specifier is None:
        # A bare tool name denies every use of the tool.
        return _ReadRule(PurePosixPath("/"), (), False, index, everything=True)
    spec = rule.specifier.strip()
    if not spec or spec == "!":
        return None
    negated = spec.startswith("!")
    if negated:
        # "Claude Code reads a ! pattern relative to the current directory even
        # when /, ~/, or // follows the !", so it is always a relative pattern.
        spec = spec[1:]
    relative = negated or not spec.startswith(("/", "~/"))
    if relative:
        anchor = _posix(cwd)
        rest = spec[2:] if spec.startswith("./") else spec.lstrip("/")
        if rest.startswith("~/"):
            rest = rest[2:]
        trimmed = rest.rstrip("/")
        if trimmed.endswith("/**"):
            trimmed = trimmed[:-3]
        # A bare name, or one directory segment, matches at any depth.
        if "/" not in trimmed and not rest.startswith("**"):
            rest = "**/" + rest
    elif spec.startswith("//"):
        anchor, rest = PurePosixPath("/"), spec[2:]
    elif spec.startswith("~/"):
        anchor, rest = _posix(home), spec[2:]
    elif spec.startswith("/"):
        if source.scope == "user":
            anchor = _posix(source.path.parent)
        elif source.scope in ("project", "local"):
            anchor = _posix(cwd)
        else:
            return None
        rest = spec[1:]
    parts = _segments(rest)
    if parts is None:
        return None
    return _ReadRule(
        anchor, tuple(parts) if parts else ("**",), negated, index, relative=relative
    )


def _sandbox_path(
    entry: str, source: SettingsSource, home: Path
) -> PurePosixPath | None:
    """Resolve a sandbox path entry (settings reference, "Sandbox path prefixes").

    ``/`` and ``//`` are absolute, ``~/`` is home, ``./`` or no prefix is the
    project root for project settings and ``~/.claude`` for user settings.  A
    trailing slash is stripped.
    """
    text = entry.strip().rstrip("/")
    if not text or len(text) > _MAX_PATTERN_CHARS:
        return None
    if text.startswith("~/"):
        return _posix(home) / text[2:]
    if text == "~":
        return _posix(home)
    if text.startswith("/"):
        return PurePosixPath("/" + text.lstrip("/"))
    base: Path | None
    if source.scope == "user":
        base = source.path.parent
    elif source.scope in ("project", "local"):
        base = source.path.parent.parent
    else:
        base = None
    if base is None:
        return None
    return _posix(base) / (text[2:] if text.startswith("./") else text)


@dataclass
class Protection:
    """What the loaded settings files do to reads, merged across files."""

    read_rules: list[_ReadRule] = field(default_factory=list)
    block_outside_cwd: bool = False
    sandbox_enabled: bool = False
    sandbox_fs_disabled: bool = False
    sandbox_deny: list[tuple[PurePosixPath, tuple[str, ...]]] = field(
        default_factory=list
    )

    def read_rule_covers(self, target: PurePosixPath) -> bool:
        """A ``Read`` deny rule covers *target* and no ``!`` rule reopens it.

        Permissions doc: a ``!`` pattern "carves the paths it matches out of the
        ``path`` or ``./path`` rules listed before it", from the same source only.
        """
        for i, rule in enumerate(self.read_rules):
            if rule.negated:
                continue
            covered = rule.everything or _covers(
                rule.anchor, list(rule.pattern), target
            )
            if not covered:
                continue
            carved = rule.relative and any(
                later.negated
                and later.source_index == rule.source_index
                and _covers(later.anchor, list(later.pattern), target)
                for later in self.read_rules[i + 1 :]
            )
            if not carved:
                return True
        return False

    def sandbox_covers(self, target: PurePosixPath) -> bool:
        """The sandbox is on and a ``denyRead``/credentials entry covers *target*."""
        if not self.sandbox_enabled or self.sandbox_fs_disabled:
            return False
        for anchor, pattern in self.sandbox_deny:
            if not pattern:
                if target == anchor or anchor in target.parents:
                    return True
            elif _covers(anchor, list(pattern), target):
                return True
        return False


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def _dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def build_protection(
    sources: Iterable[SettingsSource], cwd: Path, home: Path
) -> Protection:
    """Merge the read-relevant keys of *sources* into one :class:`Protection`."""
    protection = Protection()
    for index, source in enumerate(sources):
        permissions = _dict(source.data.get("permissions"))
        for entry in _list(permissions.get("deny"))[:_MAX_RULES_PER_FILE]:
            if isinstance(entry, str):
                rule = _read_rule(entry, source, index, cwd, home)
                if rule is not None:
                    protection.read_rules.append(rule)
        if permissions.get("blockReadsOutsideWorkingDirectories") is True:
            protection.block_outside_cwd = True
        sandbox = _dict(source.data.get("sandbox"))
        if sandbox.get("enabled") is True:
            protection.sandbox_enabled = True
        filesystem = _dict(sandbox.get("filesystem"))
        if filesystem.get("disabled") is True:
            protection.sandbox_fs_disabled = True
        entries: list[str] = [
            e for e in _list(filesystem.get("denyRead")) if isinstance(e, str)
        ]
        for item in _list(_dict(sandbox.get("credentials")).get("files")):
            item = _dict(item)
            if item.get("mode") == "deny" and isinstance(item.get("path"), str):
                entries.append(item["path"])
        for entry in entries[:_MAX_RULES_PER_FILE]:
            resolved = _sandbox_path(entry, source, home)
            if resolved is None:
                continue
            if any(ch in resolved.as_posix() for ch in "*?["):
                parts = _segments(resolved.as_posix())
                if parts is not None:
                    protection.sandbox_deny.append((PurePosixPath("/"), tuple(parts)))
            else:
                protection.sandbox_deny.append((resolved, ()))
    return protection


# ── Stores ────────────────────────────────────────────────────────────────────


def _stat_store(path: Path) -> os.stat_result | None:
    """``stat()`` of a non-empty regular file at *path*, else ``None``; never opened."""
    try:
        st = path.stat()
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
        return None
    return st


def _resolved(path: Path) -> PurePosixPath | None:
    try:
        return _posix(path.resolve())
    except (OSError, RuntimeError):
        return None


def _inside(path: PurePosixPath, root: PurePosixPath) -> bool:
    return path == root or root in path.parents


def _store_applies(store: SecretStore) -> bool:
    if store.platforms == "windows":
        return _ON_WINDOWS
    if store.platforms == "posix":
        return not _ON_WINDOWS
    return True


def _home_store_rel(store: SecretStore, home: Path, config_dir: Path) -> Path:
    """The store's path; Claude Code's own login store follows ``CLAUDE_CONFIG_DIR``."""
    if store.rel == ".claude/.credentials.json":
        return config_dir / ".credentials.json"
    return home / store.rel


def _uncovered_home_stores(
    protection: Protection, cwd: Path, home: Path, config_dir: Path
) -> list[tuple[SecretStore, Path]]:
    cwd_posix = _posix(cwd)
    hits: list[tuple[SecretStore, Path]] = []
    for store in HOME_STORES:
        if not _store_applies(store):
            continue
        path = _home_store_rel(store, home, config_dir)
        if _stat_store(path) is None:
            continue
        targets = [_posix(path)]
        real = _resolved(path)
        if real is not None and real != targets[0]:
            targets.append(real)
        if any(protection.read_rule_covers(t) for t in targets):
            continue
        in_working_dir = _inside(targets[0], cwd_posix)
        if protection.block_outside_cwd and not in_working_dir:
            continue
        if any(protection.sandbox_covers(t) for t in targets):
            continue
        hits.append((store, path))
    return hits


def _env_files(cwd: Path, errors: list[str]) -> list[Path]:
    """Non-empty ``.env`` files at the cwd root (names only; never opened)."""
    found: list[Path] = []
    try:
        with os.scandir(cwd) as entries:
            for count, entry in enumerate(entries):
                if count >= _MAX_ROOT_ENTRIES:
                    errors.append(
                        f"secret reach: more than {_MAX_ROOT_ENTRIES} entries at"
                        " the working directory's root; the rest were not checked"
                    )
                    break
                name = entry.name
                if not _ENV_NAME_RE.match(name):
                    continue
                if any(
                    part.lower() in _ENV_TEMPLATE_PARTS for part in name.split(".")[2:]
                ):
                    continue
                path = cwd / name
                if _stat_store(path) is not None:
                    found.append(path)
    except OSError as exc:
        errors.append(
            "secret reach: cannot list the working directory:"
            f" {exc.strerror or type(exc).__name__}"
        )
    return sorted(found)


# ── Findings ──────────────────────────────────────────────────────────────────


def _finding(
    fid: str,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    path: Path | None,
    cwe: str,
) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        analyzer=ANALYZER,
        client=CLIENT,
        server="(machine)",
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        finding_path=str(path) if path is not None else None,
        owasp_mcp_top_10=["MCP01"],
    )


def _reach_001(
    hits: list[tuple[SecretStore, Path]], home: Path, user_settings: Path
) -> Finding:
    labels = [f"{_label(path, home)} ({store.label})" for store, path in hits]
    certain = sum(1 for store, _ in hits if store.certain)
    deny = ", ".join(f'"Read({_label(path, home)})"' for _, path in hits[:3])
    return _finding(
        "REACH-001",
        Severity.LOW,
        f"{len(hits)} credential file(s) a Claude Code session can read without asking",
        "Claude Code runs cat, head and tail without a permission prompt in"
        " every mode, and its sandbox's default read access includes credential"
        " files (code.claude.com/docs: permissions, 'Read-only commands';"
        " sandboxing, 'There is no built-in credential deny list'). No Read deny"
        " rule, blockReadsOutsideWorkingDirectories setting or sandbox deny"
        f" entry covers {len(hits)} file(s) that hold or commonly hold"
        f" credentials ({certain} exist only to hold one), so a prompt-injected"
        " session can read them without a prompt. Found with stat() only;"
        " mcp-audit never opens these files.",
        "; ".join(labels),
        "Add Read deny rules for them to your user settings"
        f" ({_label(user_settings, home)}), e.g. permissions.deny: [{deny}], or"
        ' set "permissions": {"blockReadsOutsideWorkingDirectories": true}. With'
        " the sandbox on, also list them in sandbox.credentials.files with"
        f' "mode": "deny". See {_PERMISSIONS_DOC} and {_SANDBOX_DOC}.',
        user_settings,
        "CWE-522",
    )


def _dir_mode(path: Path) -> int | None:
    """``st_mode`` of a directory above the login store, or ``None``."""
    try:
        return path.stat().st_mode
    except OSError:
        return None


def _exposed_classes(path: Path, st: os.stat_result) -> list[str]:
    """Classes of other local accounts that can read *path* (mode bits only).

    A class can read the file when the file has its read bit and every
    directory above it has its search bit.  Group access counts only when the
    file's group is not the owner's private group (same name as the owner).
    """
    if _ON_WINDOWS:
        return []
    import grp  # noqa: PLC0415 — POSIX only
    import pwd  # noqa: PLC0415 — POSIX only

    classes: list[tuple[str, int, int]] = []
    if st.st_mode & stat.S_IROTH:
        classes.append(("any other local account", stat.S_IROTH, stat.S_IXOTH))
    if st.st_mode & stat.S_IRGRP:
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
            group = grp.getgrgid(st.st_gid).gr_name
        except (KeyError, OSError):
            owner, group = "", "?"
        if group != owner:
            classes.append((f"members of group {group}", stat.S_IRGRP, stat.S_IXGRP))
    exposed: list[str] = []
    for name, _read_bit, search_bit in classes:
        reachable = True
        for parent in list(path.parents)[:64]:
            mode = _dir_mode(parent)
            if mode is None or not mode & search_bit:
                reachable = False
                break
        if reachable:
            exposed.append(name)
    return exposed


def _reach_002(path: Path, home: Path) -> Finding | None:
    try:
        st = path.stat()
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    try:
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            return None
    except OSError:
        return None
    exposed = _exposed_classes(path, st)
    if not exposed:
        return None
    label = _label(path, home)
    return _finding(
        "REACH-002",
        Severity.MEDIUM,
        "Claude Code's login store is readable by other local accounts",
        f"{label} holds your Claude Code login. Claude Code writes it with file"
        " mode 0600 (code.claude.com/docs: authentication), but its mode is now"
        f" {stat.S_IMODE(st.st_mode):04o} and the directories above it let"
        f" {' and '.join(exposed)} reach it. Mode bits only: ACLs are not read.",
        f"{label} mode {stat.S_IMODE(st.st_mode):04o}",
        f"chmod 600 {label}  (see {_AUTH_DOC})",
        path,
        "CWE-732",
    )


def _reach_003(env_files: list[Path], user_settings: Path, home: Path) -> Finding:
    names = [p.name for p in env_files]
    return _finding(
        "REACH-003",
        Severity.LOW,
        f"{len(names)} .env file(s) in this directory with no Read deny rule",
        "Claude Code reads files in the working directory without approval in"
        " every permission mode (code.claude.com/docs: permissions), and no Read"
        f" deny rule covers {', '.join(names)}. Anthropic's own example denies"
        ' "Read(./.env)" and "Read(./.env.*)". Found by file name; mcp-audit'
        " never opens these files.",
        ", ".join(names),
        'Add "Read(./.env)" and "Read(./.env.*)" to permissions.deny in'
        " .claude/settings.json (shared) or"
        f' {_label(user_settings, home)} as "Read(//**/.env)" for every'
        f" project. See {_PERMISSIONS_DOC}.",
        env_files[0],
        "CWE-522",
    )


def secret_reach_findings(
    errors: list[str],
    *,
    cwd: Path | None = None,
    home: Path | None = None,
    config_dir: Path | None = None,
    managed_dir: Path | None = None,
) -> list[Finding]:
    """REACH-001..003 for a default scan.  Never raises.

    Args:
        errors: The scan's error list; read problems are appended here.
        cwd: Working directory (default: ``Path.cwd()``).
        home: Home directory (default: ``Path.home()``).
        config_dir: Claude Code's config directory (default:
            ``CLAUDE_CONFIG_DIR`` or ``~/.claude``).
        managed_dir: Managed settings directory (default: this OS's).

    Returns:
        The findings, de-duplicated by ``(id, finding_path)``.  Empty when no
        Claude Code config directory exists.
    """
    try:
        return _secret_reach_findings(errors, cwd, home, config_dir, managed_dir)
    except Exception as exc:  # noqa: BLE001 — a posture check never fails the scan
        errors.append(f"secret reach: check failed: {type(exc).__name__}")
        return []


def _secret_reach_findings(
    errors: list[str],
    cwd: Path | None,
    home: Path | None,
    config_dir: Path | None,
    managed_dir: Path | None,
) -> list[Finding]:
    from mcp_audit.plugins import mods as _mods  # noqa: PLC0415

    home = home if home is not None else Path.home()
    cwd = cwd if cwd is not None else Path.cwd()
    if config_dir is None:
        config_dir = _mods.claude_config_dir(home)
    if managed_dir is None:
        managed_dir = _mods.managed_settings_dir()
    try:
        if not config_dir.is_dir():
            return []
    except OSError:
        return []

    sources = load_settings_sources(cwd, home, config_dir, managed_dir, errors)
    protection = build_protection(sources, cwd, home)
    user_settings = config_dir / "settings.json"

    findings: list[Finding] = []
    hits = _uncovered_home_stores(protection, cwd, home, config_dir)
    if hits:
        findings.append(_reach_001(hits, home, user_settings))
    reach_002 = _reach_002(config_dir / ".credentials.json", home)
    if reach_002 is not None:
        findings.append(reach_002)
    if not _same_file(cwd, home):
        env_files = [
            p
            for p in _env_files(cwd, errors)
            if not protection.read_rule_covers(_posix(p))
        ]
        if env_files:
            findings.append(_reach_003(env_files, user_settings, home))

    seen: set[tuple[str, str | None]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.id, finding.finding_path)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
