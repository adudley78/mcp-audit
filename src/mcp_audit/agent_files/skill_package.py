"""A skill is a package: read every file in a Claude Code skill directory.

STORY-0095.  Before this module mcp-audit judged a skill by its ``SKILL.md``
(SKILL-001..003) and the filenames in ``scripts/`` (SKILL-004).  The largest
2026 skill campaign (Paperclip, Zenity Labs) kept ``SKILL.md`` clean and put
the payload in a sidecar file; SkillCloak (arXiv 2607.02357) packed payloads
into ``.git/`` and ``build/``, the folders scanners skip.  This module walks
the whole skill directory.  The text and byte checks it applies live in
:mod:`mcp_audit.agent_files.install_steps`.

Finding IDs (``analyzer="agent_files"``)
----------------------------------------
SKILL-005 (HIGH / LOW / INFO)
    An install step in any text file of the skill.  HIGH: a remote fetch that
    is executed while switching off TLS checks, decoding the download, using
    plaintext or a raw IP host; a TLS-off fetch on its own; a decode-then-
    execute chain; ``marshal.loads``; an archive opened with a password; a
    DNS TXT record that is executed; a scheduled-job or login-item write; a
    reverse shell; a URL whose host is a public IP address.  LOW: a plain
    ``curl … | sh`` (or a download that is then run) over https from a host
    that is not a known vendor installer.  INFO: a known vendor installer or
    a Dockerfile ``RUN`` line.  Piped installers are common in ordinary skills
    (measured; see GAPS.md), so the plain shape is not raised above LOW.

SKILL-006 (HIGH / MEDIUM / LOW)
    What the skill ships into Claude Code beside its markdown.  A folder
    directly under a skills directory that holds ``.claude-plugin/plugin.json``
    is loaded as a plugin (``<name>@skills-dir``) with its own MCP servers
    (HIGH), hooks, monitors and language servers (MEDIUM) and ``bin/``
    programs on the agent's PATH (MEDIUM, HIGH when one shadows a common
    command).  ``hooks`` in ``SKILL.md`` frontmatter run from the skill's first
    use to the end of the session (MEDIUM).  An MCP config (MEDIUM) or a
    settings/hooks file (LOW) that Claude Code does not load from where it sits
    is reported as carried.  Text telling the agent to switch permission
    prompts off, or pointing ``ANTHROPIC_BASE_URL`` (and siblings) at a host
    that is not the vendor's, is HIGH.  Shipped servers go through the existing
    per-server analyzers and shipped hook commands through HOOK-001/002.

SKILL-007 (MEDIUM / LOW)
    Content no text scanner can read: a binary of no recognised format, a
    compiled program, a ``.pyc`` without source, a password-protected archive,
    bytes that do not match the extension, a long encoded blob in a text file,
    a text file over the read cap, a skill over its read budget, and any
    non-text file in ``.git/`` that is not part of git's layout (MEDIUM).
    Plain archives and skipped dependency folders are LOW.

SKILL-008 (HIGH)
    The skill bundles executable code **and** another MEDIUM-or-higher finding
    fires on it (the conjunctive bump; bundled scripts raised vulnerability
    odds 2.12×, arXiv 2601.10338).  Other findings keep their own severity.

Sidecars (opt-in)
-----------------
:func:`sidecar_findings` applies the ``SKILL.md`` instruction rules to every
other prose file in the skill.  It is called from
:func:`mcp_audit.agent_files.analyzer.analyze_agent_files`, so it follows the
same opt-in as ``SKILL.md`` (``scan --include-agent-files``, ``agent-files
scan``).  SKILL-005..008 run in the default ``scan``/``check``/``scan
--project`` path.

Invariants
----------
* Nothing is executed, imported, unpacked or decompressed.  Files are read as
  bytes, under a per-file cap, a per-skill budget and a per-scan budget; a
  budget that runs out is reported (SKILL-007), never silent.
* One symlink shape is followed: a link directly under a skills directory
  that points at a skill (decision 2026-10-26; the skills CLI installs skills
  this way).  It is read at its target and reported as TRUST-004 (INFO); in a
  repository the target must stay inside it (otherwise TRUST-002 HIGH, not
  read); a link to the skills directory or an ancestor is TRUST-005.  No other
  symlink is followed: a symlinked directory becomes TRUST-005; a symlinked
  file TRUST-002 (project scope) or TRUST-004 (user scope); neither is read.
  Every read is checked to resolve under the scan root and opened with
  ``O_NOFOLLOW``.  The user's ``~/.claude`` and
  ``~/.claude/skills`` may themselves be links (dotfile managers), as default
  discovery already allows for ``~/.claude/settings.json``; a repository's
  may not.
* Every filesystem call is guarded.  Failures become strings in ``errors``,
  which the scan copies to ``ScanResult.errors``; the default scan never
  crashes on a skill directory.
* Evidence goes through :func:`~mcp_audit.agent_files.install_steps.redact`.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.agent_files.install_steps import (
    BENIGN_FAMILIES,
    CLAIMED_EXT,
    blob_in_text,
    decode_text,
    entropy,
    expected_family,
    identify,
    install_step_hits,
    rank,
    redact,
    snippet,
    text_shape_hits,
)
from mcp_audit.agent_files.models import AgentFile, AgentFileSurface
from mcp_audit.models import Finding, Severity

# ── Client names ──────────────────────────────────────────────────────────────

#: Client on the package findings themselves.
PACKAGE_CLIENT = "claude-code"
#: Client on MCP servers a skill carries but Claude Code does not load from
#: where they sit.  They never join discovery, so they never reach the lock,
#: the rug-pull state key, toxic flow or the attack graph.
CARRIED_SERVER_CLIENT = "claude-code-skill"
#: A skills-directory plugin *is* a Claude Code plugin (``<name>@skills-dir``),
#: so its servers join default discovery under the existing plugin client and
#: inherit its exclusions: ``mcp-audit lock`` passes ``include_plugins=False``,
#: ``rug_pull.derive_state_path`` drops the client, ``lock.auto_verify`` skips it.
SKILLS_DIR_PLUGIN_CLIENT = "claude-code-plugin"

# ── Budgets and caps ──────────────────────────────────────────────────────────

FILE_TEXT_CAP = 1024 * 1024  # bytes of one text file that are read
_HEAD_BYTES = 64 * 1024  # bytes read to classify a file
_JSON_CAP = 1024 * 1024  # largest component JSON file that is parsed
#: Bytes read per skill and per scan.  Matching costs about 0.5 s per MiB of
#: ordinary text and up to about 1.5 s per MiB of text built to defeat the
#: pattern gates (measured, STORY-0095), so the scan budget bounds a hostile
#: repository to under a minute.  The 1,128 skills measured hold 29 MiB of text
#: in all; the largest single skill holds 2 MiB.
PACKAGE_BYTE_BUDGET = 8 * 1024 * 1024
PACKAGE_ENTRY_BUDGET = 20_000
SCAN_BYTE_BUDGET = 32 * 1024 * 1024
SCAN_ENTRY_BUDGET = 200_000
_WALK_MAX_DEPTH = 16  # inside one skill
_DISCOVERY_MAX_DEPTH = 8  # looking for SKILL.md under a skills directory
_PROJECT_MAX_DEPTH = 8  # looking for .claude/skills in a project tree
_GIT_TEXT_RECORD_CAP = 64 * 1024
_MAX_HITS_PER_FILE = 10
_MAX_PER_ID_PER_PACKAGE = 25
_MIN_UNKNOWN_BINARY = 64
#: Largest SKILL.md frontmatter parsed for hooks, and the YAML bytes one scan
#: may parse.  Frontmatter is parsed only when it has a top-level ``hooks:``
#: key; one that is not parsed is reported, not skipped.
_FRONTMATTER_CAP = 32 * 1024
_YAML_SCAN_BUDGET = 1024 * 1024
#: Hook entries taken from one hooks map.  YAML aliases let a few kilobytes of
#: frontmatter stand for billions of entries; every walk sees a bounded copy.
_HOOK_ENTRY_CAP = 256
#: Items taken from one manifest list (component paths, monitors, language
#: servers) and servers analysed from one carried MCP config.
_MANIFEST_ITEM_CAP = 64

#: Third-party dependency folders: not walked (native libraries and data would
#: drown the report, and their code is not the skill's instructions).  Each
#: one is reported as SKILL-007 LOW so the gap is visible.
_DEPENDENCY_DIRS = frozenset(
    {"node_modules", ".venv", "venv", "site-packages", "bower_components"}
)
#: Skipped while looking for skills; the walk inside a skill enters ``build/``,
#: ``dist/`` and ``.git/`` (SkillCloak's blind spots).
_DISCOVERY_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".tox",
        "venv",
        ".venv",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)
_PROJECT_SKIP_DIRS = _DISCOVERY_SKIP_DIRS | {"dist", "build"}

_CODE_EXTENSIONS = frozenset(
    {
        ".py",
        ".pyw",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ksh",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".mts",
        ".cts",
        ".tsx",
        ".jsx",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".vbs",
        ".rb",
        ".pl",
        ".php",
        ".lua",
        ".applescript",
        ".scpt",
        ".jar",
        ".pyc",
        ".wasm",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
    }
)
_PROSE_EXTENSIONS = frozenset({".md", ".mdx", ".markdown", ".mdc", ".txt", ".rst"})

# ── Data model ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SkillPackage:
    """One skill directory, or one skills-directory plugin root.

    Attributes:
        root: The directory as discovered (not resolved).
        scope: ``"user"``, ``"project"`` or ``"plugin"`` (a skill an installed
            marketplace plugin ships).
        scan_root: The boundary every read must resolve under: the skills
            directory (user and plugin scope) or the repository / working
            directory (project scope).
        is_plugin: The directory sits directly under a skills directory and
            holds ``.claude-plugin/plugin.json``, so Claude Code loads it as
            the plugin ``<name>@skills-dir`` (docs: plugins/loading).
        link: For a skill reached through a symlink directly under a skills
            directory, that link; *root* is then the resolved target
            (decision 2026-10-26, "Follow a symlinked skill folder one level").
    """

    root: Path
    scope: str
    scan_root: Path
    is_plugin: bool = False
    link: Path | None = None

    @property
    def name(self) -> str:
        """The skill's directory name."""
        return self.root.name

    @property
    def label(self) -> str:
        """``Finding.server`` for package findings; never an MCP server's name."""
        return f"{self.root.name} (skill)"


@dataclass
class ScanBudget:
    """Bytes and directory entries one scan may still spend across skills."""

    bytes_left: int = SCAN_BYTE_BUDGET
    entries_left: int = SCAN_ENTRY_BUDGET
    #: Frontmatter bytes the YAML parser may still read (it costs about 10 µs
    #: per byte, so this keeps a hostile repository's skills to seconds).
    yaml_left: int = _YAML_SCAN_BUDGET


@dataclass
class _TextFile:
    path: Path
    rel: str
    text: str
    in_git: bool = False


@dataclass
class _Opaque:
    rel: str
    path: Path
    reason: str
    severity: Severity


@dataclass
class _Inventory:
    texts: list[_TextFile] = field(default_factory=list)
    opaque: list[_Opaque] = field(default_factory=list)
    code_files: list[str] = field(default_factory=list)
    dependency_dirs: list[str] = field(default_factory=list)
    symlink_findings: list[Finding] = field(default_factory=list)
    uninspected: int = 0
    budget_reason: str = ""


# ── Guarded filesystem helpers ────────────────────────────────────────────────


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except (OSError, ValueError):
        return None


def _is_real_dir(path: Path) -> bool:
    st = _lstat(path)
    return st is not None and stat.S_ISDIR(st.st_mode)


def _is_real_file(path: Path) -> bool:
    st = _lstat(path)
    return st is not None and stat.S_ISREG(st.st_mode)


def _is_link(path: Path) -> bool:
    st = _lstat(path)
    return st is not None and stat.S_ISLNK(st.st_mode)


def _realpath(path: Path) -> str:
    try:
        return os.path.realpath(path)
    except (OSError, ValueError):
        return ""


def _inside(path: Path, boundary: str) -> bool:
    """True when *path* resolves at or under the resolved *boundary*."""
    real = _realpath(path)
    if not real or not boundary:
        return False
    base = boundary.rstrip(os.sep) or os.sep
    return real == base or real.startswith(base.rstrip(os.sep) + os.sep)


def _scandir(path: Path, errors: list[str]) -> list[os.DirEntry[str]]:
    try:
        with os.scandir(path) as entries:
            return sorted(entries, key=lambda e: e.name)
    except OSError as exc:
        errors.append(f"skill package: cannot list {path}: {exc}")
        return []


def _read_bytes(path: Path, limit: int, boundary: str, errors: list[str]) -> bytes:
    """Read up to *limit* bytes of *path*, a regular file under *boundary*.

    Opened with ``O_NOFOLLOW`` and ``O_NONBLOCK`` (where the platform has
    them) and checked with ``fstat``, so a link or FIFO swapped in after the
    walk is neither followed nor blocked on.
    """
    if limit <= 0 or not _inside(path, boundary):
        return b""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        errors.append(f"skill package: cannot open {path}: {exc}")
        return b""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return b""
        chunks: list[bytes] = []
        remaining = limit
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError as exc:
        errors.append(f"skill package: cannot read {path}: {exc}")
        return b""
    finally:
        os.close(fd)


def _load_json(path: Path, boundary: str, errors: list[str]) -> object | None:
    """Parse a component JSON file (strict JSON, then JSONC); ``None`` if unusable."""
    from mcp_audit.analyzers.config_hygiene import parse_jsonc  # noqa: PLC0415

    if not _is_real_file(path):
        return None
    data = _read_bytes(path, _JSON_CAP + 1, boundary, errors)
    if len(data) > _JSON_CAP:
        errors.append(f"skill package: {path} is over {_JSON_CAP:,} bytes; not parsed")
        return None
    text = decode_text(data)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return parse_jsonc(text)


# ── Git directory layout (names only; nothing in .git is parsed) ──────────────

_GIT_TOP_FILES = frozenset(
    {
        "HEAD",
        "config",
        "config.worktree",
        "description",
        "index",
        "packed-refs",
        "shallow",
        "FETCH_HEAD",
        "ORIG_HEAD",
        "MERGE_HEAD",
        "MERGE_MSG",
        "MERGE_MODE",
        "MERGE_RR",
        "AUTO_MERGE",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "REBASE_HEAD",
        "COMMIT_EDITMSG",
        "TAG_EDITMSG",
        "SQUASH_MSG",
        "NOTES_EDITMSG",
        "EDIT_DESCRIPTION",
        "gitk.cache",
        "BISECT_LOG",
        "BISECT_START",
        "BISECT_TERMS",
        "BISECT_EXPECTED_REV",
        "BISECT_ANCESTORS_OK",
        "BISECT_NAMES",
        "BISECT_HEAD",
        "commondir",
        "gitdir",
        "locked",
    }
)
#: Git's own small text records; a binary or large file here is foreign.
_GIT_TEXT_DIRS = frozenset(
    {
        "refs",
        "logs",
        "info",
        "branches",
        "remotes",
        "rr-cache",
        "rebase-merge",
        "rebase-apply",
        "sequencer",
        "filter-repo",
        "gk",
        "svn",
    }
)
#: Owned by git or a git tool and not inspected (hooks are STORY-0089's).
_GIT_SKIPPED_DIRS = frozenset({"hooks", "annex", "fsmonitor--daemon"})
#: Each child is a git directory of its own.
_GIT_NESTED_DIRS = frozenset({"modules", "worktrees"})
_GIT_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{38}|[0-9a-f]{62}|tmp_obj_\w{1,40})$")
_GIT_PACK_RE = re.compile(
    r"^(?:pack-[0-9a-f]{40,64}\.(?:pack|idx|rev|keep|promisor|mtimes|bitmap)"
    r"|multi-pack-index(?:-[0-9a-f]{40,64}\.(?:bitmap|rev))?"
    r"|tmp_(?:pack|idx|rev)_\w{1,40})$"
)
_GIT_LFS_OBJECT_RE = re.compile(r"^[0-9a-f]{64}$")


def _git_file_kind(parts: tuple[str, ...]) -> str:
    """Classify a file path relative to a ``.git`` directory.

    ``"layout"``: git's own file, not read.  ``"record"``: one of git's text
    records, foreign only if binary or large.  ``"foreign"``: not git's.
    """
    head = parts[0]
    if len(parts) == 1:
        if head in _GIT_TOP_FILES or head.endswith(".lock"):
            return "layout"
        return (
            "layout" if head.startswith(("sharedindex.", "next-index-")) else "foreign"
        )
    if head == "objects":
        rest = parts[1:]
        if len(rest) == 2 and re.fullmatch(r"[0-9a-f]{2}", rest[0]):
            return "layout" if _GIT_OBJECT_RE.match(rest[1]) else "foreign"
        if rest[0] == "pack" and len(rest) == 2:
            return "layout" if _GIT_PACK_RE.match(rest[1]) else "foreign"
        if rest[0] == "info" and len(rest) == 2:
            return (
                "layout"
                if rest[1] in {"packs", "alternates", "http-alternates", "commit-graph"}
                else "foreign"
            )
        if rest[:2] == ("info", "commit-graphs") and len(rest) == 3:
            return "layout"
        return "foreign"
    if head == "lfs":
        if parts[1] == "objects":
            return "layout" if _GIT_LFS_OBJECT_RE.match(parts[-1]) else "foreign"
        return "layout"
    if head in _GIT_TEXT_DIRS:
        return "record"
    return "foreign"


# ── Walking one skill ─────────────────────────────────────────────────────────


def _symlink_finding(pkg: SkillPackage, path: Path) -> Finding:
    from mcp_audit.discovery import (  # noqa: PLC0415
        build_info_symlink_finding,
        build_project_symlink_finding,
        build_untraversed_symlink_dir_finding,
    )

    if _is_real_dir(Path(_realpath(path) or path)):
        return build_untraversed_symlink_dir_finding(path, "agent-files")
    if pkg.scope == "project":
        return build_project_symlink_finding(path, "agent-files", pkg.scan_root)
    return build_info_symlink_finding(path, "agent-files")


def _has_skill_md(path: Path) -> bool:
    candidate = path / "SKILL.md"
    return _is_real_file(candidate) or _is_link(candidate)


class _Walk:
    """State for one walk of one skill directory."""

    def __init__(
        self, pkg: SkillPackage, budget: ScanBudget, errors: list[str]
    ) -> None:
        self.pkg = pkg
        self.budget = budget
        self.errors = errors
        self.inv = _Inventory()
        self.boundary = _realpath(pkg.scan_root)
        self.bytes_left = PACKAGE_BYTE_BUDGET
        self.entries_left = PACKAGE_ENTRY_BUDGET

    def _out_of_budget(self, kind: str) -> bool:
        if kind == "entries":
            if self.budget.entries_left <= 0:
                self.inv.budget_reason = "the scan-wide entry budget"
                return True
            if self.entries_left <= 0:
                self.inv.budget_reason = (
                    f"the {PACKAGE_ENTRY_BUDGET:,}-entry skill budget"
                )
                return True
            return False
        if self.budget.bytes_left <= 0:
            self.inv.budget_reason = "the scan-wide read budget"
            return True
        if self.bytes_left <= 0:
            mib = PACKAGE_BYTE_BUDGET // (1024 * 1024)
            self.inv.budget_reason = f"the {mib} MiB skill read budget"
            return True
        return False

    def _read(self, path: Path, want: int) -> bytes:
        want = min(want, self.bytes_left, self.budget.bytes_left)
        data = _read_bytes(path, want, self.boundary, self.errors)
        self.bytes_left -= len(data)
        self.budget.bytes_left -= len(data)
        return data

    def run(self) -> _Inventory:
        root = self.pkg.root
        if not self.boundary or not _inside(root, self.boundary):
            self.errors.append(
                f"skill package: {root} does not resolve under"
                f" {self.pkg.scan_root}; not read"
            )
            return self.inv
        stack: list[tuple[Path, int, tuple[str, ...], tuple[str, ...] | None]] = [
            (root, 0, (), None)
        ]
        while stack:
            directory, depth, rel_parts, git_parts = stack.pop()
            for entry in _scandir(directory, self.errors):
                if self._out_of_budget("entries"):
                    self.inv.uninspected += 1
                    continue
                self.entries_left -= 1
                self.budget.entries_left -= 1
                self._visit(entry, depth, rel_parts, git_parts, stack)
        return self.inv

    def _visit(
        self,
        entry: os.DirEntry[str],
        depth: int,
        rel_parts: tuple[str, ...],
        git_parts: tuple[str, ...] | None,
        stack: list[tuple[Path, int, tuple[str, ...], tuple[str, ...] | None]],
    ) -> None:
        path = Path(entry.path)
        parts = (*rel_parts, entry.name)
        sub_git = (*git_parts, entry.name) if git_parts is not None else None
        try:
            is_link = entry.is_symlink()
            is_dir = not is_link and entry.is_dir(follow_symlinks=False)
            is_file = not is_link and entry.is_file(follow_symlinks=False)
        except OSError as exc:
            self.errors.append(f"skill package: cannot stat {path}: {exc}")
            return
        if is_link:
            self.inv.symlink_findings.append(_symlink_finding(self.pkg, path))
            return
        if is_dir:
            self._visit_dir(path, entry.name, depth, parts, sub_git, stack)
            return
        if is_file:
            self._visit_file(entry, path, parts, sub_git)
        # sockets, FIFOs and devices are never opened

    def _visit_dir(
        self,
        path: Path,
        name: str,
        depth: int,
        parts: tuple[str, ...],
        sub_git: tuple[str, ...] | None,
        stack: list[tuple[Path, int, tuple[str, ...], tuple[str, ...] | None]],
    ) -> None:
        if depth + 1 > _WALK_MAX_DEPTH:
            self.inv.uninspected += 1
            self.inv.budget_reason = f"the {_WALK_MAX_DEPTH}-level depth cap"
            return
        if sub_git is not None:
            if len(sub_git) == 1 and name in _GIT_SKIPPED_DIRS:
                return
            if len(sub_git) == 2 and sub_git[0] in _GIT_NESTED_DIRS:
                stack.append((path, depth + 1, parts, ()))
                return
            stack.append((path, depth + 1, parts, sub_git))
            return
        if name in _DEPENDENCY_DIRS:
            self.inv.dependency_dirs.append("/".join(parts))
            return
        if name == ".git":
            stack.append((path, depth + 1, parts, ()))
            return
        if _has_skill_md(path):
            return  # a nested skill is its own package
        stack.append((path, depth + 1, parts, None))

    def _visit_file(
        self,
        entry: os.DirEntry[str],
        path: Path,
        parts: tuple[str, ...],
        sub_git: tuple[str, ...] | None,
    ) -> None:
        rel = "/".join(parts)
        git_kind = _git_file_kind(sub_git) if sub_git is not None else None
        if git_kind == "layout":
            return
        try:
            size = entry.stat(follow_symlinks=False).st_size
        except OSError as exc:
            self.errors.append(f"skill package: cannot stat {path}: {exc}")
            return
        if self._out_of_budget("bytes"):
            self.inv.uninspected += 1
            return
        head = self._read(path, min(size, _HEAD_BYTES))
        ext = Path(parts[-1]).suffix.lower()
        text = decode_text(head)
        in_git = sub_git is not None
        if text is None:
            self._binary(rel, path, ext, size, head, parts, in_git)
            return
        if text.startswith("version https://git-lfs.github.com/spec/"):
            return  # an LFS pointer standing in for a binary asset
        if git_kind == "record" and size <= _GIT_TEXT_RECORD_CAP:
            return
        if ext in CLAIMED_EXT and not in_git:
            self.inv.opaque.append(
                _Opaque(
                    rel, path, f"named {ext} but its content is text", Severity.MEDIUM
                )
            )
        if size > len(head) and len(head) < FILE_TEXT_CAP:
            # Re-read from the start up to the text cap; the head is credited
            # back so it is not charged twice.
            self.bytes_left += len(head)
            self.budget.bytes_left += len(head)
            more = self._read(path, min(size, FILE_TEXT_CAP))
            decoded = decode_text(more)
            if decoded is not None:
                text = decoded
            if len(more) < min(size, FILE_TEXT_CAP):
                self.inv.uninspected += 1
                self.inv.budget_reason = self.inv.budget_reason or "the read budget"
        if size > FILE_TEXT_CAP:
            text = text[:FILE_TEXT_CAP]
            self.inv.opaque.append(
                _Opaque(
                    rel,
                    path,
                    f"{size:,}-byte text file; only the first {FILE_TEXT_CAP:,}"
                    " bytes were inspected",
                    Severity.MEDIUM,
                )
            )
        self.inv.texts.append(_TextFile(path, rel, text, in_git))
        if not in_git and (
            ext in _CODE_EXTENSIONS or text.startswith("#!") or "scripts" in parts[:-1]
        ):
            self.inv.code_files.append(rel)

    def _binary(
        self,
        rel: str,
        path: Path,
        ext: str,
        size: int,
        head: bytes,
        parts: tuple[str, ...],
        in_git: bool,
    ) -> None:
        family, label = identify(head, ext)
        add = self.inv.opaque.append
        if in_git:
            add(
                _Opaque(
                    rel,
                    path,
                    f"{label} inside .git/ that is not part of git's layout"
                    f" ({size:,} bytes)",
                    Severity.MEDIUM,
                )
            )
            return
        if "scripts" in parts[:-1] or family.startswith("compiled"):
            self.inv.code_files.append(rel)
        claimed = expected_family(ext)
        actual = "archive" if family.startswith("archive") else family
        if claimed is not None and actual != claimed:
            add(
                _Opaque(
                    rel,
                    path,
                    f"named {ext} but its bytes are a {label}",
                    Severity.MEDIUM,
                )
            )
        elif family in BENIGN_FAMILIES:
            return
        elif family == "archive-encrypted":
            add(_Opaque(rel, path, label, Severity.MEDIUM))
        elif family == "archive":
            add(
                _Opaque(
                    rel,
                    path,
                    f"{label} ({size:,} bytes); mcp-audit does not unpack archives",
                    Severity.LOW,
                )
            )
        elif family == "compiled-pyc":
            stem = path.name.split(".", 1)[0]
            source_dir = (
                path.parent.parent if path.parent.name == "__pycache__" else path.parent
            )
            if not _is_real_file(source_dir / f"{stem}.py"):
                add(
                    _Opaque(
                        rel, path, "compiled Python with no .py source", Severity.MEDIUM
                    )
                )
        elif family == "compiled":
            add(
                _Opaque(
                    rel,
                    path,
                    f"{label}; compiled code cannot be read as text",
                    Severity.MEDIUM,
                )
            )
        elif size >= _MIN_UNKNOWN_BINARY:
            add(
                _Opaque(
                    rel,
                    path,
                    f"{label}, {size:,} bytes, entropy {entropy(head):.1f} bits/byte",
                    Severity.MEDIUM,
                )
            )


def _walk_package(
    pkg: SkillPackage, budget: ScanBudget, errors: list[str]
) -> _Inventory:
    return _Walk(pkg, budget, errors).run()


# ── Finding builders ──────────────────────────────────────────────────────────


def _finding(
    pkg: SkillPackage,
    finding_id: str,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    path: Path | None,
    owasp: list[str],
    cwe: str | None,
    cve: list[str] | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="agent_files",
        client=PACKAGE_CLIENT,
        server=pkg.label,
        title=redact(title),
        description=redact(description),
        evidence=redact(evidence),
        remediation=remediation,
        finding_path=str(path if path is not None else pkg.root),
        owasp_mcp_top_10=owasp,
        cwe=cwe,
        cve=cve or [],
    )


def _scrub(findings: Iterable[Finding], path: Path) -> list[Finding]:
    """Point routed findings at *path* and redact their text."""
    out: list[Finding] = []
    for f in findings:
        f.finding_path = str(path)
        f.title = redact(f.title)
        f.description = redact(f.description)
        f.evidence = redact(f.evidence)
        out.append(f)
    return out


def _skill_005(pkg: SkillPackage, tf: _TextFile) -> list[Finding]:
    out: list[Finding] = []
    for hit in install_step_hits(tf.rel, tf.text)[:_MAX_HITS_PER_FILE]:
        where = f"{tf.rel}:{hit.line}"
        out.append(
            _finding(
                pkg,
                "SKILL-005",
                hit.severity,
                "Skill contains an install step that runs remote or hidden code",
                (
                    f"The skill '{pkg.name}' contains, in {where}, an install step:"
                    f" {'; '.join(hit.reasons)}. Whatever a skill's files tell the"
                    " agent to run, it runs with your user's privileges. Every file"
                    " in the skill directory is checked, not only SKILL.md: the"
                    " Paperclip campaign (Zenity Labs, 2026) kept SKILL.md clean and"
                    " put this kind of command in a sidecar file."
                ),
                f"{where}: {snippet(hit.text)}",
                (
                    "Read the command and what it fetches before using this skill."
                    " Prefer a pinned package (npm or PyPI with a version) to a piped"
                    " script. Never follow a step that switches off TLS checks or"
                    " decodes a payload before running it."
                ),
                tf.path,
                ["MCP04", "MCP05"],
                "CWE-494",
            )
        )
    return out


def _skill_006_text(pkg: SkillPackage, tf: _TextFile) -> list[Finding]:
    out: list[Finding] = []
    for shape in text_shape_hits(tf.text):
        where = f"{tf.rel}:{shape.line}"
        if shape.kind == "permissions":
            out.append(
                _finding(
                    pkg,
                    "SKILL-006",
                    Severity.HIGH,
                    "Skill tells the agent to switch off permission prompts",
                    (
                        f"The skill '{pkg.name}' has, in {where}, an instruction or"
                        " setting that runs the agent with permission prompts off"
                        " (--dangerously-skip-permissions, bypassPermissions, or the"
                        " equivalent for Codex or Gemini CLI). Every later tool call"
                        " would run without asking you. The USENIX Security 2026"
                        " study of malicious skills (arXiv 2602.06547) found this"
                        " instruction in confirmed cases."
                    ),
                    f"{where}: {snippet(shape.source)}",
                    (
                        "Do not follow it. Remove the instruction, or run only in"
                        " a disposable container."
                    ),
                    tf.path,
                    ["MCP05", "MCP02"],
                    "CWE-269",
                )
            )
        else:
            out.append(
                _finding(
                    pkg,
                    "SKILL-006",
                    Severity.HIGH,
                    f"Skill points {shape.variable} at a host that is not the vendor's",
                    (
                        f"The skill '{pkg.name}' sets {shape.variable}, in {where}, to"
                        " a host that is not the model vendor's endpoint. The harness"
                        " sends your prompts, code and API key to that base URL (the"
                        " CVE-2026-21852 vector; the USENIX Security 2026 study's"
                        " smp_9014 skill redirected Claude API calls this way)."
                    ),
                    f"{where}: {snippet(shape.source)}",
                    (
                        "Remove the override unless the host is a gateway you run"
                        " or trust. Rotate the API key if it was applied."
                    ),
                    tf.path,
                    ["MCP01", "MCP05"],
                    "CWE-441",
                    ["CVE-2026-21852"]
                    if shape.variable.startswith("ANTHROPIC_")
                    else [],
                )
            )
    return out


def _skill_007(pkg: SkillPackage, inv: _Inventory) -> list[Finding]:
    remediation = (
        "Find out what this file is before using the skill. A skill should ship"
        " readable instructions and scripts; content nothing can read is where"
        " packed payloads hide."
    )
    out = [
        _finding(
            pkg,
            "SKILL-007",
            item.severity,
            "Skill contains content that cannot be inspected",
            (
                f"The skill '{pkg.name}' contains '{item.rel}': {item.reason}."
                " mcp-audit reads every file in a skill directory, including .git/"
                " and build/, because a scanner that skips opaque files can be"
                " evaded by packing the payload into one (SkillCloak, arXiv"
                " 2607.02357). Nothing is unpacked or run."
            ),
            f"{item.rel}: {item.reason}",
            remediation,
            item.path,
            ["MCP04", "MCP03"],
            "CWE-506",
        )
        for item in inv.opaque
    ]
    for tf in inv.texts:
        blob = blob_in_text(tf.text)
        if blob is not None:
            out.append(
                _finding(
                    pkg,
                    "SKILL-007",
                    Severity.MEDIUM,
                    "Skill contains an encoded blob inside a text file",
                    (
                        f"The skill '{pkg.name}' has {blob} in '{tf.rel}' that does"
                        " not decode to an image, font or document. An encoded"
                        " payload in a text file hides its content from pattern"
                        " scanners."
                    ),
                    f"{tf.rel}: {blob}",
                    remediation,
                    tf.path,
                    ["MCP04", "MCP03"],
                    "CWE-506",
                )
            )
    if inv.uninspected:
        plural = "entry was" if inv.uninspected == 1 else "entries were"
        out.append(
            _finding(
                pkg,
                "SKILL-007",
                Severity.MEDIUM,
                "Skill was not fully inspected",
                (
                    f"{inv.uninspected:,} {plural} not read in the skill '{pkg.name}'"
                    f" because the scan reached {inv.budget_reason}. Padding a skill"
                    " past a scanner's limits is a known evasion (SkillCloak's"
                    " size-pad operator)."
                ),
                f"{inv.uninspected:,} not read ({inv.budget_reason})",
                "Review the skill by hand, or remove files it does not need.",
                pkg.root,
                ["MCP04"],
                "CWE-506",
            )
        )
    if inv.dependency_dirs:
        dirs = ", ".join(inv.dependency_dirs[:10])
        out.append(
            _finding(
                pkg,
                "SKILL-007",
                Severity.LOW,
                "Skill contains a dependency folder that was not inspected",
                (
                    f"The skill '{pkg.name}' contains {dirs}. Dependency folders are"
                    " not walked, so nothing inside them was checked."
                ),
                f"not inspected: {dirs}",
                "Install dependencies from a lockfile instead of shipping them.",
                pkg.root,
                ["MCP04"],
                "CWE-1104",
            )
        )
    return out


# ── SKILL-006: components the skill ships ─────────────────────────────────────


def _mcp_server_names(value: object) -> list[str]:
    """Server names in an MCP config value (``mcpServers`` wrapper or bare map)."""
    if not isinstance(value, dict):
        return []
    for key in ("mcpServers", "servers"):
        inner = value.get(key)
        if isinstance(inner, dict):
            value = inner
            break
    return [
        str(name)
        for name, conf in list(value.items())[:_MANIFEST_ITEM_CAP]
        if isinstance(conf, dict) and {"command", "url", "type"} & set(conf)
    ]


def _manifest_items(value: object) -> list[object]:
    """A manifest field as a list of at most ``_MANIFEST_ITEM_CAP`` items."""
    items = value if isinstance(value, list) else [value]
    return items[:_MANIFEST_ITEM_CAP]


def _manifest_paths(value: object, root: Path) -> list[Path]:
    """``./relative`` component paths from a manifest value, staying in *root*.

    Duplicates are dropped, so listing one file thousands of times reads it once.
    """
    out: list[Path] = []
    for item in _manifest_items(value):
        if (
            isinstance(item, str)
            and item.startswith("./")
            and ".." not in item.split("/")
            and root / item[2:] not in out
        ):
            out.append(root / item[2:])
    return out


def _bounded_hooks(hooks: object) -> dict | None:
    """A copy of a hooks map holding at most ``_HOOK_ENTRY_CAP`` hook entries.

    Only the shape Claude Code reads is kept: event → list of matcher groups →
    ``hooks`` list.  Taking the copy under a cap bounds every later walk, even
    when YAML aliases make one entry appear millions of times.
    """
    if not isinstance(hooks, dict):
        return None
    out: dict[str, list[dict]] = {}
    left = _HOOK_ENTRY_CAP
    for event, groups in list(hooks.items())[:64]:
        if left <= 0:
            break
        if not isinstance(groups, list):
            continue
        kept: list[dict] = []
        for group in groups[:64]:
            if left <= 0:
                break
            if not isinstance(group, dict):
                continue
            entries = group.get("hooks")
            entries = list(entries[:left]) if isinstance(entries, list) else []
            left -= max(1, len(entries))
            kept.append({"matcher": group.get("matcher"), "hooks": entries})
        out[str(event)] = kept
    return out or None


def _hooks_findings(
    pkg: SkillPackage,
    hooks: object,
    path: Path,
    severity: Severity,
    where: str,
    how: str,
) -> list[Finding]:
    """SKILL-006 for a hooks map, plus HOOK-001/002 on its commands."""
    from mcp_audit.analyzers.config_hygiene import (
        ConfigHygieneAnalyzer,  # noqa: PLC0415
    )

    hooks = _bounded_hooks(hooks)
    if not hooks:
        return []
    commands = ConfigHygieneAnalyzer._extract_hook_commands(hooks)  # noqa: SLF001
    events = ", ".join(sorted(str(k) for k in hooks)[:8])
    finding = _finding(
        pkg,
        "SKILL-006",
        severity,
        "Skill ships hooks",
        (
            f"The skill '{pkg.name}' declares hooks in {where} ({events}). {how}"
            " A hook runs its command on every matching event without asking. The"
            " USENIX Security 2026 study (arXiv 2602.06547, smp_413) found a skill"
            " using PreToolUse/PostToolUse hooks to send results and memory to an"
            " external server."
        ),
        f"{where}: {len(commands)} command hook(s) on {events}",
        "Read every hook command and remove hooks you did not ask for.",
        path,
        ["MCP05", "MCP07"],
        "CWE-78",
    )
    routed = ConfigHygieneAnalyzer()._check_hook_commands(  # noqa: SLF001
        hooks, path, PACKAGE_CLIENT
    )
    return [finding, *_scrub(routed, path)]


_FRONTMATTER_HOW = (
    "Claude Code registers a skill's frontmatter hooks when the skill is invoked"
    " and keeps running them for the rest of the session, including in a -p run in"
    ' a folder you have not trusted (docs: hooks, "Hooks in skills and agents").'
)


_HOOKS_KEY_RE = re.compile(r"(?m)^[\"']?hooks[\"']?[ \t]{0,5}:")


def _frontmatter_hooks(
    pkg: SkillPackage, boundary: str, errors: list[str], budget: ScanBudget
) -> list[Finding]:
    from mcp_audit.agent_files.discovery import _split_frontmatter  # noqa: PLC0415

    skill_md = pkg.root / "SKILL.md"
    if not _is_real_file(skill_md):
        return []
    raw = _read_bytes(skill_md, FILE_TEXT_CAP, boundary, errors)
    block = (decode_text(raw) or "").lstrip("\ufeff")
    end = block.find("\n---", 3) if block.startswith("---") else -1
    if end == -1 or not _HOOKS_KEY_RE.search(block, 0, end):
        return []
    if end > _FRONTMATTER_CAP:
        why = f"is over {_FRONTMATTER_CAP:,} bytes"
    elif end > budget.yaml_left:
        why = "is past this scan's frontmatter budget"
    else:
        budget.yaml_left -= end
        frontmatter, _body = _split_frontmatter(block[: end + 4])
        hooks = frontmatter.get("hooks")
        if isinstance(hooks, dict):
            return _hooks_findings(
                pkg,
                hooks,
                skill_md,
                Severity.MEDIUM,
                "SKILL.md frontmatter",
                _FRONTMATTER_HOW,
            )
        if frontmatter:
            return []
        why = "is not strict YAML"
    # Claude Code's reader may accept what was not parsed here; take the
    # stricter reading: the hooks may load.
    return [
        _finding(
            pkg,
            "SKILL-006",
            Severity.MEDIUM,
            "Skill ships hooks",
            (
                f"The skill '{pkg.name}' declares hooks in SKILL.md frontmatter"
                f" that mcp-audit did not parse (the frontmatter {why}), so the"
                f" hook commands were not inspected. {_FRONTMATTER_HOW}"
            ),
            f"SKILL.md frontmatter: hooks key present, not parsed ({why})",
            "Read the frontmatter by hand and remove hooks you did not ask for.",
            skill_md,
            ["MCP05", "MCP07"],
            "CWE-78",
        )
    ]


#: A ``bin/`` program with one of these names would run instead of the system
#: command when the agent types it.
_SHADOWED_COMMANDS = frozenset(
    {
        "git",
        "ls",
        "cat",
        "cd",
        "curl",
        "wget",
        "python",
        "python3",
        "pip",
        "pip3",
        "node",
        "npm",
        "npx",
        "pnpm",
        "yarn",
        "bun",
        "uv",
        "uvx",
        "sh",
        "bash",
        "zsh",
        "ssh",
        "scp",
        "gh",
        "sudo",
        "make",
        "docker",
        "kubectl",
        "grep",
        "find",
        "rm",
        "cp",
        "mv",
        "echo",
        "env",
        "which",
        "open",
        "code",
        "claude",
        "jq",
        "tar",
    }
)


class _PluginReader:
    """SKILL-006 for one skills-directory plugin."""

    def __init__(self, pkg: SkillPackage, boundary: str, errors: list[str]) -> None:
        self.pkg = pkg
        self.root = pkg.root
        self.boundary = boundary
        self.errors = errors
        self.manifest_path = self.root / ".claude-plugin" / "plugin.json"
        manifest = _load_json(self.manifest_path, boundary, errors)
        self.manifest: dict = manifest if isinstance(manifest, dict) else {}
        self.disabled = self.manifest.get("defaultEnabled") is False
        self.project = pkg.scope == "project"
        self.consumed: set[str] = set()
        name = (
            self.manifest.get("name")
            if isinstance(self.manifest.get("name"), str)
            else pkg.name
        )
        note = (
            "Claude Code loads a folder under a skills directory that holds"
            f" .claude-plugin/plugin.json as the plugin '{name}@skills-dir'"
            " (docs: plugins/loading)."
        )
        if self.project:
            note += (
                " In a repository it loads once you accept the workspace trust"
                " dialog, and its MCP servers then need the same per-server approval"
                " as a project .mcp.json."
            )
        if self.disabled:
            note += (
                " Its manifest sets defaultEnabled: false, so it loads only if a"
                " settings file enables it."
            )
        self.note = note

    def tier(self, severity: Severity) -> Severity:
        if not self.disabled:
            return severity
        return Severity.MEDIUM if severity == Severity.HIGH else Severity.LOW

    def consume(self, path: Path) -> None:
        try:
            self.consumed.add(path.relative_to(self.root).as_posix())
        except ValueError:
            return

    def read(self) -> list[Finding]:
        out: list[Finding] = []
        out.extend(self._servers())
        out.extend(self._hooks())
        out.extend(self._monitors())
        out.extend(self._language_servers())
        out.extend(self._bin())
        return out

    def _servers(self) -> list[Finding]:
        sources: list[tuple[Path, list[str]]] = []
        mcp_json = self.root / ".mcp.json"
        if _is_real_file(mcp_json):
            self.consume(mcp_json)
            sources.append(
                (
                    mcp_json,
                    _mcp_server_names(_load_json(mcp_json, self.boundary, self.errors)),
                )
            )
        declared = self.manifest.get("mcpServers")
        bundles: list[str] = []
        for item in _manifest_items(declared):
            if isinstance(item, dict):
                sources.append((self.manifest_path, _mcp_server_names(item)))
            elif isinstance(item, str) and item.lower().endswith((".mcpb", ".dxt")):
                bundles.append(item)
        for path in _manifest_paths(declared, self.root):
            if path.suffix.lower() == ".json" and _is_real_file(path):
                self.consume(path)
                sources.append(
                    (
                        path,
                        _mcp_server_names(_load_json(path, self.boundary, self.errors)),
                    )
                )
        out: list[Finding] = []
        for path, names in sources:
            out.extend(
                _finding(
                    self.pkg,
                    "SKILL-006",
                    self.tier(Severity.HIGH),
                    "Skill also installs an MCP server",
                    (
                        f"The skill folder '{self.pkg.name}' starts the MCP server"
                        f" '{name}' with your user's privileges. {self.note} The"
                        " server also appears in this scan as client"
                        " claude-code-plugin, where the per-server checks run."
                    ),
                    f"{path.name}: server '{name}'",
                    "Review the server's command and arguments before keeping it.",
                    path,
                    ["MCP09", "MCP04"],
                    "CWE-829",
                )
                for name in names
            )
        for bundle in bundles:
            skipped = (
                " Claude Code skips bundles in a repository's plugin."
                if self.project
                else ""
            )
            out.append(
                _finding(
                    self.pkg,
                    "SKILL-006",
                    self.tier(Severity.LOW if self.project else Severity.HIGH),
                    "Skill also installs an MCP server",
                    (
                        f"The skill folder '{self.pkg.name}' declares the MCP bundle"
                        f" '{bundle}', which Claude Code extracts (or downloads) and"
                        f" starts. {self.note}{skipped}"
                    ),
                    f"plugin.json mcpServers: {snippet(bundle)}",
                    "Review the bundle before keeping this skill.",
                    self.manifest_path,
                    ["MCP09", "MCP04"],
                    "CWE-829",
                )
            )
        return out

    def _hooks(self) -> list[Finding]:
        sources: list[tuple[Path, object]] = []
        hooks_json = self.root / "hooks" / "hooks.json"
        if _is_real_file(hooks_json):
            self.consume(hooks_json)
            value = _load_json(hooks_json, self.boundary, self.errors)
            sources.append(
                (hooks_json, value.get("hooks") if isinstance(value, dict) else None)
            )
        declared = self.manifest.get("hooks")
        for item in _manifest_items(declared):
            if isinstance(item, dict):
                sources.append((self.manifest_path, item))
        for path in _manifest_paths(declared, self.root):
            if _is_real_file(path):
                self.consume(path)
                value = _load_json(path, self.boundary, self.errors)
                sources.append(
                    (path, value.get("hooks") if isinstance(value, dict) else None)
                )
        how = self.note + " Its hooks merge with your user and project hooks."
        out: list[Finding] = []
        for path, hooks in sources:
            out.extend(
                _hooks_findings(
                    self.pkg, hooks, path, self.tier(Severity.MEDIUM), path.name, how
                )
            )
        return out

    def _monitors(self) -> list[Finding]:
        entries: list[tuple[Path, object]] = []
        mon_json = self.root / "monitors" / "monitors.json"
        if _is_real_file(mon_json):
            self.consume(mon_json)
            value = _load_json(mon_json, self.boundary, self.errors)
            entries.extend(
                (mon_json, m) for m in (value if isinstance(value, list) else [])
            )
        exp = self.manifest.get("experimental")
        for value in (
            exp.get("monitors") if isinstance(exp, dict) else None,
            self.manifest.get("monitors"),
        ):
            if isinstance(value, list):
                entries.extend((self.manifest_path, m) for m in value)
        out: list[Finding] = []
        for path, mon in entries[:_MANIFEST_ITEM_CAP]:
            if not isinstance(mon, dict) or not isinstance(mon.get("command"), str):
                continue
            skipped = (
                " Monitors do not load for a repository's plugin."
                if self.project
                else ""
            )
            out.append(
                _finding(
                    self.pkg,
                    "SKILL-006",
                    self.tier(Severity.LOW if self.project else Severity.MEDIUM),
                    "Skill starts a background command",
                    (
                        f"The skill folder '{self.pkg.name}' declares the monitor"
                        f" '{snippet(str(mon.get('name', '?')), 60)}', a command"
                        " Claude Code runs as a persistent background process"
                        f" (when: {snippet(str(mon.get('when', 'always')), 60)})."
                        f" {self.note}{skipped}"
                    ),
                    f"monitor command: {snippet(mon['command'])}",
                    "Read the monitor command before keeping this skill.",
                    path,
                    ["MCP05"],
                    "CWE-78",
                )
            )
        return out

    def _language_servers(self) -> list[Finding]:
        sources: list[tuple[Path, object]] = []
        lsp_json = self.root / ".lsp.json"
        if _is_real_file(lsp_json):
            self.consume(lsp_json)
            sources.append((lsp_json, _load_json(lsp_json, self.boundary, self.errors)))
        if isinstance(self.manifest.get("lspServers"), dict):
            sources.append((self.manifest_path, self.manifest["lspServers"]))
        out: list[Finding] = []
        for path, value in sources:
            if isinstance(value, dict) and isinstance(value.get("lspServers"), dict):
                value = value["lspServers"]
            if not isinstance(value, dict):
                continue
            for name, conf in list(value.items())[:_MANIFEST_ITEM_CAP]:
                if not (
                    isinstance(conf, dict) and isinstance(conf.get("command"), str)
                ):
                    continue
                out.append(
                    _finding(
                        self.pkg,
                        "SKILL-006",
                        self.tier(Severity.MEDIUM),
                        "Skill starts a language server",
                        (
                            f"The skill folder '{self.pkg.name}' declares the language"
                            f" server '{snippet(str(name), 60)}', a command Claude Code"
                            f" starts when it works on matching files. {self.note}"
                        ),
                        f"{path.name}: {snippet(conf['command'])}",
                        "Check the language server's command before keeping it.",
                        path,
                        ["MCP05"],
                        "CWE-78",
                    )
                )
        return out

    def _bin(self) -> list[Finding]:
        bin_dir = self.root / "bin"
        if not _is_real_dir(bin_dir):
            return []
        names: list[str] = []
        for entry in _scandir(bin_dir, self.errors):
            try:
                if not entry.is_symlink() and entry.is_file(follow_symlinks=False):
                    names.append(entry.name)
            except OSError:
                continue
        if not names:
            return []
        shadow = sorted(
            n for n in names if n.split(".")[0].lower() in _SHADOWED_COMMANDS
        )
        shadow_note = (
            f" {', '.join(shadow)} share a name with a common command, so the agent"
            " would run the skill's copy instead."
            if shadow
            else ""
        )
        return [
            _finding(
                self.pkg,
                "SKILL-006",
                self.tier(Severity.HIGH if shadow else Severity.MEDIUM),
                "Skill puts programs on the agent's PATH",
                (
                    f"The skill folder '{self.pkg.name}' ships {len(names)} file(s) in"
                    " bin/, which Claude Code puts on the Bash tool's PATH while the"
                    ' plugin is enabled (docs: plugin manifest reference, "Standard'
                    f' layout"). {self.note}{shadow_note}'
                ),
                f"bin/: {', '.join(sorted(names)[:15])}",
                (
                    "Remove programs you did not expect; a skill should never"
                    " shadow a system command."
                ),
                bin_dir,
                ["MCP05", "MCP04"],
                "CWE-427",
            )
        ]


_CARRIED_MCP_NAMES = frozenset({".mcp.json", "mcp.json"})
_CARRIED_SETTINGS_NAMES = frozenset(
    {"settings.json", "settings.local.json", "hooks.json"}
)
_CARRIED_NOTE = (
    "Claude Code does not load this file from inside a skill folder (only a"
    " folder holding .claude-plugin/plugin.json is loaded as a plugin), so it"
    " takes effect only if the skill's instructions or an installer copy it into"
    " place. The USENIX Security 2026 study (arXiv 2602.06547, smp_866) found a"
    " skill shipping a .mcp.json with hardcoded credentials."
)


def _carried_components(
    pkg: SkillPackage,
    texts: list[_TextFile],
    consumed: set[str],
    boundary: str,
    errors: list[str],
) -> list[Finding]:
    """SKILL-006 for MCP and settings files Claude Code does not load from here."""
    from mcp_audit.analyzers.auth import AuthAnalyzer  # noqa: PLC0415
    from mcp_audit.analyzers.config_hygiene import (
        ConfigHygieneAnalyzer,  # noqa: PLC0415
    )
    from mcp_audit.analyzers.credentials import CredentialsAnalyzer  # noqa: PLC0415
    from mcp_audit.analyzers.poisoning import PoisoningAnalyzer  # noqa: PLC0415
    from mcp_audit.analyzers.transport import TransportAnalyzer  # noqa: PLC0415
    from mcp_audit.config_parser import parse_config  # noqa: PLC0415
    from mcp_audit.discovery import DiscoveredConfig  # noqa: PLC0415

    out: list[Finding] = []
    analyzers = [
        PoisoningAnalyzer(),
        CredentialsAnalyzer(),
        TransportAnalyzer(),
        ConfigHygieneAnalyzer(),
        AuthAnalyzer(),
    ]
    for tf in texts:
        if tf.in_git or tf.rel in consumed:
            continue
        name = tf.path.name
        if name in _CARRIED_MCP_NAMES and len(tf.text) <= _JSON_CAP:
            config = DiscoveredConfig(
                client_name=CARRIED_SERVER_CLIENT, root_key="mcpServers", path=tf.path
            )
            try:
                servers = parse_config(config)
            except (ValueError, RecursionError) as exc:
                errors.append(f"skill package: {redact(str(exc))[:300]}")
                continue
            if not servers:
                continue
            names = ", ".join(s.name for s in servers[:10])
            out.append(
                _finding(
                    pkg,
                    "SKILL-006",
                    Severity.MEDIUM,
                    "Skill carries an MCP server configuration",
                    (
                        f"The skill '{pkg.name}' ships '{tf.rel}' defining"
                        f" {len(servers)} MCP server(s): {names}. {_CARRIED_NOTE}"
                    ),
                    f"{tf.rel}: {names}",
                    (
                        "Do not copy this configuration into your settings"
                        " without reviewing every server."
                    ),
                    tf.path,
                    ["MCP09", "MCP04"],
                    "CWE-829",
                )
            )
            for server in servers[:_MANIFEST_ITEM_CAP]:
                for analyzer in analyzers:
                    try:
                        routed = analyzer.analyze(server)
                    except Exception as exc:  # noqa: BLE001 — never crash the scan
                        errors.append(
                            f"skill package: {analyzer.name} on {tf.path}: {exc}"
                        )
                        continue
                    for f in _scrub(routed, tf.path):
                        f.server = f"{server.name} (carried by skill {pkg.name})"
                        out.append(f)
        elif name in _CARRIED_SETTINGS_NAMES:
            value = _load_json(tf.path, boundary, errors)
            hooks = value.get("hooks") if isinstance(value, dict) else None
            out.extend(
                _hooks_findings(
                    pkg, hooks, tf.path, Severity.LOW, tf.rel, _CARRIED_NOTE
                )
            )
    return out


# ── Analysis entry points ─────────────────────────────────────────────────────

#: Executable files found per skill root in this process, so SKILL-008 can be
#: decided again by a later stage without re-reading the skill.
_CODE_FILES: dict[str, list[str]] = {}

#: Findings that never make a skill qualify for SKILL-008: inventories,
#: coverage notes and the noisy SKILL.md checks (length, any URL).
_NOT_QUALIFYING = frozenset(
    {
        "SKILL-002",
        "SKILL-003",
        "SKILL-004",
        "SKILL-008",
        "TRUST-002",
        "TRUST-004",
        "TRUST-005",
    }
)


def analyze_skill_package(
    pkg: SkillPackage,
    budget: ScanBudget | None = None,
    errors: list[str] | None = None,
) -> list[Finding]:
    """SKILL-005/006/007 and the routed findings for one skill.

    Args:
        pkg: The skill to read.
        budget: Scan-wide budget shared across skills; a fresh one if omitted.
        errors: Receives filesystem and parse errors (never raised).

    Returns:
        Findings with redacted evidence.  SKILL-008 comes from
        :func:`bundled_code_findings`.
    """
    errs: list[str] = errors if errors is not None else []
    budget = budget if budget is not None else ScanBudget()
    inv = _walk_package(pkg, budget, errs)
    boundary = _realpath(pkg.scan_root)
    findings: list[Finding] = list(inv.symlink_findings)
    per_id: dict[str, int] = {}

    def keep(batch: Iterable[Finding]) -> None:
        for f in batch:
            per_id[f.id] = per_id.get(f.id, 0) + 1
            if per_id[f.id] <= _MAX_PER_ID_PER_PACKAGE:
                findings.append(f)

    for tf in inv.texts:
        keep(_skill_005(pkg, tf))
        keep(_skill_006_text(pkg, tf))
    consumed: set[str] = set()
    if pkg.is_plugin:
        reader = _PluginReader(pkg, boundary, errs)
        keep(reader.read())
        consumed = reader.consumed
    keep(_frontmatter_hooks(pkg, boundary, errs, budget))
    keep(_carried_components(pkg, inv.texts, consumed, boundary, errs))
    keep(_skill_007(pkg, inv))
    _CODE_FILES[str(pkg.root)] = list(inv.code_files)
    return findings


def _code_files(pkg: SkillPackage) -> list[str]:
    cached = _CODE_FILES.get(str(pkg.root))
    if cached is None:
        cached = list(_walk_package(pkg, ScanBudget(), []).code_files)
        _CODE_FILES[str(pkg.root)] = cached
    return cached


def _owner(path: str | None, packages: list[SkillPackage]) -> SkillPackage | None:
    """The innermost skill whose directory contains *path*."""
    if not path:
        return None
    best: SkillPackage | None = None
    for pkg in packages:
        root = str(pkg.root).rstrip(os.sep)
        if (path == root or path.startswith(root + os.sep)) and (
            best is None or len(root) > len(str(best.root))
        ):
            best = pkg
    return best


def bundled_code_findings(
    packages: list[SkillPackage], findings: list[Finding]
) -> list[Finding]:
    """SKILL-008 for skills that bundle code and carry a MEDIUM+ finding.

    A skill that already has SKILL-008 in *findings* is skipped, so each stage
    that sees part of the evidence (default scan, ``--project``, agent-file
    scan) emits it at most once.
    """
    done = {f.finding_path for f in findings if f.id == "SKILL-008"}
    qualifying: dict[str, set[str]] = {}
    for f in findings:
        if f.id in _NOT_QUALIFYING or rank(f.severity) < rank(Severity.MEDIUM):
            continue
        owner = _owner(f.finding_path, packages)
        if owner is not None:
            qualifying.setdefault(str(owner.root), set()).add(f.id)
    out: list[Finding] = []
    for pkg in packages:
        ids = qualifying.get(str(pkg.root))
        if not ids or str(pkg.root) in done:
            continue
        code = _code_files(pkg)
        if not code:
            continue
        done.add(str(pkg.root))
        out.append(
            _finding(
                pkg,
                "SKILL-008",
                Severity.HIGH,
                "Skill bundles code and has another finding",
                (
                    f"The skill '{pkg.name}' bundles {len(code)} executable file(s)"
                    f" and also has {', '.join(sorted(ids))}. Code a skill ships runs"
                    " with your privileges when the agent follows its instructions;"
                    " skills with bundled scripts were 2.12 times as likely to be"
                    " vulnerable (arXiv 2601.10338). This finding marks the"
                    " combination; the other findings keep their own severity."
                ),
                f"code: {', '.join(code[:10])} | with: {', '.join(sorted(ids))}",
                "Resolve the other findings on this skill, then review its code.",
                pkg.root,
                ["MCP04", "MCP05"],
                "CWE-506",
            )
        )
    return out


def _key(f: Finding) -> tuple[str, str, str | None, str]:
    return (f.id, f.title, f.finding_path, f.evidence)


def analyze_skill_packages(
    packages: list[SkillPackage],
    prior: list[Finding] | None = None,
    errors: list[str] | None = None,
) -> list[Finding]:
    """Analyze *packages*; return the findings not already in *prior*.

    Adds SKILL-008 over *prior* plus the new findings.  Never raises: an
    unexpected failure on one skill becomes an ``errors`` entry.
    """
    prior = prior or []
    errs: list[str] = errors if errors is not None else []
    seen = {_key(f) for f in prior}
    budget = ScanBudget()
    out: list[Finding] = []
    for pkg in packages:
        try:
            batch = analyze_skill_package(pkg, budget, errs)
        except Exception as exc:  # noqa: BLE001 — the default scan must not crash
            errs.append(f"skill package: {pkg.root}: {exc}")
            continue
        for f in batch:
            if _key(f) not in seen:
                seen.add(_key(f))
                out.append(f)
    try:
        out.extend(bundled_code_findings(packages, prior + out))
    except Exception as exc:  # noqa: BLE001
        errs.append(f"skill package: SKILL-008: {exc}")
    return out


# ── Discovery ─────────────────────────────────────────────────────────────────


def _skills_home() -> Path:
    """Home directory whose ``.claude/skills`` holds personal skills.

    Separate from :meth:`pathlib.Path.home` so tests can point it elsewhere.
    """
    return Path.home()


def _untraversed(path: Path) -> Finding:
    from mcp_audit.discovery import (
        build_untraversed_symlink_dir_finding,  # noqa: PLC0415
    )

    return build_untraversed_symlink_dir_finding(path, "agent-files")


def _is_plugin_dir(path: Path) -> bool:
    return (
        _is_real_dir(path)
        and _is_real_dir(path / ".claude-plugin")
        and _is_real_file(path / ".claude-plugin" / "plugin.json")
    )


def _followed_link_finding(link: Path, target: str) -> Finding:
    """TRUST-004 (INFO): a skill folder read through its symlink."""
    return Finding(
        id="TRUST-004",
        severity=Severity.INFO,
        analyzer="discovery",
        client="agent-files",
        server=link.name,
        title="Skill folder is a symlink",
        description=redact(
            f"'{link}' is a symlink to '{target}'. Claude Code reads a skill"
            " through a symlinked folder (the skills CLI installs skills this way"
            " by default), so mcp-audit read the skill at its target. Links"
            " inside the skill are not followed."
        ),
        evidence=redact(f"Visible path: {link} | Resolved target: {target}"),
        remediation=(
            "No action required if you installed the skill this way. Otherwise,"
            " check what the link points to."
        ),
        finding_path=str(link),
        owasp_mcp_top_10=["MCP09"],
        cwe="CWE-61",
    )


def _follow_skill_link(
    link: Path,
    skills_root: Path,
    scope: str,
    scan_root: Path,
    findings: list[Finding],
) -> SkillPackage | None:
    """The skill a symlink directly under a skills directory points at, or ``None``.

    Decision 2026-10-26 ("Follow a symlinked skill folder one level", amending
    site 8 of the 2026-09-08 symlink decision).  User scope: followed whatever
    the target.  Project scope: followed only when the target resolves inside
    *scan_root* (the repository); a target outside it is TRUST-002 HIGH and is
    not read.  A target that is the skills directory or one of its ancestors
    (a loop), or that holds no skill, is TRUST-005 as before.  A followed
    skill is reported as TRUST-004 (INFO) and walked like any other, so no
    link inside it is followed and every budget applies.
    """
    from mcp_audit.discovery import build_project_symlink_finding  # noqa: PLC0415

    target = _realpath(link)
    if not target or not _is_real_dir(Path(target)):
        return None  # broken or not a directory: nothing Claude Code can load
    skills_real = _realpath(skills_root)
    base = target.rstrip(os.sep) or os.sep
    if skills_real == base or skills_real.startswith(base.rstrip(os.sep) + os.sep):
        findings.append(_untraversed(link))
        return None
    if scope == "project" and not _inside(Path(target), _realpath(scan_root)):
        findings.append(build_project_symlink_finding(link, "agent-files", scan_root))
        return None
    root = Path(target)
    is_plugin = _is_plugin_dir(root)
    if not (is_plugin or _has_skill_md(root)):
        findings.append(_untraversed(link))
        return None
    findings.append(_followed_link_finding(link, target))
    boundary = scan_root if scope == "project" else root
    return SkillPackage(root, scope, boundary, is_plugin, link=link)


def _packages_under(
    skills_root: Path,
    scope: str,
    scan_root: Path,
    errors: list[str],
    findings: list[Finding],
) -> list[SkillPackage]:
    """Every skill and skills-directory plugin under *skills_root*.

    A symlink directly under *skills_root* that points at a skill is followed
    one level (:func:`_follow_skill_link`).  Any other symlinked directory is
    never entered; one that points at a directory is reported as TRUST-005.
    """
    plugin_roots: set[str] = set()
    for entry in _scandir(skills_root, errors):
        path = Path(entry.path)
        if _is_plugin_dir(path):
            plugin_roots.add(str(path))
    found: list[SkillPackage] = []
    stack: list[tuple[Path, int]] = [(skills_root, 0)]
    while stack:
        directory, depth = stack.pop()
        if directory != skills_root and (
            str(directory) in plugin_roots or _has_skill_md(directory)
        ):
            found.append(
                SkillPackage(
                    directory, scope, scan_root, str(directory) in plugin_roots
                )
            )
        if depth >= _DISCOVERY_MAX_DEPTH:
            continue
        for entry in _scandir(directory, errors):
            path = Path(entry.path)
            try:
                if entry.is_symlink():
                    if depth == 0:
                        followed = _follow_skill_link(
                            path, skills_root, scope, scan_root, findings
                        )
                        if followed is not None:
                            found.append(followed)
                    elif _is_real_dir(Path(_realpath(path) or path)):
                        findings.append(_untraversed(path))
                    continue
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if entry.name not in _DISCOVERY_SKIP_DIRS:
                stack.append((path, depth + 1))
    # Claude Code loads a skill once even when several entries point at it.
    unique: dict[str, SkillPackage] = {}
    for pkg in sorted(found, key=lambda p: (p.link is not None, str(p.root))):
        unique.setdefault(_realpath(pkg.root) or str(pkg.root), pkg)
    return sorted(unique.values(), key=lambda p: str(p.root))


def _repo_skills_dir(base: Path, findings: list[Finding]) -> Path | None:
    """``base/.claude/skills`` when it exists and neither segment is a symlink."""
    current = base
    for segment in (".claude", "skills"):
        current = current / segment
        if _is_link(current):
            if _is_real_dir(Path(_realpath(current) or current)):
                findings.append(_untraversed(current))
            return None
        if not _is_real_dir(current):
            return None
    return current


def default_skill_packages(
    cwd: Path | None = None,
    errors: list[str] | None = None,
    findings: list[Finding] | None = None,
) -> list[SkillPackage]:
    """Skills under ``~/.claude/skills`` (user) and ``<cwd>/.claude/skills``.

    The user's ``~/.claude`` and ``~/.claude/skills`` may be links (dotfile
    managers); the resolved skills directory is then the scan root.  The
    cwd's are repository content and are skipped (TRUST-005) when either is a
    link.  Nothing below a skills directory is followed through a link.

    Args:
        cwd: The working directory; defaults to the current one.
        errors: Receives filesystem errors.
        findings: Receives TRUST-005 for symlinked directories not entered.
    """
    errs: list[str] = errors if errors is not None else []
    sink: list[Finding] = findings if findings is not None else []
    packages: list[SkillPackage] = []
    user_dir = _skills_home() / ".claude" / "skills"
    user_real = ""
    try:
        user_ok = user_dir.is_dir()
    except OSError as exc:
        errs.append(f"skill package: cannot read {user_dir}: {exc}")
        user_ok = False
    if user_ok:
        user_real = _realpath(user_dir)
        packages.extend(
            _packages_under(user_dir, "user", Path(user_real or user_dir), errs, sink)
        )
    try:
        base = (cwd or Path.cwd()).resolve()
    except OSError as exc:
        errs.append(f"skill package: cannot resolve the working directory: {exc}")
        return packages
    project_dir = _repo_skills_dir(base, sink)
    if project_dir is not None and _realpath(project_dir) != user_real:
        packages.extend(_packages_under(project_dir, "project", base, errs, sink))
    return packages


def project_skill_packages(
    project_root: Path,
    errors: list[str] | None = None,
    findings: list[Finding] | None = None,
) -> list[SkillPackage]:
    """Skills under every ``.claude/skills`` in a repository tree.

    Same walk rules as the other ``--project`` walks: depth cap 8, the usual
    skip list, symlinked directories never entered.
    """
    errs: list[str] = errors if errors is not None else []
    sink: list[Finding] = findings if findings is not None else []
    try:
        root = project_root.resolve()
    except OSError as exc:
        errs.append(f"skill package: cannot resolve {project_root}: {exc}")
        return []
    packages: list[SkillPackage] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        skills_dir = _repo_skills_dir(directory, sink)
        if skills_dir is not None:
            packages.extend(_packages_under(skills_dir, "project", root, errs, sink))
        if depth >= _PROJECT_MAX_DEPTH:
            continue
        for entry in _scandir(directory, errs):
            try:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if entry.name not in _PROJECT_SKIP_DIRS and entry.name != ".claude":
                stack.append((Path(entry.path), depth + 1))
    return sorted(packages, key=lambda p: str(p.root))


def _skills_ancestor(path: Path) -> Path:
    """The nearest ancestor named ``skills`` (the boundary), else *path* itself."""
    return next((p for p in path.parents if p.name == "skills"), path)


def packages_for_agent_files(files: list[AgentFile]) -> list[SkillPackage]:
    """Skill packages for discovered ``SKILL.md`` files (used for plugin skills).

    The boundary is the nearest ``skills`` directory above each skill, so
    nothing outside it is read.  A marketplace plugin's root components
    (``.mcp.json``, hooks) are covered by existing plugin discovery.
    """
    out: list[SkillPackage] = []
    seen: set[str] = set()
    for af in files:
        if af.surface != AgentFileSurface.CLAUDE_SKILL or af.path.name != "SKILL.md":
            continue
        root = af.path.parent
        if str(root) in seen:
            continue
        seen.add(str(root))
        scope = af.scope if af.scope in {"user", "project", "plugin"} else "plugin"
        out.append(SkillPackage(root, scope, _skills_ancestor(root)))
    return out


def followed_agent_files(
    packages: list[SkillPackage], errors: list[str] | None = None
) -> list[AgentFile]:
    """``SKILL.md`` of each skill reached through a followed symlink.

    The agent-file walk never follows a symlinked directory, so these skills'
    ``SKILL.md`` files are read here for the opt-in agent-file rules
    (SKILL-001..004 and the sidecar pass), under the same boundary and cap as
    the package walk.  Frontmatter over ``_FRONTMATTER_CAP`` is not parsed.
    """
    from mcp_audit.agent_files.discovery import _split_frontmatter  # noqa: PLC0415

    errs: list[str] = errors if errors is not None else []
    out: list[AgentFile] = []
    for pkg in packages:
        skill_md = pkg.root / "SKILL.md"
        if pkg.link is None or not _is_real_file(skill_md):
            continue
        raw = _read_bytes(skill_md, FILE_TEXT_CAP, _realpath(pkg.scan_root), errs)
        text = decode_text(raw)
        if text is None:
            continue
        end = text.find("\n---", 3) if text.startswith("---") else -1
        if 0 <= end <= _FRONTMATTER_CAP:
            frontmatter, body = _split_frontmatter(text)
        else:
            frontmatter, body = {}, text
        out.append(
            AgentFile(
                path=skill_md,
                surface=AgentFileSurface.CLAUDE_SKILL,
                client="claude-code",
                scope=pkg.scope,
                raw_content=text,
                body=body,
                frontmatter=frontmatter,
            )
        )
    return out


def skills_dir_plugin_mcp_configs(packages: list[SkillPackage]) -> list:
    """``DiscoveredConfig`` entries for servers that skills-directory plugins load.

    ``.mcp.json`` at the plugin root, and ``.claude-plugin/plugin.json`` when
    its ``mcpServers`` is an object.  A plugin whose manifest sets
    ``defaultEnabled: false`` is left out (it loads only when a settings file
    enables it; SKILL-006 still reports it).  Client ``claude-code-plugin``;
    a repository's plugin (scope ``project``) is marked project-scoped, which
    keeps it in the rug-pull state key (``rug_pull.derive_state_path``).
    """
    from mcp_audit.discovery import DiscoveredConfig  # noqa: PLC0415

    out: list[DiscoveredConfig] = []
    for pkg in packages:
        if not pkg.is_plugin:
            continue
        boundary = _realpath(pkg.scan_root)
        manifest_path = pkg.root / ".claude-plugin" / "plugin.json"
        manifest = _load_json(manifest_path, boundary, [])
        if isinstance(manifest, dict) and manifest.get("defaultEnabled") is False:
            continue
        candidates = [pkg.root / ".mcp.json"]
        if isinstance(manifest, dict) and isinstance(manifest.get("mcpServers"), dict):
            candidates.append(manifest_path)
        for path in candidates:
            st = _lstat(path)
            if (
                st is None
                or not stat.S_ISREG(st.st_mode)
                or st.st_size > _JSON_CAP
                or not _inside(path, boundary)
            ):
                continue
            out.append(
                DiscoveredConfig(
                    client_name=SKILLS_DIR_PLUGIN_CLIENT,
                    root_key="mcpServers",
                    path=path,
                    is_project_scoped=pkg.scope == "project",
                )
            )
    return out


def scan_default_skills(
    errors: list[str], prior: list[Finding] | None = None
) -> list[Finding]:
    """The default scan's skill pass: user and cwd skills, TRUST-005 included.

    Never raises; problems go to *errors*.
    """
    try:
        trust: list[Finding] = []
        packages = default_skill_packages(errors=errors, findings=trust)
        return trust + analyze_skill_packages(
            packages, prior=(prior or []) + trust, errors=errors
        )
    except Exception as exc:  # noqa: BLE001 — never crash scan/check
        errors.append(f"skill package: {exc}")
        return []


# ── Sidecars (opt-in, with the SKILL.md rules) ────────────────────────────────


def _sidecar_boundary(root: Path, scope: str) -> Path:
    if scope == "project":
        for parent in root.parents:
            if parent.name == "skills" and parent.parent.name == ".claude":
                return parent.parent.parent
    return _skills_ancestor(root)


def sidecar_findings(af: AgentFile) -> list[Finding]:
    """Apply the ``SKILL.md`` instruction rules to a skill's other prose files.

    SKILL-001, the SKILL-002 obfuscation check and POISON-041/042 apply.  The
    SKILL-002 length check and SKILL-003 (any URL) do not: reference files are
    expected to be long and to link to documentation.  Every prose file in the
    skill directory is read, not only those ``SKILL.md`` links to, because
    references chain (the Paperclip board skill pointed at another skill, which
    pointed at the trojanised setup guide).  Never raises.
    """
    from mcp_audit.agent_files.analyzer import _analyze_skill  # noqa: PLC0415

    if af.surface != AgentFileSurface.CLAUDE_SKILL or af.path.name != "SKILL.md":
        return []
    root = af.path.parent
    pkg = SkillPackage(root, af.scope, _sidecar_boundary(root, af.scope))
    try:
        inv = _walk_package(pkg, ScanBudget(), [])
    except Exception:  # noqa: BLE001 — opt-in pass; never crash the scan
        return []
    out: list[Finding] = []
    for tf in inv.texts:
        if (
            tf.in_git
            or tf.rel == "SKILL.md"
            or tf.path.suffix.lower() not in _PROSE_EXTENSIONS
        ):
            continue
        sidecar = AgentFile(
            path=tf.path,
            surface=AgentFileSurface.CLAUDE_SKILL,
            client=af.client,
            scope=af.scope,
            raw_content=tf.text,
            body=tf.text,
        )
        for f in _analyze_skill(sidecar):
            if f.id == "SKILL-003" or (
                f.id == "SKILL-002" and f.title.startswith("Oversized")
            ):
                continue
            out.extend(_scrub([f], tf.path))
    return out
