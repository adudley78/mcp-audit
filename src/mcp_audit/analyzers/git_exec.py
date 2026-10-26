"""Git can run code: repo-controlled git configuration and repository shapes.

STORY-0089 (EPIC-0007), finding IDs ``TRUST-006`` and ``TRUST-007``.

Coding agents run ``git status`` and ``git diff`` in the background as soon as
they open a folder, before any trust prompt.  Git reads the repository's own
``.git/config`` for those commands, and several of its keys name a program to
run.  A repository that arrives as files with its ``.git`` directory intact (an
archive, a shared drive, a sync folder) therefore runs whatever that file says,
as the user and outside the agent's sandbox.  Manifold Security published this
as GitSpawn (2026-09; seven agents, eight flaws) with ``core.fsmonitor`` as the
named key; CVE-2026-26268 (Cursor) is the ``.git/hooks`` variant; git's own
``safe.bareRepository`` documentation describes the embedded-bare-repository
variant.

This module **never runs git** and never executes anything it reads.  It reads
a handful of small files as text:

- ``<git-dir>/config``, any file it includes that lies inside the scanned tree,
  ``<git-dir>/config.worktree`` and ``<git-dir>/worktrees/*/config.worktree``
  (only when ``extensions.worktreeConfig`` is on, as git does);
- a ``.git`` *file*'s ``gitdir:`` pointer and a git dir's ``commondir`` file;
- a listing (names and modes only) of the hooks directory.

It never walks ``objects/``.  Running git to answer these questions would be the
attack itself.

Public entry points:

- :func:`parse_git_config` — tolerant reader for git's config syntax.
- :func:`check_git_config` — one config file (plus in-tree includes) →
  :class:`GitExecHit` list.  Independent of any discovery plumbing; STORY-0096
  reuses it on plugin checkouts.
- :func:`scan_repository` — a directory holding ``.git`` (dir or file) or a bare
  repository → findings.
- :func:`scan_git_surfaces` — the ``scan --project`` walk's output → findings.
- :func:`scan_cwd_repository` — the repository enclosing the current directory,
  located the way git locates it, → findings (default ``scan`` / ``check``).
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import stat as stat_module
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path

from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.models import Finding, Severity

__all__ = [
    "GIT_FINDING_IDS",
    "GitConfigEntry",
    "GitExecHit",
    "GitSurface",
    "ParsedGitConfig",
    "check_git_config",
    "git_exec_findings",
    "is_bare_repository",
    "parse_git_config",
    "scan_cwd_repository",
    "scan_git_surfaces",
    "scan_repository",
]

#: Git configuration that runs a command (config keys, includes, hooksPath).
GIT_CONFIG_EXEC_ID = "TRUST-006"
#: Repository shapes that make git run repo-controlled code (nested bare
#: repositories, hooks).
GIT_REPO_SHAPE_ID = "TRUST-007"
GIT_FINDING_IDS: frozenset[str] = frozenset({GIT_CONFIG_EXEC_ID, GIT_REPO_SHAPE_ID})

_ANALYZER = "trust"
_CLIENT = "git"
_CWE = "CWE-829"
_OWASP = ["MCP05"]

# git config files are tiny; a padded one is an evasion attempt.  Anything past
# a cap is reported (MEDIUM, "too large to inspect fully"), never silently
# dropped.  The per-file cap bounds one read; the budgets bound one repository
# (its config, every include, and its worktree configs together), so a config
# that includes the same large file many times cannot exhaust memory or time.
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_TOTAL_CONFIG_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_ENTRIES = 20_000
_MAX_INCLUDES = 256
_MAX_INCLUDE_DEPTH = 10  # git's own MAX_INCLUDE_DEPTH (config.c)
_MAX_SMALL_FILE_BYTES = 4096  # .git files, commondir, HEAD
_MAX_DIR_ENTRIES = 512  # hooks/ and worktrees/ listings

_SPACE_NO_NL = " \t\v\f\r"
_SPACE = _SPACE_NO_NL + "\n"

# ══ Parser ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class GitConfigEntry:
    """One ``name = value`` line from a git config file.

    ``var`` is git's own canonical key: the section name lower-cased, the
    subsection exactly as written (``[section "Sub"]``) or lower-cased for the
    deprecated ``[section.sub]`` form, and the variable name lower-cased —
    e.g. ``filter.lfs.smudge``.  ``value`` is ``None`` for a bare ``name`` line,
    which git reads as boolean true.
    """

    var: str
    value: str | None
    path: Path
    line: int

    @property
    def section(self) -> str:
        """The part of :attr:`var` before the first dot (git's own split)."""
        return self.var.split(".", 1)[0]

    @property
    def name(self) -> str:
        """The part of :attr:`var` after the last dot."""
        return self.var.rsplit(".", 1)[-1]

    @property
    def subsection(self) -> str | None:
        """Everything between the first and the last dot, or ``None``."""
        first = self.var.find(".")
        last = self.var.rfind(".")
        if first == last:
            return None
        return self.var[first + 1 : last]


@dataclass
class ParsedGitConfig:
    """Result of :func:`parse_git_config`.

    ``errors`` holds the line numbers git itself would reject.  Git refuses a
    whole config file at its first syntax error (``fatal: bad config line``),
    so the parser records the line and keeps going: over-reading an invalid
    file is the safe direction for a scanner.
    """

    entries: list[GitConfigEntry] = field(default_factory=list)
    errors: list[int] = field(default_factory=list)


def _is_keychar(c: str) -> bool:
    return c.isascii() and (c.isalnum() or c == "-")


def _eol(s: str, i: int) -> int:
    """Index of the next newline at or after *i* (or ``len(s)``)."""
    j = s.find("\n", i)
    return len(s) if j < 0 else j


def _parse_section_header(s: str, i: int) -> tuple[str, int] | None:
    """Parse a header starting just after ``[``; return ``(prefix, next_i)``.

    *prefix* is git's key prefix without the trailing dot: ``core``,
    ``filter.lfs`` (``[filter "lfs"]``) or ``a.b`` (deprecated ``[a.b]``).
    Mirrors ``get_base_var`` / ``get_extended_base_var`` in git's config.c.
    """
    n = len(s)
    base: list[str] = []
    while i < n:
        c = s[i]
        if c == "]":
            return ("".join(base), i + 1) if base else None
        if c in _SPACE:
            return _parse_extended_header(s, i, "".join(base))
        if not (_is_keychar(c) or c == "."):
            return None
        base.append(c.lower())
        i += 1
    return None


def _parse_extended_header(s: str, i: int, base: str) -> tuple[str, int] | None:
    """Parse ``[base "subsection"]`` from the whitespace after *base*."""
    n = len(s)
    while i < n and s[i] in _SPACE:
        if s[i] == "\n":
            return None
        i += 1
    if i >= n or s[i] != '"' or not base:
        return None
    i += 1
    sub: list[str] = []
    while True:
        if i >= n or s[i] == "\n":
            return None
        c = s[i]
        if c == '"':
            break
        if c == "\\":
            i += 1
            if i >= n or s[i] == "\n":
                return None
            c = s[i]
        sub.append(c)
        i += 1
    i += 1  # past the closing quote
    if i >= n or s[i] != "]":
        return None
    return f"{base}.{''.join(sub)}", i + 1


_VALUE_ESCAPES = {"t": "\t", "b": "\b", "n": "\n", "\\": "\\", '"': '"'}


def _parse_value(s: str, i: int) -> tuple[str, int, int, bool]:
    """Parse a value from just after ``=``; mirrors ``parse_value`` in config.c.

    Returns ``(value, index_of_terminating_newline_or_end, continuation_lines,
    ok)``.  ``ok`` is ``False`` where git would reject the line (an unknown
    escape, a newline or end of file inside quotes).
    """
    n = len(s)
    buf: list[str] = []
    quote = False
    comment = False
    trim_len = 0
    newlines = 0
    ok = True
    while i < n:
        c = s[i]
        if c == "\n":
            if quote:
                ok = False
            break
        if comment:
            i += 1
            continue
        if c in _SPACE_NO_NL and not quote:
            if not trim_len:
                trim_len = len(buf)
            if buf:
                buf.append(c)
            i += 1
            continue
        if not quote and c in "#;":
            comment = True
            i += 1
            continue
        trim_len = 0
        if c == "\\":
            i += 1
            if i >= n:
                ok = False
                break
            escaped = s[i]
            if escaped == "\n":  # line continuation
                newlines += 1
                i += 1
                continue
            mapped = _VALUE_ESCAPES.get(escaped)
            if mapped is None:
                ok = False
                mapped = escaped
            buf.append(mapped)
            i += 1
            continue
        if c == '"':
            quote = not quote
            i += 1
            continue
        buf.append(c)
        i += 1
    if quote and i >= n:
        ok = False
    if trim_len:
        del buf[trim_len:]
    return "".join(buf), i, newlines, ok


def parse_git_config(text: str, path: Path | None = None) -> ParsedGitConfig:
    """Parse git config text the way git's own reader does, tolerantly.

    Handles everything ``configparser`` cannot: ``[section "Sub"]`` with
    case-preserved, escaped subsections; the deprecated ``[section.sub]`` form;
    a variable on the same line as its header (``[core] fsmonitor = x``); bare
    boolean keys; double-quoted values with ``\\"`` ``\\\\`` ``\\t`` ``\\n``
    ``\\b`` escapes; ``#`` and ``;`` comments (outside quotes); and
    backslash-newline continuation lines, inside or outside quotes.

    Never raises on malformed input: a line git would reject is recorded in
    :attr:`ParsedGitConfig.errors` and parsing resumes at the next line.

    Args:
        text: The file's contents.
        path: Stamped on every entry for reporting; defaults to ``<memory>``.

    Returns:
        A :class:`ParsedGitConfig` with entries in file order.
    """
    src = path if path is not None else Path("<memory>")
    s = text.replace("\r\n", "\n")
    if s.startswith("\ufeff"):
        s = s[1:]
    n = len(s)
    i = 0
    line = 1
    prefix: str | None = None
    result = ParsedGitConfig()
    while i < n:
        c = s[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in _SPACE_NO_NL:
            i += 1
            continue
        if c in "#;":
            i = _eol(s, i)
            continue
        if c == "[":
            header = _parse_section_header(s, i + 1)
            if header is None:
                result.errors.append(line)
                prefix = None
                i = _eol(s, i)
                continue
            prefix, i = header
            continue
        if prefix is None or not (c.isascii() and c.isalpha()):
            result.errors.append(line)
            i = _eol(s, i)
            continue
        j = i
        while j < n and _is_keychar(s[j]):
            j += 1
        var = f"{prefix}.{s[i:j].lower()}"
        k = j
        while k < n and s[k] in " \t":
            k += 1
        if k >= n or s[k] == "\n":
            result.entries.append(GitConfigEntry(var, None, src, line))
            i = k
            continue
        if s[k] != "=":
            result.errors.append(line)
            i = _eol(s, k)
            continue
        value, i, continuation, ok = _parse_value(s, k + 1)
        result.entries.append(GitConfigEntry(var, value, src, line))
        if not ok:
            result.errors.append(line)
        line += continuation
    return result


# ══ Loading (with includes) ═══════════════════════════════════════════════════


@dataclass(frozen=True)
class _Loaded:
    entry: GitConfigEntry
    via: tuple[Path, ...]  # files that included entry.path, outermost first


@dataclass
class _Budget:
    """What one repository's configuration may still cost to read."""

    # Read at construction time, so the module constants stay the one setting.
    bytes_left: int = field(default_factory=lambda: _MAX_TOTAL_CONFIG_BYTES)
    entries_left: int = field(default_factory=lambda: _MAX_TOTAL_ENTRIES)
    includes_left: int = field(default_factory=lambda: _MAX_INCLUDES)


@dataclass
class _ConfigView:
    entries: list[_Loaded] = field(default_factory=list)
    outside_includes: list[_Loaded] = field(default_factory=list)
    parse_errors: dict[Path, list[int]] = field(default_factory=dict)
    # (file, size on disk, why reading stopped)
    oversize: list[tuple[Path, int, str]] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)

    def extend(self, other: _ConfigView) -> None:
        """Append *other* after this view (later files take precedence)."""
        self.entries.extend(other.entries)
        self.outside_includes.extend(other.outside_includes)
        for path, lines in other.parse_errors.items():
            self.parse_errors.setdefault(path, []).extend(lines)
        self.oversize.extend(other.oversize)
        self.files.extend(other.files)


def _real(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return Path(os.path.abspath(path))


def _within(path: Path | None, root: Path) -> bool:
    """True when *path* resolves inside *root* (both resolved, symlinks followed).

    ``None`` (see :func:`_expand_path`) is never inside.
    """
    if path is None:
        return False
    try:
        _real(path).relative_to(_real(root))
    except ValueError:
        return False
    return True


def _looks_absolute(value: str) -> bool:
    """Absolute on any OS git runs on (POSIX, MSYS ``/c/...``, ``C:\\``, UNC)."""
    return value.startswith(("/", "\\")) or bool(re.match(r"^[A-Za-z]:[\\/]", value))


def _expand_path(value: str, base: Path) -> Path | None:
    """Resolve a git pathname value: ``~`` expansion, else relative to *base*.

    Returns ``None`` for a path that cannot exist on this machine: an absolute
    path in another OS's syntax (``C:/...`` read on Linux, ``/usr/...`` read on
    Windows) or an unknown ``~user``.  Callers treat ``None`` as outside the
    scanned tree, never inside it.
    """
    if value.startswith("~"):
        try:
            return _tidy(Path(value).expanduser())
        except RuntimeError:  # ~user that does not exist
            return None
    if _looks_absolute(value):
        candidate = Path(value)
        return _tidy(candidate) if candidate.is_absolute() else None
    return _tidy(base / value)


def _tidy(path: Path) -> Path:
    """Collapse ``..`` for reporting, unless a symlink makes that change the target."""
    tidy = Path(os.path.normpath(path))
    return tidy if _real(tidy) == _real(path) else path


def _read_text(path: Path, limit: int) -> tuple[str | None, int, int]:
    """Read at most *limit* bytes of a regular file.

    Returns ``(text, size_on_disk, bytes_read)``; ``text`` is ``None`` when the
    path is missing or not a regular file.
    """
    try:
        st = path.stat()
    except OSError:
        return None, 0, 0
    if not stat_module.S_ISREG(st.st_mode):
        return None, 0, 0
    try:
        with path.open("rb") as fh:
            data = fh.read(max(limit, 0))
    except OSError:
        return None, 0, 0
    return data.decode("utf-8", errors="replace"), st.st_size, len(data)


def _is_include(entry: GitConfigEntry) -> bool:
    return entry.name == "path" and (
        entry.var == "include.path"
        or (entry.section == "includeif" and entry.subsection is not None)
    )


# actions/checkout v6+ persists the job token in $RUNNER_TEMP and points the
# checkout's .git/config at it with includeIf.gitdir:<dir>.path entries
# (src/git-auth-helper.ts, configureToken); its own cleanup matches this name.
_CHECKOUT_CREDENTIALS_RE = re.compile(
    r"(^|[/\\])git-credentials-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}"
    r"-[0-9a-f]{12}\.config$",
    re.IGNORECASE,
)


_BUDGET_NOTE = (
    "this repository's configuration, with its includes and worktree configs, is"
    " larger than this scan reads ({what}); the rest was not inspected and git"
    " reads all of it"
)


def _load_config(
    path: Path,
    scan_root: Path,
    budget: _Budget,
    *,
    via: tuple[Path, ...] = (),
) -> _ConfigView:
    """Load one config file, splicing in includes that stay inside *scan_root*.

    Like git, the same file may be included more than once (each inclusion
    re-applies its values at that point); only an include that would loop back
    into the current chain is skipped, since git itself rejects that
    configuration (it exceeds the include depth).  *budget* is shared by every
    file one repository reads.
    """
    view = _ConfigView()
    if budget.bytes_left <= 0:
        view.oversize.append((path, 0, _BUDGET_NOTE.format(what="byte budget")))
        return view
    limit = min(_MAX_CONFIG_BYTES, budget.bytes_left)
    text, size, read = _read_text(path, limit)
    if text is None:
        return view
    budget.bytes_left -= read
    view.files.append(path)
    if size > read:
        why = (
            f"the file is {size} bytes; this scan read the first {read} and git"
            " reads all of it"
            if read >= _MAX_CONFIG_BYTES
            else _BUDGET_NOTE.format(what="byte budget")
        )
        view.oversize.append((path, size, why))
    parsed = parse_git_config(text, path)
    if parsed.errors:
        view.parse_errors[path] = list(parsed.errors)
    entries = parsed.entries
    if len(entries) > budget.entries_left:
        entries = entries[: max(budget.entries_left, 0)]
        view.oversize.append((path, size, _BUDGET_NOTE.format(what="entry budget")))
    budget.entries_left -= len(entries)
    chain = {_real(p) for p in (*via, path)}
    for entry in entries:
        loaded = _Loaded(entry, via)
        view.entries.append(loaded)
        raw = (entry.value or "").strip()
        if not raw or not _is_include(entry):
            continue
        target = _expand_path(raw, path.parent)
        if target is None or not _within(target, scan_root):
            if not _CHECKOUT_CREDENTIALS_RE.search(raw):
                view.outside_includes.append(loaded)
            continue
        if len(via) + 1 >= _MAX_INCLUDE_DEPTH or _real(target) in chain:
            continue
        if not target.is_file():
            continue
        if budget.includes_left <= 0:
            view.oversize.append(
                (path, size, _BUDGET_NOTE.format(what="include budget"))
            )
            continue
        budget.includes_left -= 1
        # Git inserts the included file's entries at the directive.
        view.extend(_load_config(target, scan_root, budget, via=(*via, path)))
    return view


# ══ Rules ═════════════════════════════════════════════════════════════════════

_RUNS_INDEX = (
    "every time git refreshes the index: `git status`, `git diff`, `git add`,"
    " `git commit` — the commands coding agents run in the background as soon as"
    " they open a folder"
)
_RUNS_DIFF = "on `git diff`, `git log -p` and `git show`"
_RUNS_ATTR_DIFF = (
    "on `git diff`, `git log -p`, `git show` and `git blame` for files whose"
    " attributes (`.gitattributes`, `.git/info/attributes`) select this driver"
)
_RUNS_CLEAN = (
    "on `git add`, `git status`, `git diff` and `git commit` for files whose"
    " attributes select this filter"
)
_RUNS_SMUDGE = (
    "on `git checkout`, `git switch`, `git reset` and `git pull` for files whose"
    " attributes select this filter"
)
_RUNS_PROCESS = "on checkout and add for files whose attributes select this filter"
_RUNS_SSH = "on `git fetch`, `git pull` and `git push` to an SSH remote"
_RUNS_CREDENTIAL = (
    "whenever git needs a password or token: `git fetch`, `git pull`, `git push`"
)
_RUNS_PAGER = "when git output goes to a terminal (`git log`, `git diff`)"
_RUNS_EDITOR = (
    "when git opens an editor: `git commit` without `-m`, `git merge`,"
    " `git rebase --continue`"
)
_RUNS_SEQUENCE_EDITOR = "on `git rebase -i`"
_RUNS_ASKPASS = "when git asks for a password and no credential helper answers"
_RUNS_GPG = (
    "when git signs or verifies: `git commit -S`, or every commit with `commit.gpgSign`"
)
_RUNS_MERGE = (
    "on `git merge`, `git pull` and `git rebase` for files whose attributes"
    " select this driver"
)
_RUNS_ALIAS = "when someone runs `git <alias>`"
_RUNS_SUBMODULE = "on `git submodule update`"
_RUNS_GITPROXY = "on fetches over the `git://` protocol"
_RUNS_REMOTE_PACK = (
    "on `git fetch` / `git push` to that remote over a local path or SSH"
)

_PAGERS = frozenset({"cat", "less", "more", "most", "delta", "bat", "lv", "moar"})
# fmt: off
_EDITORS = frozenset({
    "vi", "vim", "nvim", "gvim", "mvim", "nano", "pico", "emacs", "emacsclient",
    "code", "code-insiders", "codium", "cursor", "subl", "mate", "micro", "hx",
    "kak", "gedit", "kate", "notepad", "notepad++", "zed",
})
# Text converters people point diff.<driver>.textconv at.  They read the file
# git hands them and print text; none runs code from its input, as long as the
# options in _CONVERTER_RISKY_OPTIONS are absent and no argument names a file
# inside the repository.  Interpreters (python, node, bun, …) are deliberately
# not here: they run whatever file git routes to them.
_CONVERTERS = frozenset({
    "exiftool", "docx2txt", "pdftotext", "pandoc", "odt2txt", "strings",
    "hexdump", "xxd", "cat", "sops", "gpg", "gpg2", "ansible-vault", "age", "unzip",
})
# Options that make a converter load code or a config that can run code.
_CONVERTER_RISKY_OPTIONS: dict[str, tuple[str, ...]] = {
    "pandoc": ("--filter", "-F", "--lua-filter", "-L", "--defaults", "-d",
               "--data-dir"),
    "exiftool": ("-config", "-@", "-if", "-p", "-api", "-userparam"),
    "sops": ("exec-env", "exec-file"),
    "ansible-vault": ("--vault-password-file", "--vault-pass-file", "--vault-id",
                      "--new-vault-password-file", "--new-vault-id"),
    "gpg": ("--options", "--homedir", "--photo-viewer", "--exec-path",
            "--load-extension"),
    "gpg2": ("--options", "--homedir", "--photo-viewer", "--exec-path",
             "--load-extension"),
}
_SIGNERS = frozenset({
    "gpg", "gpg2", "gpgsm", "gitsign", "ssh-keygen", "smimesign", "op-ssh-sign",
})
# fmt: on


@dataclass(frozen=True)
class _Rule:
    label: str  # display form, e.g. "filter.<driver>.smudge"
    section: str
    name: str  # "*" = any variable name in the section
    subsection: str  # "none" | "any" | "either"
    tier: Severity
    runs: str
    kind: str = "command"  # command | bool-or-command | bang | ssh | credential
    known: frozenset[str] = frozenset()
    known_args: str = "any"  # "any" | "flags" | "converter"
    python_modules: frozenset[str] = frozenset()


_H = Severity.HIGH
_M = Severity.MEDIUM
_L = Severity.LOW

# Keys whose value git runs as a program.  HIGH: git runs it on its own during
# commands agents run unprompted (status/diff/add/checkout/fetch/push).  MEDIUM:
# a git action an agent may well take (commit, merge, rebase, push without a
# helper, submodule update).  LOW: only on an explicit, unusual invocation.
# ``known`` lists the tools whose installers write these keys into a repo's own
# config (git lfs install --local, git-crypt unlock, nbstripout --install,
# husky, gitsign); a known tool run from outside the tree is reported once, as
# INFO inventory, not as a finding to fail CI on.
# fmt: off
_RULES: tuple[_Rule, ...] = (
    # label, section, name, subsection, tier, when it runs, …
    _Rule("core.fsmonitor", "core", "fsmonitor", "none", _H, _RUNS_INDEX,
          kind="bool-or-command", known=frozenset({"rs-git-fsmonitor"})),
    _Rule("core.sshCommand", "core", "sshcommand", "none", _H, _RUNS_SSH, kind="ssh"),
    _Rule("diff.external", "diff", "external", "none", _H, _RUNS_DIFF,
          known=frozenset({"difft"})),
    _Rule("diff.<driver>.command", "diff", "command", "any", _H, _RUNS_ATTR_DIFF,
          known=frozenset({"git-nbdiffdriver", "difft"})),
    _Rule("diff.<driver>.textconv", "diff", "textconv", "any", _H, _RUNS_ATTR_DIFF,
          known=frozenset({"git-crypt", "nbstripout"}) | _CONVERTERS,
          known_args="converter", python_modules=frozenset({"nbstripout"})),
    # `cat` is what nbstripout --install writes as its smudge filter.
    _Rule("filter.<driver>.clean", "filter", "clean", "any", _H, _RUNS_CLEAN,
          known=frozenset({"git-lfs", "git-crypt", "git-annex", "nbstripout", "cat"}),
          python_modules=frozenset({"nbstripout"})),
    _Rule("filter.<driver>.smudge", "filter", "smudge", "any", _H, _RUNS_SMUDGE,
          known=frozenset({"git-lfs", "git-crypt", "git-annex", "nbstripout", "cat"}),
          python_modules=frozenset({"nbstripout"})),
    _Rule("filter.<driver>.process", "filter", "process", "any", _H, _RUNS_PROCESS,
          known=frozenset({"git-lfs", "git-annex"})),
    _Rule("credential.helper", "credential", "helper", "either", _H, _RUNS_CREDENTIAL,
          kind="credential"),
    _Rule("core.editor", "core", "editor", "none", _M, _RUNS_EDITOR,
          known=_EDITORS, known_args="flags"),
    _Rule("sequence.editor", "sequence", "editor", "none", _M, _RUNS_SEQUENCE_EDITOR,
          known=_EDITORS, known_args="flags"),
    _Rule("core.askPass", "core", "askpass", "none", _M, _RUNS_ASKPASS),
    _Rule("gpg.program", "gpg", "program", "none", _M, _RUNS_GPG,
          known=_SIGNERS, known_args="flags"),
    _Rule("gpg.<format>.program", "gpg", "program", "any", _M, _RUNS_GPG,
          known=_SIGNERS, known_args="flags"),
    _Rule("merge.<driver>.driver", "merge", "driver", "any", _M, _RUNS_MERGE,
          known=frozenset({"true", "git-nbmergedriver", "git-lfs"})),
    _Rule("submodule.<name>.update", "submodule", "update", "any", _M, _RUNS_SUBMODULE,
          kind="bang"),
    _Rule("remote.<name>.uploadpack", "remote", "uploadpack", "any", _M,
          _RUNS_REMOTE_PACK, known=frozenset({"git-upload-pack"})),
    _Rule("remote.<name>.receivepack", "remote", "receivepack", "any", _M,
          _RUNS_REMOTE_PACK, known=frozenset({"git-receive-pack"})),
    _Rule("core.pager", "core", "pager", "none", _L, _RUNS_PAGER,
          known=_PAGERS, known_args="flags"),
    _Rule("pager.<command>", "pager", "*", "none", _L, _RUNS_PAGER,
          kind="bool-or-command", known=_PAGERS, known_args="flags"),
    _Rule("alias.<name>", "alias", "*", "none", _L, _RUNS_ALIAS, kind="bang"),
    _Rule("core.gitProxy", "core", "gitproxy", "none", _L, _RUNS_GITPROXY),
)
# fmt: on

# Multi-valued keys: every occurrence counts.  Everything else is last-one-wins,
# as in git (a later `core.fsmonitor = false` disables an earlier command).
_MULTI_VALUED_SECTIONS = frozenset({"credential"})


def _match_rule(entry: GitConfigEntry) -> _Rule | None:
    section = entry.section
    sub = entry.subsection
    name = entry.name
    for rule in _RULES:
        if rule.section != section:
            continue
        if rule.name not in ("*", name):
            continue
        if rule.subsection == "none" and sub is not None:
            continue
        if rule.subsection == "any" and sub is None:
            continue
        return rule
    return None


_SHELL_META_RE = re.compile(r"[;&|<>`\r\n]|\$\(")
_FLAG_RE = re.compile(r"^--?[A-Za-z][A-Za-z0-9-]*(=[A-Za-z0-9._/:@%+~-]*)?$")
_PYTHON_RE = re.compile(r"^python(w)?(\d+(\.\d+)*)?$")
_BOOL_WORDS = frozenset({"true", "false", "yes", "no", "on", "off", ""})
_INT_RE = re.compile(r"^[+-]?\d+[kmg]?$", re.IGNORECASE)


def _is_git_bool(value: str | None) -> bool:
    if value is None:
        return True
    v = value.strip().lower()
    return v in _BOOL_WORDS or bool(_INT_RE.match(v))


def _program_basename(prog: str) -> str:
    base = re.split(r"[\\/]", prog)[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".com"):
        if base.endswith(ext):
            return base[: -len(ext)]
    return base


@dataclass(frozen=True)
class _Ctx:
    repo_root: Path  # where git runs commands from (worktree, or $GIT_DIR if bare)
    scan_root: Path  # boundary of repo-controlled files


def _lexically_within(path: Path, root: Path) -> bool:
    """True when *path* is inside *root* before following symlinks below *root*.

    A repository's ``.venv/bin/python`` is a symlink to a system interpreter,
    yet Python treats it as the repository's environment (its ``pyvenv.cfg`` and
    ``site-packages``), so where a program *is* matters, not where it points.
    """
    target = _real(root)
    tidy = Path(os.path.normpath(path))
    return any(_real(ancestor) == target for ancestor in (tidy, *tidy.parents))


def _in_tree(path: Path | None, root: Path) -> bool:
    """Inside *root* either as written or once symlinks are followed."""
    if path is None:
        return False
    return _within(path, root) or _lexically_within(path, root)


def _program_location(prog: str, ctx: _Ctx) -> str:
    """``"path-lookup"``, ``"outside"`` or ``"in-tree"`` for a command's program."""
    if "/" not in prog and "\\" not in prog:
        return "path-lookup"
    candidate = _expand_path(prog, ctx.repo_root)
    return "in-tree" if _in_tree(candidate, ctx.scan_root) else "outside"


def _in_tree_environment(prog: str, ctx: _Ctx) -> bool:
    """True when *prog* lives in a Python environment inside the tree.

    An environment is a directory with a ``pyvenv.cfg`` (venv/virtualenv) or a
    ``conda-meta/`` directory (conda), one or two levels above the program
    (``env/bin/python``, ``env\\Scripts\\python.exe``, ``env\\python.exe``).
    """
    candidate = _expand_path(prog, ctx.repo_root)
    if candidate is None:
        return False
    tidy = Path(os.path.normpath(candidate))
    for env in (tidy.parent.parent, tidy.parent):
        try:
            marked = (env / "pyvenv.cfg").is_file() or (env / "conda-meta").is_dir()
        except OSError:
            marked = False
        if marked:
            return _in_tree(env, ctx.scan_root)
    return False


def _shadows_module(root: Path, module: str) -> bool:
    """True when *root* holds an entry Python's ``-m module`` could import first.

    ``module.py``, ``module/``, a sourceless ``module.pyc``, an extension
    ``module.cpython-312-x86_64-linux-gnu.so`` or ``module.pyd``: any entry named
    ``module`` or ``module.<anything>``.
    """
    try:
        names = os.listdir(root)
    except OSError:
        return False
    return any(n == module or n.startswith(f"{module}.") for n in names)


def _tokens(cmd: str) -> list[str] | None:
    if _SHELL_META_RE.search(cmd):
        return None
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        return None
    return tokens or None


@dataclass(frozen=True)
class _Verdict:
    status: str  # "known" | "known-in-venv" | "unknown"
    tool: str | None = None
    note: str = ""


_UNKNOWN = _Verdict("unknown")


def _locate_known(prog: str, tool: str, ctx: _Ctx) -> _Verdict:
    location = _program_location(prog, ctx)
    if location != "in-tree":
        return _Verdict("known", tool)
    if _in_tree_environment(prog, ctx):
        return _Verdict(
            "known-in-venv",
            tool,
            f"the program is {tool}, but it runs from a Python environment inside"
            " the scanned tree (it has a pyvenv.cfg or conda-meta), so a"
            " repository that ships that environment controls the code that runs",
        )
    return _Verdict(
        "unknown",
        None,
        f"the program path `{prog}` is inside the scanned tree, so the repository"
        " controls what runs",
    )


def _classify_command(cmd: str, rule: _Rule, ctx: _Ctx) -> _Verdict:
    """Decide whether *cmd* is a known tool's command form (see ``_Rule.known``)."""
    if not rule.known and not rule.python_modules:
        return _UNKNOWN
    tokens = _tokens(cmd)
    if tokens is None:
        return _UNKNOWN
    prog, args = tokens[0], tokens[1:]
    base = _program_basename(prog)
    tool: str | None = None
    # `git lfs …` is deliberately not accepted as git-lfs: when git-lfs is not
    # installed, git runs `alias.lfs` instead, which the same config can define.
    # Installers write the `git-lfs …` form.
    if base in rule.known:
        tool = base
    elif _PYTHON_RE.match(base) and len(args) >= 2 and args[0] == "-m":
        module = args[1]
        if module in rule.python_modules:
            # `python -m X` puts the working directory (the repo root) first on
            # sys.path, so a repo-root X.py, X/, X.pyc or X.*.so would run instead.
            if _shadows_module(ctx.repo_root, module):
                return _Verdict(
                    "unknown",
                    None,
                    f"`python -m {module}` runs from the repo root, which holds its"
                    f" own `{module}` module, so the repository's copy would run",
                )
            tool, args = module, args[2:]
    if tool is None:
        return _UNKNOWN
    if rule.known_args == "flags" and not all(
        a == "" or _FLAG_RE.match(a) for a in args
    ):
        return _UNKNOWN
    if rule.known_args == "converter" and not _converter_args_ok(tool, args, ctx):
        return _Verdict(
            "unknown",
            None,
            f"`{tool}` is given an option or a file inside the repository that can"
            " make it load code",
        )
    return _locate_known(prog, tool, ctx)


def _arg_is_risky(tool: str, arg: str) -> bool:
    for opt in _CONVERTER_RISKY_OPTIONS.get(tool, ()):
        if arg == opt or arg.startswith(f"{opt}="):
            return True
        if len(opt) == 2 and opt.startswith("-") and arg.startswith(opt):
            return True  # attached short option, e.g. -Lfilter.lua
    return False


def _arg_points_in_tree(arg: str, ctx: _Ctx) -> bool:
    value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
    if not value or (value.startswith("-") and "=" not in arg):
        return False
    pathlike = (
        value.startswith((".", "~"))
        or "/" in value
        or "\\" in value
        or _looks_absolute(value)
    )
    return pathlike and _in_tree(_expand_path(value, ctx.repo_root), ctx.scan_root)


def _converter_args_ok(tool: str, args: list[str], ctx: _Ctx) -> bool:
    """No code-loading option and no argument naming a file inside the repo."""
    return not any(_arg_is_risky(tool, a) or _arg_points_in_tree(a, ctx) for a in args)


_SSH_PROGRAMS = frozenset({"ssh", "plink", "tortoiseplink"})
# ssh -o options that cannot start a program or load code.  Anything else
# (ProxyCommand, LocalCommand, KnownHostsCommand, Match exec, Include,
# PKCS11Provider, SecurityKeyProvider, XAuthLocation, …) keeps the finding HIGH.
# fmt: off
_SSH_SAFE_OPTIONS = frozenset({
    "addkeystoagent", "addressfamily", "batchmode", "certificatefile",
    "checkhostip", "ciphers", "compression", "connectionattempts",
    "connecttimeout", "controlmaster", "controlpath", "controlpersist",
    "forwardagent", "globalknownhostsfile", "hashknownhosts", "hostkeyalgorithms",
    "hostkeyalias", "hostname", "identitiesonly", "identityagent", "identityfile",
    "ipqos", "kexalgorithms", "loglevel", "macs", "passwordauthentication", "port",
    "preferredauthentications", "pubkeyacceptedalgorithms",
    "pubkeyacceptedkeytypes", "requesttty", "serveralivecountmax",
    "serveraliveinterval", "stricthostkeychecking", "tcpkeepalive",
    "updatehostkeys", "user", "userknownhostsfile", "verifyhostkeydns",
})
# fmt: on
_SSH_ARG_FLAGS = frozenset({"-i", "-p", "-l", "-P"})
_SSH_STANDALONE_RE = re.compile(
    r"^(-[46AaCkNnqTtvXxYy]+|-batch|-ssh|-agent|-noagent|-noshare|-share)$"
)


def _ssh_option_ok(option: str) -> bool:
    key = re.split(r"[=\s]", option.strip(), maxsplit=1)[0].lower()
    return key in _SSH_SAFE_OPTIONS


def _classify_ssh(cmd: str, ctx: _Ctx) -> _Verdict:
    """A plain ``ssh`` invocation with key/port/known-hosts options is known."""
    tokens = _tokens(cmd)
    if tokens is None:
        return _UNKNOWN
    prog = tokens[0]
    if _program_basename(prog) not in _SSH_PROGRAMS:
        return _UNKNOWN
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t in _SSH_ARG_FLAGS:
            if i + 1 >= len(tokens):
                return _UNKNOWN
            i += 2
            continue
        if len(t) > 2 and t[:2] in ("-i", "-l"):
            i += 1
            continue
        if t == "-F":
            if i + 1 >= len(tokens):
                return _UNKNOWN
            cfg = tokens[i + 1]
            if cfg not in ("/dev/null", "NUL") and _in_tree(
                _expand_path(cfg, ctx.repo_root), ctx.scan_root
            ):
                return _Verdict(
                    "unknown",
                    None,
                    "ssh reads its config (`-F`) from inside the scanned tree,"
                    " and an ssh config can run commands (ProxyCommand)",
                )
            i += 2
            continue
        if t == "-o":
            if i + 1 >= len(tokens) or not _ssh_option_ok(tokens[i + 1]):
                return _UNKNOWN
            i += 2
            continue
        if t.startswith("-o"):
            if not _ssh_option_ok(t[2:]):
                return _UNKNOWN
            i += 1
            continue
        if _SSH_STANDALONE_RE.match(t):
            i += 1
            continue
        return _UNKNOWN
    return _locate_known(prog, _program_basename(prog), ctx)


def _classify_credential(value: str, ctx: _Ctx) -> _Verdict | None:
    """``None`` when the helper value is not a command form at all."""
    stripped = value.strip()
    if not stripped.startswith("!"):
        # A helper name (`store`, `osxkeychain`, `manager`) runs
        # `git credential-<name>` from git's own exec path; an absolute path
        # runs that file, which matters only when the repository ships it.
        first = stripped.split()[0] if stripped.split() else ""
        if (
            first
            and _looks_absolute(first)
            and _in_tree(_expand_path(first, ctx.repo_root), ctx.scan_root)
        ):
            return _Verdict(
                "unknown",
                None,
                "the helper is a program inside the scanned tree",
            )
        return None
    tokens = _tokens(stripped[1:])
    if (
        tokens is not None
        and len(tokens) == 3
        and _program_basename(tokens[0]) == "gh"
        and tokens[1:] == ["auth", "git-credential"]
    ):
        return _locate_known(tokens[0], "gh", ctx)
    return _UNKNOWN


# ══ Evaluation ════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class GitExecHit:
    """One reason git would run something, found in one config file.

    ``finding_id`` is always ``TRUST-006`` (git configuration).  ``tool`` is set
    when the command is a recognised tool's own form (severity INFO).
    """

    severity: Severity
    rule: str
    key: str
    value: str | None
    path: Path
    line: int
    via: tuple[Path, ...]
    runs: str
    note: str = ""
    tool: str | None = None
    kind: str = "command"  # command | include-outside | hooks-path | oversize
    finding_id: str = GIT_CONFIG_EXEC_ID


def _effective(view: _ConfigView) -> list[tuple[_Loaded, _Rule]]:
    """Rule-matched entries git would actually use (last-wins / reset rules)."""
    matched: list[tuple[_Loaded, _Rule]] = []
    last_index: dict[str, int] = {}
    reset_index: dict[str, int] = {}
    for idx, loaded in enumerate(view.entries):
        var = loaded.entry.var
        last_index[var] = idx
        if (
            loaded.entry.section in _MULTI_VALUED_SECTIONS
            and not (loaded.entry.value or "").strip()
        ):
            reset_index[var] = idx  # an empty helper resets the list
    for idx, loaded in enumerate(view.entries):
        rule = _match_rule(loaded.entry)
        if rule is None:
            continue
        var = loaded.entry.var
        if rule.section in _MULTI_VALUED_SECTIONS:
            if idx <= reset_index.get(var, -1):
                continue
        elif last_index[var] != idx:
            continue
        matched.append((loaded, rule))
    return matched


def _last_value(view: _ConfigView, var: str) -> _Loaded | None:
    found = None
    for loaded in view.entries:
        if loaded.entry.var == var:
            found = loaded
    return found


def _hit(
    loaded: _Loaded,
    severity: Severity,
    rule: str,
    runs: str,
    *,
    note: str = "",
    tool: str | None = None,
    kind: str = "command",
) -> GitExecHit:
    entry = loaded.entry
    return GitExecHit(
        severity=severity,
        rule=rule,
        key=entry.var,
        value=entry.value,
        path=entry.path,
        line=entry.line,
        via=loaded.via,
        runs=runs,
        note=note,
        tool=tool,
        kind=kind,
    )


# SHA-256 of git's own fsmonitor-watchman hook sample, every version git has
# shipped (templates/hooks--fsmonitor-watchman.sample, renamed
# templates/hooks/fsmonitor-watchman.sample in 2.48), read from the v2.16.0 …
# v2.56.0 release tags at build time (2026-10-25).  Watchman's documented
# setup copies that sample to .git/hooks/query-watchman and points
# core.fsmonitor at it.  Only an exact copy counts: a matching header proves
# nothing, since a payload can follow it.
_WATCHMAN_SAMPLE_SHA256: frozenset[str] = frozenset(
    {
        "7f9cacf1f7c8f791abfaa76171b951a55a9a2a11f1390b43cbc83995b4a91b33",  # 2.16–2.24
        "9c34ab6527211ec8605b2a563f5329ed8f66dbfbd11e677c78da6c3171085604",  # 2.25
        "f3c0228d8e827f1c5260ac59fdd92c3d425c46e54711ef713c5a54ae0a4db2b4",  # 2.26–2.36
        "e0549964e93897b519bd8e333c037e51fff0f88ba13e086a331592bf801fa1d0",  # 2.37–2.53
        "9159720099ad5595b8e66645cbfd47763c1e920f46e0b50ae75e642bbec57ef0",  # 2.54–2.56
    }
)
_WATCHMAN_TOOL = "git's fsmonitor-watchman sample (unmodified)"
_MAX_HOOK_HASH_BYTES = 64 * 1024


def _is_watchman_sample(cmd: str, ctx: _Ctx) -> bool:
    """True when *cmd* is a path to an unmodified copy of git's watchman sample."""
    tokens = _tokens(cmd)
    if tokens is None or len(tokens) != 1:
        return False
    hook = _expand_path(tokens[0], ctx.repo_root)
    if hook is None:
        return False
    try:
        if not hook.is_file() or hook.stat().st_size > _MAX_HOOK_HASH_BYTES:
            return False
        data = hook.read_bytes()
    except OSError:
        return False
    digests = {
        hashlib.sha256(data).hexdigest(),
        hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest(),
    }
    return not digests.isdisjoint(_WATCHMAN_SAMPLE_SHA256)


def _evaluate_rule(loaded: _Loaded, rule: _Rule, ctx: _Ctx) -> GitExecHit | None:
    value = loaded.entry.value
    if rule.kind == "bool-or-command":
        if _is_git_bool(value):
            return None
        command = value or ""
    elif rule.kind == "bang":
        if value is None or not value.strip().startswith("!"):
            return None
        command = value.strip()[1:]
    else:
        if value is None or not value.strip():
            return None
        command = value
    if rule.label == "core.gitProxy" and command.strip().lower() == "none":
        return None

    if rule.kind == "credential":
        verdict = _classify_credential(command, ctx)
        if verdict is None:
            return None
    elif rule.label == "core.fsmonitor" and _is_watchman_sample(command, ctx):
        verdict = _Verdict("known", _WATCHMAN_TOOL)
    elif rule.kind == "ssh":
        verdict = _classify_ssh(command, ctx)
    else:
        verdict = _classify_command(command, rule, ctx)

    if verdict.status == "known":
        return _hit(loaded, Severity.INFO, rule.label, rule.runs, tool=verdict.tool)
    if verdict.status == "known-in-venv":
        severity = Severity.MEDIUM if rule.tier == Severity.HIGH else rule.tier
        return _hit(loaded, severity, rule.label, rule.runs, note=verdict.note)
    return _hit(loaded, rule.tier, rule.label, rule.runs, note=verdict.note)


def _hooks_path_hit(loaded: _Loaded, ctx: _Ctx) -> GitExecHit | None:
    value = (loaded.entry.value or "").strip()
    if not value or value in ("/dev/null", "NUL"):
        return None
    target = _expand_path(value, ctx.repo_root)
    runs = (
        "on commit, checkout, merge, rebase and push (whichever hooks the"
        " directory holds)"
    )
    if _within(target, ctx.scan_root):
        return _hit(
            loaded,
            Severity.INFO,
            "core.hooksPath",
            runs,
            note=(
                f"git runs hooks from `{value}`, inside the repository (husky and"
                " similar tools set this); those hook files are ordinary repo files,"
                " so review changes to them like code"
            ),
            kind="hooks-path",
        )
    return _hit(
        loaded,
        Severity.MEDIUM,
        "core.hooksPath",
        runs,
        note=(
            f"git runs hooks from `{value}`, outside the scanned tree, which this"
            " scan did not inspect"
        ),
        kind="hooks-path",
    )


def _evaluate(view: _ConfigView, ctx: _Ctx) -> list[GitExecHit]:
    hits: list[GitExecHit] = []
    for loaded, rule in _effective(view):
        hit = _evaluate_rule(loaded, rule, ctx)
        if hit is not None:
            hits.append(hit)
    hooks_path = _last_value(view, "core.hookspath")
    if hooks_path is not None:
        hit = _hooks_path_hit(hooks_path, ctx)
        if hit is not None:
            hits.append(hit)
    for loaded in view.outside_includes:
        hits.append(
            _hit(
                loaded,
                Severity.MEDIUM,
                loaded.entry.var,
                "on every git command in this repository",
                note=(
                    "the included file is outside the scanned tree, so this scan did"
                    " not read it; any command key it sets applies here"
                ),
                kind="include-outside",
            )
        )
    seen_oversize: set[tuple[Path, str]] = set()
    for path, _size, why in view.oversize:
        if (path, why) in seen_oversize:
            continue
        seen_oversize.add((path, why))
        hits.append(
            GitExecHit(
                severity=Severity.MEDIUM,
                rule="(file size)",
                key="(whole file)",
                value=None,
                path=path,
                line=0,
                via=(),
                runs="on every git command in this repository",
                note=why,
                kind="oversize",
            )
        )
    return hits


def _default_roots(
    config_path: Path, repo_root: Path | None, scan_root: Path | None
) -> tuple[Path, Path]:
    if repo_root is None:
        parent = config_path.parent
        repo_root = parent.parent if parent.name == ".git" else parent
    return repo_root, scan_root if scan_root is not None else repo_root


def check_git_config(
    config_path: Path,
    *,
    repo_root: Path | None = None,
    scan_root: Path | None = None,
) -> list[GitExecHit]:
    """Report every way one git config file makes git run a program.

    Reads *config_path* (never runs git), splices in ``include.path`` /
    ``includeIf.*.path`` targets that resolve inside *scan_root*, applies git's
    last-one-wins rule, and returns one :class:`GitExecHit` per key that runs a
    command, per include that points outside *scan_root*, and for
    ``core.hooksPath``.  Recognised tools' own command forms (git-lfs, git-crypt,
    nbstripout, a plain ``ssh -i key``, …) come back as INFO hits.

    This is the standalone entry point STORY-0096 reuses on plugin checkouts;
    it depends on no discovery plumbing.  It does not apply
    ``extensions.worktreeConfig`` or look at hooks; :func:`scan_repository`
    does both.

    Args:
        config_path: A git config file (``.git/config``, a bare repo's
            ``config``, ``config.worktree``).
        repo_root: Directory git runs commands from (the worktree, or the git
            dir for a bare repository); relative program paths and
            ``core.hooksPath`` resolve against it.  Defaults to the parent of
            ``.git`` when *config_path* is ``.git/config``, else its directory.
        scan_root: Boundary of repository-controlled files.  Defaults to
            *repo_root*.

    Returns:
        Hits in file order; empty when the file is missing or harmless.
    """
    repo_root, scan_root = _default_roots(config_path, repo_root, scan_root)
    view = _load_config(config_path, scan_root, _Budget())
    hits = _evaluate(view, _Ctx(repo_root=repo_root, scan_root=scan_root))
    return _annotate_parse_errors(hits, view)


def _annotate_parse_errors(
    hits: list[GitExecHit], view: _ConfigView
) -> list[GitExecHit]:
    if not view.parse_errors:
        return hits
    out: list[GitExecHit] = []
    for hit in hits:
        lines = view.parse_errors.get(hit.path)
        if not lines:
            out.append(hit)
            continue
        extra = (
            f"git itself rejects this file (syntax error at line {lines[0]}) and"
            " stops before running anything; other git implementations may not"
        )
        out.append(replace(hit, note=f"{hit.note}; {extra}" if hit.note else extra))
    return out


# ══ Findings ══════════════════════════════════════════════════════════════════


_REDACTED = "[REDACTED]"


def _redact(text: str) -> str:
    """Scrub credential-shaped substrings (``SECRET_PATTERNS``) from report text.

    Git config values can embed tokens (a ``!`` credential helper that echoes a
    password, a URL with userinfo); findings go to terminals, JSON, SARIF and
    PR comments, so they never carry them.
    """
    cleaned = text
    for _label, pattern, _provider in SECRET_PATTERNS:
        cleaned = pattern.sub(_REDACTED, cleaned)
    return cleaned


def _finding(**fields: object) -> Finding:
    """Build a Finding with every human-readable field redacted."""
    for name in ("title", "description", "evidence", "remediation"):
        fields[name] = _redact(str(fields[name]))
    return Finding(**fields)  # type: ignore[arg-type]


def _evidence(hit: GitExecHit) -> str:
    parts = [f"{hit.path}:{hit.line}" if hit.line else str(hit.path)]
    if hit.kind != "oversize":
        parts.append(f"{hit.key} = {hit.value!r}")
    if hit.via:
        parts.append("included from " + " -> ".join(str(p) for p in hit.via))
    return " | ".join(parts)


_DELIVERY = (
    " A repository that arrives with its `.git` directory intact (an archive, a"
    " shared drive, a sync folder) brings this file with it, and coding agents run"
    " `git status` and `git diff` in the background as soon as they open a folder,"
    " before any trust prompt (GitSpawn, Manifold Security, 2026). The command runs"
    " as you, outside the agent's sandbox."
)


def _remediation(key: str) -> str:
    return (
        f"If you did not set `{key}`, delete it with a text editor before running"
        " git or opening an agent in this repository, then find out how it got"
        " there. For a one-off git command until then, override the key on the"
        " command line (for example `git -c core.fsmonitor=false status`)."
    )


def git_exec_findings(hits: Iterable[GitExecHit]) -> list[Finding]:
    """Turn :class:`GitExecHit` objects into ``TRUST-006`` findings.

    HIGH/MEDIUM/LOW hits become one finding each.  INFO hits for recognised
    tools are folded into one inventory finding per config file;
    ``core.hooksPath`` inside the repository is its own INFO finding.
    """
    findings: list[Finding] = []
    known_by_file: dict[Path, list[GitExecHit]] = {}
    for hit in hits:
        if hit.tool is not None and hit.severity == Severity.INFO:
            known_by_file.setdefault(hit.path, []).append(hit)
            continue
        findings.append(_hit_finding(hit))
    for path, known in known_by_file.items():
        tools = sorted({h.tool for h in known if h.tool})
        findings.append(
            _finding(
                id=GIT_CONFIG_EXEC_ID,
                severity=Severity.INFO,
                analyzer=_ANALYZER,
                client=_CLIENT,
                server="(git config)",
                title="Git config runs known tools",
                description=(
                    f"'{path}' makes git run {', '.join(tools)} through"
                    f" {len(known)} key(s). These are the command forms those tools'"
                    " own installers write (for example `git lfs install --local`),"
                    " run from outside the repository, so this is inventory, not a"
                    " finding to act on."
                ),
                evidence=" | ".join(
                    f"{h.path}:{h.line} {h.key} = {h.value!r}" for h in known
                ),
                remediation=(
                    "No action needed if you installed these tools for this repository."
                ),
                cwe=_CWE,
                owasp_mcp_top_10=list(_OWASP),
                finding_path=str(path),
            )
        )
    return findings


def _hit_finding(hit: GitExecHit) -> Finding:
    note = f" Why this severity: {hit.note}." if hit.note else ""
    if hit.kind == "include-outside":
        title = "Git config includes a file from outside the scanned tree"
        description = (
            f"'{hit.path}' sets `{hit.key} = {hit.value}`. Git reads that file as"
            " part of this repository's configuration on every command, and this"
            " scan did not read it, so any command key it sets runs here too."
            f"{note}"
        )
        remediation = (
            "Check what the included file sets, or remove the include if you did"
            " not add it."
        )
    elif hit.kind == "oversize":
        title = "Git config too large to inspect fully"
        description = (
            f"'{hit.path}' could not be read in full: real git configs are a few"
            " kilobytes, and padding a file (or including it over and over) past a"
            f" scanner's read limit is a way to hide keys from it.{note}"
        )
        remediation = "Open the file and look at its end before running git here."
    elif hit.kind == "hooks-path":
        title = (
            "Git hooks come from a directory inside the repo (core.hooksPath)"
            if hit.severity == Severity.INFO
            else "Git hooks come from a directory outside the repo (core.hooksPath)"
        )
        description = (
            f"'{hit.path}' sets `core.hooksPath = {hit.value}`. Git runs the hooks"
            f" in that directory {hit.runs}.{note}"
        )
        remediation = (
            "No action needed for husky or a similar tool you set up yourself."
            if hit.severity == Severity.INFO
            else "Check the hooks in that directory, or remove the setting."
        )
    else:
        # git's documented spelling when the key has no driver/name part.
        shown = hit.rule if "<" not in hit.rule else hit.key
        title = f"Git config runs a command: {shown}"
        delivery = _DELIVERY if hit.severity == Severity.HIGH else ""
        description = (
            f"'{hit.path}' sets `{hit.key}` ({hit.rule}), which git runs as a"
            f" program {hit.runs}.{delivery}{note}"
        )
        remediation = _remediation(hit.key)
    return _finding(
        id=hit.finding_id,
        severity=hit.severity,
        analyzer=_ANALYZER,
        client=_CLIENT,
        server="(git config)",
        title=title,
        description=description,
        evidence=_evidence(hit),
        remediation=remediation,
        cwe=_CWE,
        owasp_mcp_top_10=list(_OWASP),
        finding_path=str(hit.path),
    )


# ══ Repositories ══════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class GitSurface:
    """A git surface found by a tree walk.

    ``kind`` is ``"dot-git"`` (a ``.git`` directory or ``.git`` file) or
    ``"bare-repo"`` (a directory not named ``.git`` that git would treat as a
    repository).  ``nested`` is ``False`` only for a bare repository that is
    the scan root itself.
    """

    kind: str
    path: Path
    nested: bool = True


def _read_small(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            return fh.read(_MAX_SMALL_FILE_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None


def _valid_head(head: Path) -> bool:
    """Mirror git's ``validate_headref``: a ref, a symref symlink, or an object id."""
    try:
        if head.is_symlink():
            return os.readlink(head).startswith("refs/")
        if not head.is_file():
            return False
    except OSError:
        return False
    text = _read_small(head)
    if text is None:
        return False
    content = text.strip()
    if content.startswith("ref:"):
        return content[4:].strip().startswith("refs/")
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", content))


def _is_git_directory(path: Path) -> bool:
    """Mirror git's ``is_git_directory`` (setup.c).

    A valid ``HEAD`` in *path*, and ``objects/`` and ``refs/`` in its common
    directory (*path* itself, or where its ``commondir`` file points, as for a
    linked worktree's git dir).
    """
    try:
        if not _valid_head(path / "HEAD"):
            return False
        common = path
        text = _read_small(path / "commondir")
        if text and text.strip():
            pointed = _expand_path(text.strip(), path)
            if pointed is None:
                return False
            common = pointed
        return (common / "objects").is_dir() and (common / "refs").is_dir()
    except OSError:
        return False


def is_bare_repository(path: Path) -> bool:
    """True when git would treat *path* itself as a repository directory.

    Git's own test (``is_git_directory`` in setup.c): a valid ``HEAD`` plus
    ``objects/`` and ``refs/`` directories.  A ``.git`` directory passes too;
    callers exclude that name.
    """
    return _is_git_directory(path)


def _common_dir(git_dir: Path) -> Path:
    text = _read_small(git_dir / "commondir")
    if text and text.strip():
        candidate = _expand_path(text.strip(), git_dir)
        if candidate is not None and candidate.is_dir():
            return candidate
    return git_dir


def _resolve_dot_git(dot_git: Path) -> tuple[Path, Path] | None:
    """``(git_dir, worktree)`` for a ``.git`` dir or a ``gitdir:`` file.

    ``None`` when git would not use it: a ``.git`` directory that fails git's
    own repository test (git skips it and keeps looking further up), or a
    ``.git`` file that is malformed or points at something that is not a git
    directory (git stops with an error and runs nothing).
    """
    try:
        if dot_git.is_dir():
            return (dot_git, dot_git.parent) if _is_git_directory(dot_git) else None
        if not dot_git.is_file():
            return None
    except OSError:
        return None
    text = _read_small(dot_git)
    if text is None or not text.startswith("gitdir:"):
        return None
    target = text[len("gitdir:") :].strip()
    if not target:
        return None
    git_dir = _expand_path(target, dot_git.parent)
    if git_dir is None or not git_dir.is_dir() or not _is_git_directory(git_dir):
        return None
    return git_dir, dot_git.parent


def _worktree_config_enabled(view: _ConfigView) -> bool:
    loaded = _last_value(view, "extensions.worktreeconfig")
    if loaded is None:
        return False
    value = loaded.entry.value
    return value is None or value.strip().lower() in ("true", "yes", "on", "1")


def _is_executable(path: Path, st: os.stat_result) -> bool:
    if os.name == "nt":
        # Git for Windows decides by extension or a "#!" first line.
        if path.suffix.lower() in (".exe", ".bat", ".cmd", ".com"):
            return True
        try:
            with path.open("rb") as fh:
                return fh.read(2) == b"#!"
        except OSError:
            return False
    return bool(st.st_mode & 0o111)


# Every hook name githooks(5) documents; git runs nothing else from hooks/.
# fmt: off
_GITHOOK_NAMES = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
    "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit",
    "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive",
    "update", "proc-receive", "post-receive", "post-update",
    "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite",
    "sendemail-validate", "fsmonitor-watchman", "p4-changelist",
    "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit",
    "post-index-change",
})
# fmt: on


def _list_hooks(hooks_dir: Path) -> list[Path]:
    """Executable files in *hooks_dir* named like a hook git runs (names only)."""
    try:
        names = sorted(os.listdir(hooks_dir))[:_MAX_DIR_ENTRIES]
    except OSError:
        return []
    hooks: list[Path] = []
    for name in names:
        if name.endswith(".sample"):
            continue
        path = hooks_dir / name
        if _hook_name(path) not in _GITHOOK_NAMES:
            continue
        try:
            st = path.stat()
        except OSError:
            continue
        if stat_module.S_ISREG(st.st_mode) and _is_executable(path, st):
            hooks.append(path)
    return hooks


def _hook_name(path: Path) -> str:
    name = path.name
    if os.name == "nt" and name.lower().endswith(".exe"):
        return name[:-4]
    return name


# `post-index-change` runs whenever git writes the index, and `git status` /
# `git diff` write it while refreshing stat data (verified with git 2.43:
# `git status --porcelain=2 --branch` in a checkout with touched files ran it).
_INDEX_HOOK = "post-index-change"


def _hook_findings(hooks_dir: Path, *, inventory: bool, origin: str) -> list[Finding]:
    hooks = _list_hooks(hooks_dir)
    findings: list[Finding] = []
    for hook in hooks:
        if _hook_name(hook) == _INDEX_HOOK:
            findings.append(
                _finding(
                    id=GIT_REPO_SHAPE_ID,
                    severity=Severity.HIGH,
                    analyzer=_ANALYZER,
                    client=_CLIENT,
                    server="(git hooks)",
                    title="Git hook runs on git status (post-index-change)",
                    description=(
                        f"'{hook}' is an executable `post-index-change` hook. Git runs"
                        " it whenever it writes the index, and `git status` and"
                        " `git diff` write the index while refreshing file"
                        " timestamps — the commands coding agents run in the"
                        " background when they open a folder. A repository copied"
                        " as files (an archive, a shared drive) brings its"
                        " `.git/hooks` with it, unreviewed, and the hook runs as you"
                        " outside the agent's sandbox."
                    ),
                    evidence=f"{hook} | hooks directory: {hooks_dir} ({origin})",
                    remediation=(
                        "Delete the hook unless you installed it (VFS for Git uses"
                        " one). Until then, don't open the folder in an agent."
                    ),
                    cwe=_CWE,
                    owasp_mcp_top_10=list(_OWASP),
                    finding_path=str(hook),
                )
            )
    if inventory and hooks:
        names = [_hook_name(h) for h in hooks]
        findings.append(
            _finding(
                id=GIT_REPO_SHAPE_ID,
                severity=Severity.INFO,
                analyzer=_ANALYZER,
                client=_CLIENT,
                server="(git hooks)",
                title="Git hooks installed in the repository's git directory",
                description=(
                    f"'{hooks_dir}' holds {len(names)} executable hook(s) that git"
                    " runs on commit, checkout, merge, rebase or push. `.git/hooks`"
                    " is not part of the repository's history, so a repository that"
                    " arrives as files can carry hooks nobody reviewed. pre-commit,"
                    " husky (v4), lefthook, git-lfs and DVC install hooks here"
                    " legitimately."
                ),
                evidence=f"{hooks_dir}: " + ", ".join(names),
                remediation=(
                    "Check that each hook is one you or your tooling installed."
                ),
                cwe=_CWE,
                owasp_mcp_top_10=list(_OWASP),
                finding_path=str(hooks_dir),
            )
        )
    return findings


def _scan_git_dir(
    git_dir: Path,
    *,
    worktree: Path | None,
    scan_root: Path,
) -> tuple[list[Finding], bool]:
    """Scan one git directory; return ``(findings, has_high)``.

    ``has_high`` is true when any finding is HIGH or above: a command key in
    its config or a ``post-index-change`` hook.  One read budget covers the
    shared config, its includes and every worktree config.
    """
    common = _common_dir(git_dir)
    linked = _real(common) != _real(git_dir)
    repo_root = worktree if worktree is not None else git_dir
    ctx = _Ctx(repo_root=repo_root, scan_root=scan_root)
    budget = _Budget()

    view = _load_config(common / "config", scan_root, budget)
    worktree_config = _worktree_config_enabled(view)
    if worktree_config:
        view.extend(_load_config(git_dir / "config.worktree", scan_root, budget))
    hits = _annotate_parse_errors(_evaluate(view, ctx), view)

    if worktree_config and not linked:
        # Per-worktree configs of this repository's linked worktrees: git reads
        # them when it runs inside those worktrees.  Report only what each one
        # adds; the shared config's hits are already above.
        worktrees_dir = git_dir / "worktrees"
        try:
            ids = sorted(os.listdir(worktrees_dir))[:_MAX_DIR_ENTRIES]
        except OSError:
            ids = []
        for wt_id in ids:
            wt_file = worktrees_dir / wt_id / "config.worktree"
            if not wt_file.is_file():
                continue
            wt_view = _ConfigView()
            wt_view.extend(view)
            own = _load_config(wt_file, scan_root, budget)
            wt_view.extend(own)
            own_files = {_real(p) for p in own.files}
            hits.extend(
                h
                for h in _annotate_parse_errors(_evaluate(wt_view, ctx), wt_view)
                if _real(h.path) in own_files
            )

    findings = git_exec_findings(hits)

    hooks_path = _last_value(view, "core.hookspath")
    hooks_value = ((hooks_path.entry.value or "").strip()) if hooks_path else ""
    if hooks_value and hooks_value not in ("/dev/null", "NUL"):
        custom = _expand_path(hooks_value, repo_root)
        if custom is not None and _within(custom, scan_root) and custom.is_dir():
            findings.extend(
                _hook_findings(custom, inventory=False, origin="core.hooksPath")
            )
    elif not hooks_value:
        findings.extend(
            _hook_findings(common / "hooks", inventory=True, origin="the git dir")
        )
    has_high = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
    return findings, has_high


# fmt: off
_FIXTURE_DIR_NAMES = frozenset({
    "test", "tests", "testdata", "test-data", "test_data", "fixture", "fixtures",
    "__fixtures__", "testing", "spec", "specs",
})
# fmt: on


# Package managers that keep bare git clones of dependencies inside a project:
# (consecutive path components, what they are).
_DEPENDENCY_CACHES: tuple[tuple[tuple[str, ...], str], ...] = (
    ((".build", "repositories"), "SwiftPM's dependency mirror (.build/repositories)"),
    (
        ("cache", "bundler", "git"),
        "Bundler's git-gem cache (vendor/bundle/…/cache/bundler/git)",
    ),
    ((".cargo", "git", "db"), "Cargo's git dependency database (.cargo/git/db)"),
    (("pkg", "mod", "cache", "vcs"), "Go's module VCS cache (pkg/mod/cache/vcs)"),
)


def _benign_location(path: Path, scan_root: Path) -> str | None:
    """Why a bare repository here is expected, or ``None``.

    A test/fixture directory (git-tooling test data) or a package manager's
    dependency cache.  The caller still requires that the repository's config
    runs nothing and it has no ``post-index-change`` hook.
    """
    try:
        rel = _real(path).relative_to(_real(scan_root))
    except ValueError:
        return None
    parts = [part.lower() for part in rel.parts]
    for pattern, label in _DEPENDENCY_CACHES:
        width = len(pattern)
        if any(
            tuple(parts[i : i + width]) == pattern for i in range(len(parts) - width)
        ):
            return label
    if any(part in _FIXTURE_DIR_NAMES for part in parts):
        return (
            "a test/fixture directory (how git-tooling projects ship test repositories)"
        )
    return None


def _bare_repo_finding(
    path: Path, severity: Severity, has_config: bool, location: str | None
) -> Finding:
    head = (_read_small(path / "HEAD") or "").strip()[:80]
    if severity == Severity.INFO and location:
        why = (
            f" It sits in {location}, its config runs nothing and it has no"
            " `post-index-change` hook, so this is inventory."
        )
    else:
        why = ""
    return _finding(
        id=GIT_REPO_SHAPE_ID,
        severity=severity,
        analyzer=_ANALYZER,
        client=_CLIENT,
        server="(bare repository)",
        title="Nested bare git repository inside the tree",
        description=(
            f"'{path}' holds `HEAD`, `objects/` and `refs/`, so git treats the"
            " directory itself as a repository. When git runs inside it (an agent"
            " that changes into it, an editor that scans sub-folders), git reads"
            f" '{path / 'config'}', which whoever made the repository controls, and"
            " any command key in it runs. Git's own documentation describes this"
            " attack under `safe.bareRepository`; ordinary projects do not commit"
            f" one.{why}"
        ),
        evidence=(
            f"{path} | HEAD: {head!r} | config: "
            + ("present" if has_config else "absent")
        ),
        remediation=(
            "Delete or move the directory unless you know why it is there. Setting"
            " `git config --global safe.bareRepository explicit` stops git from"
            " using embedded bare repositories (the default in Git 3.0)."
        ),
        cwe=_CWE,
        owasp_mcp_top_10=list(_OWASP),
        finding_path=str(path),
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.id, f.finding_path, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan_git_surfaces(
    surfaces: Iterable[GitSurface], *, scan_root: Path
) -> list[Finding]:
    """Scan the git surfaces a tree walk found; return TRUST-006/007 findings.

    ``.git`` entries are scanned first so that a bare directory a ``.git`` file
    points at (the "bare repo + worktrees" layout) is recognised as that
    repository's own git dir, scanned once, and not reported as an embedded
    bare repository.

    Args:
        surfaces: Output of :func:`mcp_audit.discovery.discover_project_git_surfaces`
            (or any list of :class:`GitSurface`).
        scan_root: The scanned directory; the repository-controlled boundary.
    """
    surface_list = list(surfaces)
    findings: list[Finding] = []
    scanned: set[Path] = set()
    referenced: set[Path] = set()
    for surface in surface_list:
        if surface.kind != "dot-git":
            continue
        resolved = _resolve_dot_git(surface.path)
        if resolved is None:
            continue
        git_dir, worktree = resolved
        real_dir = _real(git_dir)
        referenced.add(real_dir)
        referenced.add(_real(_common_dir(git_dir)))
        if real_dir in scanned:
            continue
        scanned.add(real_dir)
        found, _ = _scan_git_dir(git_dir, worktree=worktree, scan_root=scan_root)
        findings.extend(found)
    for surface in surface_list:
        if surface.kind != "bare-repo":
            continue
        real_dir = _real(surface.path)
        if real_dir in scanned:
            continue
        scanned.add(real_dir)
        found, has_high = _scan_git_dir(
            surface.path, worktree=None, scan_root=scan_root
        )
        findings.extend(found)
        if surface.nested and real_dir not in referenced:
            location = _benign_location(surface.path, scan_root)
            severity = Severity.INFO if location and not has_high else Severity.HIGH
            findings.append(
                _bare_repo_finding(
                    surface.path,
                    severity,
                    (surface.path / "config").is_file(),
                    location,
                )
            )
    return _dedupe(findings)


def scan_repository(repo_dir: Path, *, scan_root: Path | None = None) -> list[Finding]:
    """Scan one repository directory's git configuration and hooks.

    *repo_dir* is a working tree holding ``.git`` (a directory, or a file with a
    ``gitdir:`` pointer, as in submodules and linked worktrees), or a bare
    repository.  Nothing under *repo_dir* other than git's own files is read.

    Args:
        repo_dir: The repository directory.
        scan_root: Boundary of repository-controlled files; defaults to
            *repo_dir*.

    Returns:
        TRUST-006/TRUST-007 findings; empty when *repo_dir* is not a repository.
    """
    root = scan_root if scan_root is not None else repo_dir
    dot_git = repo_dir / ".git"
    if os.path.lexists(dot_git):
        return scan_git_surfaces([GitSurface("dot-git", dot_git)], scan_root=root)
    if is_bare_repository(repo_dir):
        return scan_git_surfaces(
            [GitSurface("bare-repo", repo_dir, nested=False)], scan_root=root
        )
    return []


def scan_cwd_repository(cwd: Path | None = None) -> list[Finding]:
    """Scan the repository git would use if run in *cwd* (default: the CWD).

    Searches upward the way git's own discovery does (``setup.c``): at each
    level, a valid ``.git`` directory or ``gitdir:`` file wins; a ``.git``
    directory that fails git's repository test is skipped and the search goes
    on (a decoy cannot hide the real repository above it); a malformed ``.git``
    file stops the search (git errors out and runs nothing); otherwise the
    directory itself is checked as a bare repository.  Run from inside a
    ``.git`` directory, that directory is the repository's own git dir, not an
    embedded one.  A bare repository found inside another repository's working
    tree is reported as embedded (TRUST-007).  This is the default ``scan`` /
    ``check`` path; it does not walk the tree (``scan --project`` does).

    Args:
        cwd: Starting directory; defaults to :func:`Path.cwd`.

    Returns:
        TRUST-006/TRUST-007 findings; empty outside any repository.
    """
    try:
        start = _real(cwd if cwd is not None else Path.cwd())
    except OSError:
        return []
    for candidate in (start, *start.parents):
        try:
            if candidate.name == ".git" and _is_git_directory(candidate):
                return scan_git_surfaces(
                    [GitSurface("dot-git", candidate)], scan_root=candidate.parent
                )
            dot_git = candidate / ".git"
            if os.path.lexists(dot_git):
                if _resolve_dot_git(dot_git) is not None:
                    return scan_git_surfaces(
                        [GitSurface("dot-git", dot_git)], scan_root=candidate
                    )
                if not dot_git.is_dir():
                    return []  # malformed .git file: git stops here
            if _is_git_directory(candidate):
                enclosing = next(
                    (
                        p
                        for p in candidate.parents
                        if os.path.lexists(p / ".git")
                        and _resolve_dot_git(p / ".git") is not None
                    ),
                    None,
                )
                return scan_git_surfaces(
                    [GitSurface("bare-repo", candidate, nested=enclosing is not None)],
                    scan_root=enclosing if enclosing is not None else candidate,
                )
        except OSError:
            return []
    return []
