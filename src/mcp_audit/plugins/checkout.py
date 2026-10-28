"""Plugin pin vs the actual checkout (PLUGIN-003, PLUGIN-004; STORY-0096).

PLUGIN-001 compares two records: the version Claude Code wrote into
``installed_plugins.json`` and the ``sha`` the marketplace pins.  This module
compares the pin with what is on disk, the control the Cloud Security
Alliance's Plugin4Shell note asks for ("a record of exactly which commit each
installed plugin currently resolves to", verified "independently of the
agent's self-reported pin status").

Plugin4Shell (AIR Security, 2026-09-17): agents ran ``git checkout <sha>`` for
a marketplace-pinned plugin and never checked where ``HEAD`` landed.  When a
local branch has exactly that name (a remote's default branch becomes one on
clone), git checks out the branch instead and only warns that the name is
ambiguous.  AIR Security reports the fix in Claude Code 2.1.179; the refusal itself was
observed on 2.1.311 ("SHA pin verification failed: expected HEAD to be …, got
…. Refusing to install.").  The fix checks at
install time; it does not re-check plugins already on disk.

What this module reads, all as files (it never runs git; running git in a
checkout an attacker shaped is the GitSpawn attack, STORY-0089):

- ``<install path>/.git`` (a directory, or a ``gitdir:`` file pointing inside
  the plugins root): ``HEAD``, loose refs under ``refs/``, and ``packed-refs``.
  No object is read.  Claude Code 2.1.311 copies a plugin into the cache
  without ``.git`` (observed), so for installs it made there is nothing to
  read and these checks are silent; installs made by versions that kept the
  clone's ``.git`` are checked.
- ``<plugins root>/marketplaces/<name>/``: git checkouts Claude Code clones and
  fetches into; their git config and hooks get TRUST-006/007 (STORY-0089).

Findings:

- ``PLUGIN-003`` CRITICAL: a pinned plugin's checkout resolves ``HEAD`` to a
  commit other than the pin, and either ``HEAD`` sits on a branch named like a
  commit SHA or ``FETCH_HEAD`` (the Plugin4Shell shape) or Claude Code's own
  record says it installed the pin.  MEDIUM when ``HEAD`` differs from the pin
  for a reason the record does not explain, or when ``HEAD`` cannot be
  resolved by reading files.  Silent when the checkout is the commit Claude
  Code recorded and only the marketplace's pin has moved since (pin drift;
  PLUGIN-001 reports that for plugins without a version string).
- ``PLUGIN-004`` HIGH: a plugin checkout holds a branch, tag or remote branch
  named like a commit SHA or ``FETCH_HEAD``.  MEDIUM: the marketplace ``sha``
  is set but is not a full 40-character SHA.  LOW: a pinned plugin is fetched
  from a host other than github.com, which refuses SHA-shaped branch names.
"""

from __future__ import annotations

import os
import re
import stat as stat_module
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.analyzers import git_exec as _git
from mcp_audit.models import Finding, Severity
from mcp_audit.plugins.discovery import plugins_root
from mcp_audit.plugins.models import GIT_SOURCE_TYPES, InstalledPlugin

__all__ = [
    "PLUGIN_CHANNEL_ID",
    "PLUGIN_CHECKOUT_ID",
    "GitCheckout",
    "analyze_plugin_pins",
    "read_git_checkout",
    "source_host",
]

#: The checkout does not hold the pinned commit (or cannot be verified).
PLUGIN_CHECKOUT_ID = "PLUGIN-003"
#: The update channel cannot hold the pin (SHA-shaped refs, a short pin, a host
#: without GitHub's refname block).
PLUGIN_CHANNEL_ID = "PLUGIN-004"

_ANALYZER = "plugins"
_CLIENT = "claude-code"
_CWE = "CWE-494"
_OWASP = ["MCP04"]
_PLUGIN4SHELL = "https://www.air.security/blog-posts/plugin4shell"
_FIXED_IN = "2.1.179"

# git's SYMREF_MAXDEPTH (refs/refs-internal.h): a longer chain of symbolic
# refs is an error to git, so it is unverifiable here.
_MAX_SYMREF_DEPTH = 5
_MAX_REF_FILE_BYTES = _git._MAX_SMALL_FILE_BYTES  # HEAD and loose refs
_MAX_PACKED_REFS_BYTES = 32 * 1024 * 1024
_MAX_LOOSE_REFS = 20_000  # per checkout
_MAX_REF_NAME = 1024
_SCAN_BYTES = 64 * 1024 * 1024  # ref data read per scan, all checkouts
_SCAN_ENTRIES = 100_000  # loose ref entries listed per scan
_MAX_CHECKOUTS = 512
_MAX_MARKETPLACES = 256
_MAX_LISTED_REFS = 10

_OBJECT_ID_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_SHA_SHAPED_RE = re.compile(r"[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}")
_VERSION_PREFIX_RE = re.compile(r"[0-9a-f]{12}")
_SHORT_PIN_RE = re.compile(r"[0-9a-f]{7,39}")
_SHORTHAND_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
# scp-like git URL: [user@]host:path, with no slash before the first colon.
_SCP_RE = re.compile(r"(?:[^@/:]+@)?(?P<host>[^@/:]+):(?P<path>.*)")
_PSEUDO_BRANCHES = frozenset({"FETCH_HEAD"})
# Refs git keeps per worktree, in the worktree's own git dir rather than the
# common dir (refs.c: is_per_worktree_ref).
_PER_WORKTREE_PREFIXES = ("refs/bisect/", "refs/worktree/", "refs/rewritten/")


# ══ Reading a checkout ════════════════════════════════════════════════════════


@dataclass
class _Budget:
    """What one scan may still spend reading ref data across all checkouts."""

    bytes_left: int = _SCAN_BYTES
    entries_left: int = _SCAN_ENTRIES
    checkouts_left: int = _MAX_CHECKOUTS


@dataclass(frozen=True)
class GitCheckout:
    """What a plugin's git checkout says, read from files.

    Attributes:
        work_tree: The directory holding ``.git``.
        git_dir: The git directory read (``.git`` itself or its ``gitdir:``).
        head_ref: The branch ``HEAD`` is attached to (``refs/heads/main``), or
            ``None`` when ``HEAD`` is detached at a commit.
        head_chain: Every ref name on the symbolic-ref chain from ``HEAD``
            (``head_ref`` first), as far as it could be followed.
        head_commit: The lower-cased object id ``HEAD`` resolves to, or
            ``None`` when it could not be resolved (see ``unresolved``).
        unresolved: Why ``HEAD`` could not be resolved by reading files.
        sha_shaped_refs: Branches, tags and remote branches named like a commit
            SHA or ``FETCH_HEAD``.
        refs_incomplete: Why the ref listing stopped early, if it did.
        located: ``False`` when the git dir was found but not read at all (a
            symlinked ``.git``, or a git dir outside the plugins root).
    """

    work_tree: Path
    git_dir: Path
    head_ref: str | None = None
    head_chain: tuple[str, ...] = ()
    head_commit: str | None = None
    unresolved: str | None = None
    sha_shaped_refs: tuple[str, ...] = ()
    refs_incomplete: str | None = None
    located: bool = True


class _UnverifiableError(Exception):
    """A ref could not be resolved by reading files; the message says why."""


def _why(exc: Exception) -> str:
    """A short reason for a failed filesystem call."""
    return getattr(exc, "strerror", None) or type(exc).__name__


def _printable(value: object) -> str:
    """*value* as text safe for a report line: no NUL or control characters."""
    return "".join(c if c.isprintable() else "?" for c in str(value))[:300]


def _lstat(path: Path) -> os.stat_result | None:
    """``os.lstat`` that returns ``None`` for a missing path.

    Other ``OSError``s (permission denied, a name too long) are raised as
    :class:`_UnverifiableError`, because git might read what this scan cannot.
    """
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except NotADirectoryError:
        return None
    except (OSError, ValueError) as exc:
        raise _UnverifiableError(
            f"'{_printable(path)}' could not be read ({_why(exc)})"
        ) from exc


def _read_capped(path: Path, limit: int, budget: _Budget) -> bytes:
    """Read at most *limit* bytes of a regular file, charged to *budget*."""
    if budget.bytes_left <= 0:
        raise _UnverifiableError("this scan's ref-reading budget is spent")
    cap = min(limit, budget.bytes_left)
    try:
        with path.open("rb") as fh:
            data = fh.read(cap + 1)
    except (OSError, ValueError) as exc:
        raise _UnverifiableError(
            f"'{_printable(path)}' could not be read ({_why(exc)})"
        ) from exc
    budget.bytes_left -= min(len(data), cap)
    if len(data) > cap:
        raise _UnverifiableError(
            f"'{path.name}' is larger than this scan reads ({cap} bytes)"
        )
    return data


def _valid_ref_name(name: str) -> bool:
    """A conservative subset of git's ``check_refname_format`` for ``refs/…``."""
    if not name.startswith("refs/") or len(name) > _MAX_REF_NAME:
        return False
    if name.endswith(("/", ".", ".lock")) or "//" in name or ".." in name:
        return False
    if any(ord(c) < 0x20 or c in "\\\x7f ~^:?*[" for c in name) or "@{" in name:
        return False
    return not any(part.startswith(".") for part in name.split("/"))


def _parse_ref_content(raw: bytes, where: str) -> tuple[str, str]:
    """``("oid", id)`` or ``("ref", name)`` from a HEAD or loose-ref file."""
    text = raw.decode("utf-8", errors="replace").strip()
    if text.startswith("ref:"):
        target = text[4:].strip()
        if not _valid_ref_name(target):
            raise _UnverifiableError(f"{where} names an unusual ref {target[:80]!r}")
        return "ref", target
    candidate = text.lower()
    if _OBJECT_ID_RE.fullmatch(candidate):
        return "oid", candidate
    raise _UnverifiableError(f"{where} is not a commit id or a ref ({text[:40]!r})")


def _read_ref_file(path: Path, where: str, budget: _Budget) -> tuple[str, str] | None:
    """Read HEAD or a loose ref without following a symlink.

    A symbolic link whose target starts with ``refs/`` is git's legacy
    symbolic-ref form and is read as one; any other link is not followed.
    ``None`` when the file does not exist.
    """
    st = _lstat(path)
    if st is None:
        return None
    if stat_module.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise _UnverifiableError(f"{where} could not be read") from exc
        if _valid_ref_name(target):
            return "ref", target
        raise _UnverifiableError(f"{where} is a symbolic link outside refs/")
    if not stat_module.S_ISREG(st.st_mode):
        return None
    return _parse_ref_content(_read_capped(path, _MAX_REF_FILE_BYTES, budget), where)


def _loose_ref(base: Path, name: str, budget: _Budget) -> tuple[str, str] | None:
    """Look *name* up as a loose ref under *base*, never through a symlinked dir."""
    parts = name.split("/")
    path = base
    for part in parts[:-1]:
        path = path / part
        st = _lstat(path)
        if st is None or not stat_module.S_ISDIR(st.st_mode):
            if st is not None and stat_module.S_ISLNK(st.st_mode):
                raise _UnverifiableError(
                    f"'{path.name}' in the ref path is a symbolic link"
                )
            return None
    return _read_ref_file(path / parts[-1], f"ref {name}", budget)


def _sha_shaped(name: str) -> bool:
    """Is *name* a branch, tag or remote branch named like a SHA or FETCH_HEAD?"""
    parts = name.split("/")
    if parts[:2] in (["refs", "heads"], ["refs", "tags"]):
        short = "/".join(parts[2:])
    elif parts[:2] == ["refs", "remotes"] and len(parts) >= 4:
        short = "/".join(parts[3:])
    else:
        return False
    return bool(_SHA_SHAPED_RE.fullmatch(short)) or short in _PSEUDO_BRANCHES


@dataclass
class _PackedRefs:
    found: dict[str, str] = field(default_factory=dict)  # wanted name → oid
    sha_shaped: list[str] = field(default_factory=list)
    incomplete: str | None = None


def _read_packed_refs(common: Path, wanted: str | None, budget: _Budget) -> _PackedRefs:
    """One linear pass over ``packed-refs``: the wanted ref and SHA-shaped names."""
    out = _PackedRefs()
    path = common / "packed-refs"
    try:
        st = _lstat(path)
        if st is None or not stat_module.S_ISREG(st.st_mode):
            if st is not None and stat_module.S_ISLNK(st.st_mode):
                out.incomplete = "packed-refs is a symbolic link; not followed"
            return out
        data = _read_capped(path, _MAX_PACKED_REFS_BYTES, budget)
    except _UnverifiableError as exc:
        out.incomplete = str(exc)
        return out
    for line in data.decode("utf-8", errors="replace").splitlines():
        if not line or line[0] in "#^":
            continue
        oid, _, name = line.partition(" ")
        name = name.strip()
        if name == wanted and _OBJECT_ID_RE.fullmatch(oid.lower()):
            out.found[name] = oid.lower()
        if _sha_shaped(name):
            out.sha_shaped.append(name)
    return out


def _list_loose_refs(common: Path, budget: _Budget) -> tuple[list[str], str | None]:
    """Names of loose branches/tags/remote branches shaped like a SHA.

    Walks ``refs/`` without following a symbolic link.  Returns the names and
    the reason the walk stopped early, if it did.
    """
    shaped: list[str] = []
    stack: list[tuple[Path, str]] = [(common / "refs", "refs")]
    seen = 0
    incomplete: str | None = None
    while stack:
        directory, prefix = stack.pop()
        try:
            names = sorted(os.listdir(directory))
        except OSError as exc:
            if not isinstance(exc, (FileNotFoundError, NotADirectoryError)):
                incomplete = f"'{prefix}' could not be listed ({exc.strerror})"
            continue
        for name in names:
            seen += 1
            budget.entries_left -= 1
            if seen > _MAX_LOOSE_REFS or budget.entries_left < 0:
                return shaped, "more loose refs than this scan lists"
            path = directory / name
            try:
                st = os.lstat(path)
            except OSError as exc:
                if not isinstance(exc, FileNotFoundError):
                    incomplete = f"'{prefix}/{name}' could not be read ({exc.strerror})"
                continue
            ref = f"{prefix}/{name}"
            if stat_module.S_ISLNK(st.st_mode):
                if stat_module.S_ISDIR(_safe_stat_mode(path)):
                    incomplete = f"'{ref}' is a symbolic link; not followed"
                elif _sha_shaped(ref):
                    shaped.append(ref)
                continue
            if stat_module.S_ISDIR(st.st_mode):
                stack.append((path, ref))
            elif stat_module.S_ISREG(st.st_mode) and _sha_shaped(ref):
                shaped.append(ref)
    return shaped, incomplete


def _safe_stat_mode(path: Path) -> int:
    try:
        return os.stat(path).st_mode
    except OSError:
        return 0


@dataclass
class _Head:
    ref: str | None = None  # the branch HEAD is attached to
    chain: list[str] = field(default_factory=list)  # every symref hop, in order
    commit: str | None = None
    packed: _PackedRefs | None = None  # packed-refs, when the lookup needed it


def _resolve_head(git_dir: Path, common: Path, budget: _Budget, head: _Head) -> None:
    """Fill *head* for a git dir, the way git resolves ``HEAD``.

    Raises :class:`_UnverifiableError` when ``HEAD`` cannot be resolved by
    reading files; whatever was learnt before that stays in *head*.  A packed
    ref is never symbolic, so ``packed-refs`` is read at most once.
    """
    first = _read_ref_file(git_dir / "HEAD", "HEAD", budget)
    if first is None:
        raise _UnverifiableError("HEAD is missing")
    kind, value = first
    if kind == "oid":
        head.commit = value
        return
    head.ref = value
    name = value
    head.chain.append(name)
    for _ in range(_MAX_SYMREF_DEPTH):
        base = git_dir if name.startswith(_PER_WORKTREE_PREFIXES) else common
        loose = _loose_ref(base, name, budget)
        if loose is None:
            head.packed = _read_packed_refs(common, name, budget)
            oid = head.packed.found.get(name)
            if oid is None:
                why = head.packed.incomplete or "it has no commit (an unborn branch)"
                raise _UnverifiableError(f"HEAD names {name}, and {why}")
            head.commit = oid
            return
        kind, value = loose
        if kind == "oid":
            head.commit = value
            return
        name = value
        head.chain.append(name)
    raise _UnverifiableError("HEAD is a chain of symbolic refs longer than git allows")


_OUTSIDE_ROOT = "it is outside the plugins root"


def _under_root(path: Path, root: Path) -> str | None:
    """``None`` when *path* sits under *root* with no symlinked directory between.

    Symlinks at or above *root* are allowed (a dotfile-managed ``~/.claude``);
    anything between *root* and *path* must be a real directory.  Otherwise the
    reason it is not read.
    """
    if ".." in path.parts or "\x00" in str(path):
        return f"'{path}' has a '..' component or a NUL byte; not read"
    real_root = _git._real(root)
    for candidate in (path, *path.parents):
        if _git._real(candidate) == real_root:
            return None
        try:
            if candidate.is_symlink():
                return f"'{candidate}' is a symbolic link; not followed"
        except OSError as exc:
            return f"'{candidate}' could not be read ({exc.strerror})"
    return _OUTSIDE_ROOT


def read_git_checkout(
    work_tree: Path, *, root: Path, budget: _Budget | None = None
) -> GitCheckout | None:
    """Read *work_tree*'s own git checkout as files.

    Args:
        work_tree: A plugin install directory (or marketplace clone).
        root: The plugins root; the git dir and common dir must resolve inside
            it, with no symbolic link between it and *work_tree*.
        budget: Shared per-scan budget; a fresh one when omitted.

    Returns:
        ``None`` when *work_tree* has no ``.git`` of its own, or one that git
        would not use.  Otherwise a :class:`GitCheckout`; ``unresolved`` says
        why ``HEAD`` could not be resolved, if it could not.  Never raises for
        filesystem errors.
    """
    budget = budget if budget is not None else _Budget()
    dot_git = work_tree / ".git"
    try:
        st = _lstat(dot_git)
    except _UnverifiableError as exc:
        return GitCheckout(work_tree, dot_git, unresolved=str(exc), located=False)
    if st is None:
        return None
    if stat_module.S_ISLNK(st.st_mode):
        return GitCheckout(
            work_tree,
            dot_git,
            unresolved=".git is a symbolic link; not followed",
            located=False,
        )
    if stat_module.S_ISDIR(st.st_mode):
        git_dir = dot_git
    elif stat_module.S_ISREG(st.st_mode):
        text = _git._read_small(dot_git) or ""
        target = text[len("gitdir:") :].strip() if text.startswith("gitdir:") else ""
        pointed = _git._expand_path(target, work_tree) if target else None
        if pointed is None:
            return None  # git stops with an error and checks nothing out
        if not _git._within(pointed, root):
            return GitCheckout(
                work_tree,
                pointed,
                unresolved="its .git file points outside the plugins root",
                located=False,
            )
        git_dir = pointed
    else:
        return None
    try:
        if not _git._is_git_directory(git_dir):
            return None
        common = _git._common_dir(git_dir)
    except OSError:
        return GitCheckout(
            work_tree, git_dir, unresolved="the git dir is unreadable", located=False
        )
    if not _git._within(common, root):
        return GitCheckout(
            work_tree,
            git_dir,
            unresolved="its common git dir is outside the plugins root",
            located=False,
        )

    head = _Head()
    unresolved: str | None = None
    try:
        if os.path.isdir(common / "reftable"):
            # git 2.45+ with extensions.refStorage = reftable: HEAD is a stub
            # and every ref lives in a binary table this scan does not parse.
            # The cloning client picks the format, so a remote cannot force it.
            raise _UnverifiableError(
                "the checkout keeps its refs in git's reftable format, which this"
                " scan does not read"
            )
        _resolve_head(git_dir, common, budget, head)
    except _UnverifiableError as exc:
        unresolved = str(exc)
    packed = head.packed or _read_packed_refs(common, None, budget)
    loose, loose_incomplete = _list_loose_refs(common, budget)
    shaped = sorted(set(loose) | set(packed.sha_shaped))
    return GitCheckout(
        work_tree=work_tree,
        git_dir=git_dir,
        head_ref=head.ref,
        head_chain=tuple(head.chain),
        head_commit=None if unresolved else head.commit,
        unresolved=unresolved,
        sha_shaped_refs=tuple(shaped),
        refs_incomplete=loose_incomplete or packed.incomplete,
    )


# ══ Source hosts ═════════════════════════════════════════════════════════════


def source_host(source: dict) -> tuple[str, str]:
    """``(host, location)`` of a git plugin source, read strictly.

    *host* is lower-cased, without userinfo or port, or ``""`` when it cannot
    be told (a local path, a ``file://`` URL, anything unparseable).
    *location* is the URL with userinfo, query and fragment removed, for
    reports.  A backslash
    in the authority makes the host unknown: Python's URL parser and the WHATWG
    parser Node uses split such an authority differently, and git hands the URL
    to curl, so no single reading is safe to trust.
    """
    kind = source.get("source")
    if kind == "github":
        repo = source.get("repo")
        return "github.com", f"github.com/{repo}" if isinstance(repo, str) else ""
    url = source.get("url")
    if not isinstance(url, str) or not url.strip():
        return "", ""
    url = url.strip()
    if kind == "git-subdir" and _SHORTHAND_RE.fullmatch(url):
        return "github.com", f"github.com/{url}"
    scheme, sep, rest = url.partition("://")
    if sep:
        end = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=-1)
        authority = rest if end < 0 else rest[:end]
        path = "" if end < 0 else _cut_query(rest[end:])
        hostport = authority.rpartition("@")[2]
        location = f"{scheme}://{hostport}{path}"
        if scheme.lower() == "file" or "\\" in authority or hostport.startswith("["):
            return "", location
        return hostport.partition(":")[0].lower(), location
    # scp form: whatever precedes the last "@" before the first "/" is userinfo
    # (``git:password@host:path`` included), and a query or fragment can carry a
    # token; neither reaches the report.
    head, slash, tail = url.partition("/")
    url = _cut_query(head.rpartition("@")[2] + slash + tail)
    match = _SCP_RE.fullmatch(url)
    if match and len(match.group("host")) > 1:  # "C:" is a Windows drive
        host = match.group("host").lower()
        return host, f"{host}:{match.group('path')}"
    return "", url


def _cut_query(text: str) -> str:
    """*text* up to the first ``?`` or ``#``: tokens ride in both."""
    return re.split(r"[?#]", text, maxsplit=1)[0]


# ══ Findings ══════════════════════════════════════════════════════════════════


def _finding(plugin: InstalledPlugin, finding_id: str, **fields: object) -> Finding:
    return _git._finding(
        id=finding_id,
        analyzer=_ANALYZER,
        client=_CLIENT,
        server=plugin.plugin_id,
        cwe=_CWE,
        owasp_mcp_top_10=list(_OWASP),
        **fields,
    )


def _version_prefix(plugin: InstalledPlugin) -> str | None:
    """The 12-hex commit prefix Claude Code recorded as the version, if it did.

    Only when neither ``plugin.json`` nor the marketplace entry sets a version
    and the source is not ``git-subdir`` (docs: plugins/loading, "How Claude
    Code computes the version").
    """
    if plugin.manifest_version or plugin.entry_version:
        return None
    if plugin.source_type == "git-subdir":
        return None
    version = (plugin.version or "").strip().lower()
    return version if _VERSION_PREFIX_RE.fullmatch(version) else None


def _recorded(plugin: InstalledPlugin) -> str:
    parts = []
    if plugin.git_commit_sha:
        parts.append(f"gitCommitSha {plugin.git_commit_sha[:12]}")
    prefix = _version_prefix(plugin)
    if prefix:
        parts.append(f"version {prefix}")
    return " and ".join(parts) if parts else "no commit"


def _branch_short(ref: str) -> str:
    parts = ref.split("/")
    return "/".join(parts[2:]) if parts[:2] == ["refs", "heads"] else ref


def _short_name(ref: str) -> str:
    """The branch, tag or remote-branch name inside a full ref name."""
    parts = ref.split("/")
    if parts[:2] in (["refs", "heads"], ["refs", "tags"]):
        return "/".join(parts[2:])
    if parts[:2] == ["refs", "remotes"] and len(parts) >= 4:
        return "/".join(parts[3:])
    return ref


def _swap_ref(chain: tuple[str, ...], pin: str) -> str | None:
    """The first ref on HEAD's symbolic-ref chain named like a SHA, or the pin.

    ``FETCH_HEAD`` counts.  A short pin (7-39 hex) is a swap name too: git
    reads an abbreviated hash as a ref name first.
    """
    for ref in chain:
        if _sha_shaped(ref) or _short_name(ref).lower() == pin:
            return ref
    return None


def _agrees(recorded: str, pin: str) -> bool:
    """Do a recorded commit (or commit prefix) and the pin name the same commit?"""
    return recorded.startswith(pin) or pin.startswith(recorded)


def _checkout_verdict(
    plugin: InstalledPlugin, pin: str, checkout: GitCheckout
) -> Finding | None:
    """PLUGIN-003 for one pinned plugin's checkout, or ``None``.

    *pin* is the marketplace ``sha``: 40 hex, or an abbreviation of 7-39 hex
    (compared as a prefix of HEAD).  A swap shape anywhere on HEAD's
    symbolic-ref chain makes a mismatch CRITICAL even when HEAD's commit could
    not be read or has the wrong length: the name alone is the Plugin4Shell
    signature, and an unreadable or SHA-256 checkout must not hide it.
    """
    where = f"'{checkout.work_tree}'"
    evidence_base = (
        f"plugin: {plugin.plugin_id} | pinned sha: {pin} | git dir: {checkout.git_dir}"
    )
    chain = checkout.head_chain or (
        (checkout.head_ref,) if checkout.head_ref is not None else ()
    )
    swap_ref = _swap_ref(chain, pin)
    full = len(pin) == 40
    unresolved = checkout.unresolved
    head = checkout.head_commit
    if head is not None and full and len(head) != len(pin):
        unresolved = (
            "the checkout uses SHA-256 object ids and the pin is a SHA-1 id"
            if len(head) == 64
            else "the checkout's object ids are not the pin's length"
        )
    if head is not None and (head == pin or (not full and head.startswith(pin))):
        return None
    if (head is None or unresolved) and swap_ref is None:
        return _finding(
            plugin,
            PLUGIN_CHECKOUT_ID,
            severity=Severity.MEDIUM,
            title=f"Plugin checkout could not be verified against its pin: "
            f"{plugin.plugin_id}",
            description=(
                f"The marketplace pins {plugin.plugin_id} to commit {pin[:12]}, and"
                f" the plugin at {where} is a git checkout, but its HEAD could not"
                f" be compared with it by reading files: {unresolved}. So it is"
                " unknown whether the code on disk is the pinned commit. mcp-audit"
                " reads HEAD and the refs as files and never runs git."
            ),
            evidence=f"{evidence_base} | reason: {unresolved}",
            remediation=(
                f"Reinstall the plugin (`claude plugin uninstall {plugin.plugin_id}`,"
                " then install it again) on a current Claude Code; AIR Security"
                f" reports the Plugin4Shell fix in {_FIXED_IN}, and a refusal to"
                " install a checkout that does not land on the pin was observed on"
                " 2.1.311."
            ),
            finding_path=str(checkout.work_tree),
        )
    shown_head = head[:12] if head else "a commit it could not read"
    prefix = _version_prefix(plugin)
    on_branch = (
        f" (HEAD is on branch `{_branch_short(checkout.head_ref)}`)"
        if checkout.head_ref
        else " (HEAD is detached)"
    )
    evidence = (
        f"{evidence_base} | HEAD: {checkout.head_ref or 'detached'}"
        f" -> {head or 'unresolved'}"
        f" | recorded: {_recorded(plugin)}"
    )
    signature = swap_ref is not None
    claims_pin = (
        plugin.git_commit_sha is not None and _agrees(plugin.git_commit_sha, pin)
    ) or (prefix is not None and _agrees(prefix, pin))
    names_head = bool(head) and (
        plugin.git_commit_sha == head
        or (prefix is not None and head.startswith(prefix))
    )
    if signature or claims_pin:
        if swap_ref is not None:
            branch = _short_name(swap_ref)
            what = (
                "the pinned SHA"
                if branch.lower() == pin
                else ("`FETCH_HEAD`" if branch == "FETCH_HEAD" else "a commit SHA")
            )
            hop = (
                "" if swap_ref == checkout.head_ref else " (further down HEAD's chain)"
            )
            why = (
                f" HEAD reaches branch `{branch}`{hop}, named {what}: git checked"
                " out that branch instead of the commit, which is the Plugin4Shell"
                f" swap (AIR Security, 2026-09-17, {_PLUGIN4SHELL})."
            )
        else:
            why = (
                f" Claude Code's install record ({_recorded(plugin)}) says it"
                " installed the pinned commit, so the record and the code on disk"
                " disagree."
            )
        return _finding(
            plugin,
            PLUGIN_CHECKOUT_ID,
            severity=Severity.CRITICAL,
            title=f"Plugin checkout is not the commit its marketplace pins: "
            f"{plugin.plugin_id}",
            description=(
                f"The marketplace pins {plugin.plugin_id} to commit {pin[:12]}, but"
                f" the plugin's checkout at {where} resolves HEAD to {shown_head}"
                f"{'' if signature else on_branch}.{why} Claude Code loads the code"
                " on disk, so the"
                " plugin's skills, hooks and MCP servers come from a commit the"
                " marketplace did not pin. mcp-audit read HEAD and the refs as"
                " files; it did not run git."
            ),
            evidence=evidence,
            remediation=(
                f"Disable the plugin now (`claude plugin disable {plugin.plugin_id}`),"
                f" update Claude Code (AIR Security reports the Plugin4Shell fix in"
                f" {_FIXED_IN}; a refusal to install a checkout that does not land on"
                " the pin was observed on 2.1.311), then uninstall and reinstall it."
                " Tell the marketplace owner, and review what the commit on disk"
                " changed."
            ),
            finding_path=str(checkout.work_tree),
        )
    if names_head and checkout.head_ref is None:
        return None  # pin drift: the checkout is what Claude Code recorded
    if names_head:
        why = (
            f" Claude Code's install record ({_recorded(plugin)}) names that commit,"
            " but HEAD is on a branch rather than detached at it, and a pinned"
            " install checks out the commit itself: this copy was not installed"
            " from the pin (it may predate the pin, or the checkout changed after"
            " install)."
        )
    else:
        why = (
            f" Claude Code's install record names {_recorded(plugin)}, so the record"
            " does not explain the difference. Either the marketplace moved its pin"
            " and this copy was kept (Claude Code keeps a cached copy until the"
            " plugin's version string changes), or the checkout changed after"
            " install; mcp-audit cannot tell which."
        )
    return _finding(
        plugin,
        PLUGIN_CHECKOUT_ID,
        severity=Severity.MEDIUM,
        title=f"Plugin checkout is not at its pinned commit: {plugin.plugin_id}",
        description=(
            f"The marketplace pins {plugin.plugin_id} to commit {pin[:12]}, but the"
            f" plugin's checkout at {where} resolves HEAD to {shown_head}{on_branch}."
            f"{why}"
        ),
        evidence=evidence,
        remediation=(
            f"Run `claude plugin update {plugin.plugin_id}` on a current Claude Code"
            f" (AIR Security reports the Plugin4Shell fix in {_FIXED_IN}). If HEAD"
            " still differs from the pin, uninstall and reinstall the plugin."
        ),
        finding_path=str(checkout.work_tree),
    )


def _shaped_refs_finding(plugin: InstalledPlugin, checkout: GitCheckout) -> Finding:
    refs = list(checkout.sha_shaped_refs)
    shown = ", ".join(refs[:_MAX_LISTED_REFS])
    more = (
        f" and {len(refs) - _MAX_LISTED_REFS} more"
        if len(refs) > _MAX_LISTED_REFS
        else ""
    )
    pinned = plugin.pinned_sha
    pin_note = (
        f" The marketplace pins this plugin to {pinned[:12]}, so a checkout of that"
        " pin is exactly what such a branch can redirect."
        if pinned
        else ""
    )
    return _finding(
        plugin,
        PLUGIN_CHANNEL_ID,
        severity=Severity.HIGH,
        title=(
            f"Plugin checkout has a branch named like a commit SHA: {plugin.plugin_id}"
        ),
        description=(
            f"The git checkout at '{checkout.work_tree}' holds {len(refs)} ref(s)"
            f" named like a commit SHA or `FETCH_HEAD`: {shown}{more}. When an agent"
            " runs `git checkout <sha>` and a local branch has exactly that name,"
            " git checks out the branch and only warns that the name is ambiguous;"
            " a remote's default branch becomes such a local branch on clone, and"
            " `git checkout FETCH_HEAD` likewise prefers a branch named `FETCH_HEAD`."
            " That is how Plugin4Shell (AIR Security, 2026-09-17) swapped a pinned"
            " plugin's code. GitHub refuses branch names shaped like a full SHA;"
            f" other hosts accept them.{pin_note}"
        ),
        evidence=(
            f"plugin: {plugin.plugin_id} | git dir: {checkout.git_dir}"
            f" | refs: {shown}{more}"
        ),
        remediation=(
            f"Uninstall the plugin (`claude plugin uninstall {plugin.plugin_id}`) and"
            " report the repository to the marketplace owner. Keep Claude Code"
            f" current (AIR Security reports the Plugin4Shell fix in {_FIXED_IN}; a"
            " refusal to install a checkout that does not land on the pin was"
            " observed on 2.1.311)."
        ),
        finding_path=str(checkout.git_dir),
    )


def _posture_findings(plugin: InstalledPlugin) -> list[Finding]:
    """PLUGIN-004 MEDIUM (short pin) and LOW (non-github.com host), from records."""
    if plugin.source_type not in GIT_SOURCE_TYPES or not isinstance(
        plugin.source, dict
    ):
        return []
    raw = plugin.source.get("sha")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return []  # no pin at all: PLUGIN-002
    pin = plugin.pinned_sha
    if pin is None:
        shown = (
            repr(raw.strip()[:80])
            if isinstance(raw, str)
            else f"a {type(raw).__name__} value"
        )
        return [
            _finding(
                plugin,
                PLUGIN_CHANNEL_ID,
                severity=Severity.MEDIUM,
                title=f"Plugin pin is not a full commit SHA: {plugin.plugin_id}",
                description=(
                    f"The marketplace entry for {plugin.plugin_id} sets `sha` to"
                    f" {shown}, which is not a full 40-character commit SHA, the"
                    " form Claude Code's marketplace reference requires. Git reads an"
                    " abbreviated hash as a ref name first: a tag or branch with that"
                    " name is checked out instead of the commit (verified with git"
                    " 2.43), and the pin gives the confidence of a pin without its"
                    " guarantee."
                ),
                evidence=(
                    f"plugin: {plugin.plugin_id} | source type: {plugin.source_type}"
                    f" | sha: {shown}"
                ),
                remediation=(
                    "Ask the marketplace owner to pin the entry with the full"
                    " 40-character commit SHA."
                ),
                finding_path=str(plugin.record_path),
            )
        ]
    host, location = source_host(plugin.source)
    if host == "github.com":
        return []
    shown_host = host or "a host mcp-audit could not identify"
    return [
        _finding(
            plugin,
            PLUGIN_CHANNEL_ID,
            severity=Severity.LOW,
            title=(
                f"Pinned plugin is fetched from outside github.com: {plugin.plugin_id}"
            ),
            description=(
                f"{plugin.plugin_id} is pinned to {pin[:12]} and fetched from"
                f" {shown_host}. GitHub refuses branch names shaped like a full"
                " commit SHA, which blocks the Plugin4Shell swap there; GitLab,"
                " Bitbucket and self-hosted servers accept them (AIR Security,"
                f" 2026-09-17), who report the fix in Claude Code {_FIXED_IN}; the"
                " refusal to install a checkout that does not land on the pin was"
                " observed on 2.1.311."
            ),
            evidence=(
                f"plugin: {plugin.plugin_id} | source type: {plugin.source_type}"
                f" | location: {location or 'unknown'} | sha: {pin}"
            ),
            remediation=(
                "Keep Claude Code current. If this plugin is also"
                " installed with an older version or another agent, prefer a"
                " GitHub-hosted source or a mirror you control."
            ),
            finding_path=str(plugin.record_path),
        )
    ]


# ══ Entry point ═══════════════════════════════════════════════════════════════


def _git_checks(work_tree: Path, errors: list[str]) -> list[Finding]:
    """Run the git-config and hook checks (TRUST-006/007) on one checkout."""
    try:
        return _git.scan_repository(work_tree, scan_root=work_tree)
    except Exception as exc:  # noqa: BLE001 — never fail the scan over one checkout
        errors.append(f"plugin checkout {work_tree}: git config check failed: {exc}")
        return []


def _marketplace_clones(root: Path, errors: list[str]) -> list[Path]:
    clones = root / "marketplaces"
    try:
        names = sorted(os.listdir(clones))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as exc:
        errors.append(f"plugin marketplaces: '{clones}' could not be listed: {exc}")
        return []
    if len(names) > _MAX_MARKETPLACES:
        errors.append(
            f"plugin marketplaces: only the first {_MAX_MARKETPLACES} of"
            f" {len(names)} marketplace clones were checked"
        )
    return [clones / name for name in names[:_MAX_MARKETPLACES]]


def _checkout_at(
    path: Path | None,
    root: Path,
    budget: _Budget,
    checked: set[Path],
    errors: list[str],
    *,
    report_skips: bool = True,
) -> GitCheckout | None:
    """Read the git checkout at *path* once per scan, within *root* and budget.

    ``None`` when there is nothing to check: no path, already checked, no
    ``.git`` of its own, or a path outside *root* (a plugin loaded in place
    from a local marketplace is the user's own directory, not a checkout
    Claude Code made; that skip is silent).  A symlinked directory between
    *root* and *path*, or a spent budget, is skipped and reported in *errors*
    when *report_skips* is set (git-sourced plugins and marketplace clones;
    a ``command`` source in link mode legitimately loads through links).
    """
    if path is None:
        return None
    real = _git._real(path)
    if real in checked:
        return None
    checked.add(real)
    if not os.path.lexists(path / ".git"):
        return None
    reason = _under_root(path, root)
    if reason == _OUTSIDE_ROOT:
        return None
    if reason is not None:
        if report_skips:
            errors.append(f"plugin checkout {path}: not read: {reason}")
        return None
    if budget.checkouts_left <= 0:
        errors.append(
            f"plugin checkout {path}: not read: this scan's checkout budget is spent"
        )
        return None
    budget.checkouts_left -= 1
    checkout = read_git_checkout(path, root=root, budget=budget)
    if checkout is not None and checkout.refs_incomplete:
        errors.append(
            f"plugin checkout {path}: refs listed in part: {checkout.refs_incomplete}"
        )
    return checkout


def _short_pin(plugin: InstalledPlugin) -> str | None:
    """A 7-39 hex abbreviated ``sha``, lower-cased, or ``None``."""
    if not isinstance(plugin.source, dict):
        return None
    raw = plugin.source.get("sha")
    if not isinstance(raw, str):
        return None
    pin = raw.strip().lower()
    return pin if _SHORT_PIN_RE.fullmatch(pin) else None


def _analyze_one(
    plugin: InstalledPlugin,
    root: Path,
    budget: _Budget,
    checked: set[Path],
    posture_seen: set[str],
    errors: list[str],
) -> list[Finding]:
    """Every finding for one install record."""
    findings: list[Finding] = []
    if plugin.plugin_id not in posture_seen:
        posture_seen.add(plugin.plugin_id)
        findings.extend(_posture_findings(plugin))
    git_source = plugin.source_type in GIT_SOURCE_TYPES
    checkout = _checkout_at(
        plugin.install_path,
        root,
        budget,
        checked,
        errors,
        report_skips=git_source,
    )
    if checkout is None:
        return findings
    pin = plugin.pinned_sha or (_short_pin(plugin) if git_source else None)
    if git_source and pin is not None:
        verdict = _checkout_verdict(plugin, pin, checkout)
        if verdict is not None:
            findings.append(verdict)
    elif checkout.unresolved:
        errors.append(
            f"plugin checkout {checkout.work_tree}: {_printable(checkout.unresolved)}"
        )
    if git_source and checkout.sha_shaped_refs:
        findings.append(_shaped_refs_finding(plugin, checkout))
    if checkout.located:
        findings.extend(_git_checks(checkout.work_tree, errors))
    return findings


def _analyze_clone(
    clone: Path, root: Path, budget: _Budget, checked: set[Path], errors: list[str]
) -> list[Finding]:
    """TRUST-006/007 for one marketplace clone."""
    checkout = _checkout_at(clone, root, budget, checked, errors)
    if checkout is None:
        return []
    if checkout.located:
        return _git_checks(clone, errors)
    errors.append(f"plugin marketplace {clone}: not read: {checkout.unresolved}")
    return []


def analyze_plugin_pins(
    plugins: list[InstalledPlugin],
    *,
    root: Path | None = None,
    errors: list[str] | None = None,
) -> list[Finding]:
    """PLUGIN-003/004 for installed plugins, plus TRUST-006/007 on their checkouts.

    For each install record: the update-channel posture of its marketplace
    entry (PLUGIN-004 MEDIUM/LOW, once per plugin id) and, when its install
    directory is a git checkout under the plugins root, HEAD against the pin
    (PLUGIN-003), SHA-shaped refs (PLUGIN-004 HIGH) and the checkout's git
    config and hooks (TRUST-006/007).  Every marketplace clone under
    ``<root>/marketplaces/`` gets TRUST-006/007 too: Claude Code runs git there
    to refresh it.

    Args:
        plugins: Install records from
            :func:`~mcp_audit.plugins.discovery.discover_installed_plugins`.
        root: The plugins root; defaults to :func:`plugins_root`.
        errors: Receives a line for every checkout that was skipped or read
            only in part (budgets, symlinks, unreadable files).

    Returns:
        Findings, de-duplicated.
    """
    root = root if root is not None else plugins_root()
    errors = errors if errors is not None else []
    budget = _Budget()
    findings: list[Finding] = []
    posture_seen: set[str] = set()
    checked: set[Path] = set()

    for plugin in plugins:
        try:
            findings.extend(
                _analyze_one(plugin, root, budget, checked, posture_seen, errors)
            )
        except Exception as exc:  # noqa: BLE001 — one odd record must not stop the rest
            errors.append(
                f"plugin checkout {_printable(plugin.install_path)}: not checked:"
                f" {type(exc).__name__}: {_printable(exc)}"
            )

    for clone in _marketplace_clones(root, errors):
        try:
            findings.extend(_analyze_clone(clone, root, budget, checked, errors))
        except Exception as exc:  # noqa: BLE001 — same
            errors.append(
                f"plugin marketplace {_printable(clone)}: not checked:"
                f" {type(exc).__name__}: {_printable(exc)}"
            )

    return _git._dedupe(findings)
