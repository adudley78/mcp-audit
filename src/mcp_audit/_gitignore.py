"""Is a file ignored by git?  Answered by reading ignore files, never by running git.

SANDBOX-005 (STORY-0093) asks whether a Claude Code settings file is headed for
a commit.  Running ``git check-ignore`` would answer it, but a checkout can
carry ``core.fsmonitor`` and other keys that make ``git`` run a command
(STORY-0089), so this module only reads files.

What is read, lowest precedence first (gitignore(5): patterns in lower-level
``.gitignore`` files override higher-level ones, ``.gitignore`` files override
``$GIT_DIR/info/exclude``, which overrides ``core.excludesFile``; "within one
level of precedence, the last matching pattern decides the outcome"):

1. The global excludes file.  ``core.excludesFile`` from the global git config
   (``$XDG_CONFIG_HOME/git/config`` or ``~/.config/git/config``, then
   ``~/.gitconfig``, the later one winning) when it is an absolute or
   ``~/``-prefixed path; when the key is unset,
   ``$XDG_CONFIG_HOME/git/ignore`` or ``~/.config/git/ignore``.  Claude Code
   writes ``**/.claude/settings.local.json`` to exactly this file the first
   time it creates a local settings file (code.claude.com/docs/en/settings).
2. ``.git/info/exclude``, when ``.git`` is a real directory.
3. Every ``.gitignore`` from the work-tree root down to the file's directory.
   A ``.gitignore`` that is a symlink is skipped, as git does since 2.32
   (".gitignore ... files that are symbolic links are ignored").

Pattern semantics follow gitignore(5): ``#`` comments, ``!`` negation,
trailing ``/`` for directories only, a ``/`` at the start or in the middle
anchors the pattern at its file's directory, ``*``/``?``/``[...]`` never match
``/``, ``**`` as a whole segment matches any number of directories, and "It is
not possible to re-include a file if a parent directory of that file is
excluded."  Wildcards are matched with a linear-time algorithm, never a
backtracking regular expression.

Not modelled (documented in GAPS.md): whether the file is already *tracked*
(a tracked file stays in git even when an ignore file matches it; that needs
``.git/index``), ``core.ignoreCase`` (matching is case-sensitive),
``core.excludesFile`` set in the repository's own or the system config,
``includeIf`` and nested includes in git config (a plain ``[include] path``
is followed one level), ``GIT_CONFIG_GLOBAL``, and
``info/exclude`` of a worktree or submodule whose ``.git`` is a file.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

#: Largest ignore or git config file read.  Git reads any size; a bigger file
#: makes the answer unknown rather than being read in part.
MAX_FILE_BYTES = 1024 * 1024
#: Total bytes and distinct files one :class:`IgnoreFileReader` reads.
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_FILES = 512
#: Longest single pattern considered; longer lines are skipped.
MAX_PATTERN_CHARS = 4096
#: Levels :func:`find_work_tree_root` climbs before giving up.
MAX_ROOT_LEVELS = 64
#: Wildcard and path-cell steps one reader may spend matching patterns.  A
#: real repository needs thousands; hitting this is reported, not silent.
MAX_MATCH_STEPS = 5_000_000
#: ``[include] path`` entries followed per global git config file (one level).
MAX_INCLUDES = 16


# ── Pattern parsing ───────────────────────────────────────────────────────────


class _Star:
    """``*``: any run of characters within one path segment."""


class _Any:
    """``?``: any one character within one path segment."""


_STAR = _Star()
_ANY = _Any()

_POSIX_CLASSES = {
    "alnum": str.isalnum,
    "alpha": str.isalpha,
    "blank": lambda c: c in " \t",
    "cntrl": lambda c: ord(c) < 32 or ord(c) == 127,
    "digit": str.isdigit,
    "graph": lambda c: c.isprintable() and not c.isspace(),
    "lower": str.islower,
    "print": str.isprintable,
    "punct": lambda c: c.isprintable() and not c.isalnum() and not c.isspace(),
    "space": str.isspace,
    "upper": str.isupper,
    "xdigit": lambda c: c in "0123456789abcdefABCDEF",
}


@dataclass(frozen=True)
class _Class:
    """A ``[...]`` bracket expression."""

    negated: bool
    chars: frozenset[str]
    ranges: tuple[tuple[str, str], ...]
    classes: tuple[str, ...]

    def matches(self, ch: str) -> bool:
        hit = (
            ch in self.chars
            or any(lo <= ch <= hi for lo, hi in self.ranges)
            or any(_POSIX_CLASSES[name](ch) for name in self.classes)
        )
        return hit != self.negated


_Token = str | _Star | _Any | _Class


def _parse_class(text: str, i: int) -> tuple[_Class, int] | None:
    """Parse a bracket expression starting after ``[`` at *i*; ``None`` if unclosed."""
    negated = i < len(text) and text[i] in "!^"
    if negated:
        i += 1
    chars: set[str] = set()
    ranges: list[tuple[str, str]] = []
    classes: list[str] = []
    first = True
    while i < len(text):
        ch = text[i]
        if ch == "]" and not first:
            return _Class(
                negated, frozenset(chars), tuple(ranges), tuple(classes)
            ), i + 1
        first = False
        if ch == "[" and text.startswith("[:", i):
            end = text.find(":]", i + 2)
            name = text[i + 2 : end] if end >= 0 else ""
            if name not in _POSIX_CLASSES:
                return None  # wildmatch aborts on an unknown class
            classes.append(name)
            i = end + 2
            continue
        if ch == "\\":
            i += 1
            if i >= len(text):
                return None
            ch = text[i]
        if i + 2 < len(text) and text[i + 1] == "-" and text[i + 2] != "]":
            hi = text[i + 2]
            if hi == "\\" and i + 3 < len(text):
                hi = text[i + 3]
                i += 1
            ranges.append((ch, hi))
            i += 3
            continue
        chars.add(ch)
        i += 1
    return None


def _tokenize(segment: str) -> tuple[_Token, ...] | None:
    """Wildcard tokens for one path segment; ``None`` for a malformed pattern.

    Consecutive ``*`` collapse to one ("Other consecutive asterisks are
    considered regular asterisks").  A malformed bracket or a trailing ``\\``
    makes the pattern match nothing, as git's wildmatch does.
    """
    tokens: list[_Token] = []
    i = 0
    while i < len(segment):
        ch = segment[i]
        if ch == "*":
            if not tokens or tokens[-1] is not _STAR:
                tokens.append(_STAR)
            i += 1
        elif ch == "?":
            tokens.append(_ANY)
            i += 1
        elif ch == "[":
            parsed = _parse_class(segment, i + 1)
            if parsed is None:
                return None
            tokens.append(parsed[0])
            i = parsed[1]
        elif ch == "\\":
            if i + 1 >= len(segment):
                return None
            tokens.append(segment[i + 1])
            i += 2
        else:
            tokens.append(ch)
            i += 1
    return tuple(tokens)


class MatchBudgetExceededError(Exception):
    """A :class:`MatchMeter` ran out of steps."""


@dataclass
class MatchMeter:
    """Counts matching work so one scan's pattern matching stays bounded.

    Attributes:
        limit: Steps allowed before :class:`MatchBudgetExceededError`.
        steps: Steps spent so far.
    """

    limit: int = MAX_MATCH_STEPS
    steps: int = 0

    def charge(self, steps: int) -> None:
        """Add *steps*; raise :class:`MatchBudgetExceededError` past the limit."""
        self.steps += steps
        if self.steps > self.limit:
            raise MatchBudgetExceededError


def _wild(
    tokens: tuple[_Token, ...], text: str, meter: MatchMeter | None = None
) -> bool:
    """Match one segment: greedy with one backtrack point, O(tokens x text).

    The work done is charged to *meter* when one is given.
    """
    counter = [0]
    matched = _wild_steps(tokens, text, counter)
    if meter is not None:
        meter.charge(counter[0] + 1)
    return matched


def _wild_steps(tokens: tuple[_Token, ...], text: str, counter: list[int]) -> bool:
    p = i = 0
    star_p = -1
    star_i = 0
    n = len(tokens)
    while i < len(text):
        counter[0] += 1
        if p < n and tokens[p] is _STAR:
            star_p, star_i = p, i
            p += 1
            continue
        if p < n:
            tok = tokens[p]
            if tok is _ANY or (
                tok == text[i]
                if isinstance(tok, str)
                else isinstance(tok, _Class) and tok.matches(text[i])
            ):
                p += 1
                i += 1
                continue
        if star_p >= 0:
            p = star_p + 1
            star_i += 1
            i = star_i
            continue
        return False
    while p < n and tokens[p] is _STAR:
        p += 1
    return p == n


class _Globstar:
    """A whole ``**`` segment: zero or more directories."""


_GLOBSTAR = _Globstar()

_Segment = tuple[_Token, ...] | _Globstar


@dataclass(frozen=True)
class IgnorePattern:
    """One line of an ignore file, parsed.

    Attributes:
        text: The line as written (trailing whitespace removed).
        negated: The line started with ``!``.
        dir_only: The line ended with ``/``: it matches directories only.
        anchored: The pattern had a ``/`` at its start or middle, so it is
            matched against the whole path relative to its file's directory;
            otherwise against the last path segment at any depth.
        segments: For an anchored pattern, one token tuple per segment, with
            a globstar marker for a whole ``**`` segment (consecutive ones
            collapsed); for an unanchored pattern, a single token tuple.
        min_parts: The fewest path parts the pattern can match, so a long
            pattern is rejected against a short path without any matching.
    """

    text: str
    negated: bool
    dir_only: bool
    anchored: bool
    segments: tuple[_Segment, ...]
    min_parts: int = 1

    def matches(
        self, rel_parts: Sequence[str], is_dir: bool, meter: MatchMeter | None = None
    ) -> bool:
        """True when this pattern matches *rel_parts* (a path below its directory).

        Raises:
            MatchBudgetExceededError: *meter* ran out of steps.
        """
        if not rel_parts or (self.dir_only and not is_dir):
            return False
        if self.anchored and self.min_parts > len(rel_parts):
            return False
        if meter is not None:
            meter.charge(1)
        if not self.anchored:
            only = self.segments[0]
            return isinstance(only, tuple) and _wild(only, rel_parts[-1], meter)
        return _match_segments(self.segments, rel_parts, meter)


def _match_segments(
    segments: tuple[_Segment, ...],
    parts: Sequence[str],
    meter: MatchMeter | None = None,
) -> bool:
    """Anchored match with ``**`` segments: dynamic programming, O(pattern x path)."""
    n, m = len(segments), len(parts)
    if meter is not None:
        meter.charge(n * (m + 1))
    # ok[j]: segments[i:] matches parts[j:], built from i = n down to 0.
    ok = [False] * (m + 1)
    ok[m] = True
    for i in range(n - 1, -1, -1):
        seg = segments[i]
        new = [False] * (m + 1)
        for j in range(m, -1, -1):
            if isinstance(seg, _Globstar):
                if i == n - 1:
                    # "abc/**" matches everything inside abc, not abc itself.
                    new[j] = j < m
                else:
                    new[j] = ok[j] or (j < m and new[j + 1])
            else:
                new[j] = j < m and ok[j + 1] and _wild(seg, parts[j], meter)
        ok = new
    return ok[0]


def _strip_trailing_spaces(line: str) -> str:
    """Drop trailing spaces unless the last one is escaped with ``\\``."""
    end = len(line)
    while end and line[end - 1] == " ":
        backslashes = 0
        k = end - 2
        while k >= 0 and line[k] == "\\":
            backslashes += 1
            k -= 1
        if backslashes % 2:
            break
        end -= 1
    return line[:end]


def parse_ignore_text(text: str) -> list[IgnorePattern]:
    """Parse the contents of a ``.gitignore``-format file.

    Blank lines and ``#`` comments are skipped, a UTF-8 byte-order mark and a
    trailing carriage return are dropped, and a line longer than
    :data:`MAX_PATTERN_CHARS` is skipped.  Patterns git never matches are
    dropped: a malformed one (an unclosed ``[``, a trailing ``\\``), one with
    an empty segment (``a//b``), and one ending in ``//``.  A whole segment of
    two or more ``*`` is a ``**``, and consecutive ``**`` segments collapse.
    """
    patterns: list[IgnorePattern] = []
    if text.startswith("\ufeff"):
        text = text[1:]
    for raw_line in text.split("\n"):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        line = _strip_trailing_spaces(line)
        if not line or line.startswith("#") or len(line) > MAX_PATTERN_CHARS:
            continue
        negated = line.startswith("!")
        body = line[1:] if negated else line
        if body.startswith(("\\#", "\\!")):
            body = body[1:]
        dir_only = body.endswith("/")
        if dir_only:
            body = body[:-1]
            if body.endswith("/"):
                continue  # "a//": git keeps "a/", which matches no path
        if not body:
            continue
        anchored = "/" in body
        if body.startswith("/"):
            body = body[1:]
        segments = _parse_segments(body) if anchored else _unanchored(body)
        if segments is None:
            continue
        patterns.append(
            IgnorePattern(
                text=line,
                negated=negated,
                dir_only=dir_only,
                anchored=anchored,
                segments=segments,
                min_parts=_min_parts(segments) if anchored else 1,
            )
        )
    return patterns


def _unanchored(body: str) -> tuple[_Segment, ...] | None:
    tokens = _tokenize(body)  # an unanchored "**" is just "*"
    return None if tokens is None else (tokens,)


def _parse_segments(body: str) -> tuple[_Segment, ...] | None:
    """Segments of an anchored pattern, or ``None`` if git would never match it."""
    segments: list[_Segment] = []
    for raw in body.split("/"):
        if raw == "":
            return None  # "a//b": a path never has an empty segment
        if len(raw) >= 2 and set(raw) == {"*"}:
            if not (segments and isinstance(segments[-1], _Globstar)):
                segments.append(_GLOBSTAR)
            continue
        tokens = _tokenize(raw)
        if tokens is None:
            return None
        segments.append(tokens)
    return tuple(segments) or None


def _min_parts(segments: tuple[_Segment, ...]) -> int:
    """Fewest path parts *segments* can match (a trailing ``**`` needs one)."""
    fixed = sum(1 for seg in segments if not isinstance(seg, _Globstar))
    return fixed + (1 if isinstance(segments[-1], _Globstar) else 0)


# ── Deciding ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IgnoreSource:
    """The patterns of one ignore file and the directory they are relative to.

    Attributes:
        base: The file's directory as path parts relative to the work-tree
            root (``()`` for the root, ``info/exclude`` and the global file).
        patterns: Its parsed lines, in file order.
        label: A short, root-relative name for messages (never an absolute
            path).
    """

    base: tuple[str, ...]
    patterns: tuple[IgnorePattern, ...]
    label: str


def _decide(
    path: tuple[str, ...],
    is_dir: bool,
    sources: Sequence[IgnoreSource],
    meter: MatchMeter | None = None,
) -> bool:
    """Last matching pattern across *sources* (lowest precedence first) decides."""
    ignored = False
    for source in sources:
        depth = len(source.base)
        # A file's patterns apply to paths strictly below its directory.
        if len(path) <= depth or path[:depth] != source.base:
            continue
        rel = path[depth:]
        for pattern in source.patterns:
            if pattern.matches(rel, is_dir, meter):
                ignored = not pattern.negated
    return ignored


def is_ignored(
    rel_parts: Sequence[str],
    sources: Sequence[IgnoreSource],
    meter: MatchMeter | None = None,
) -> bool:
    """True when the *file* at *rel_parts* (relative to the work-tree root) is ignored.

    Each parent directory is decided first: "It is not possible to re-include
    a file if a parent directory of that file is excluded."

    Args:
        rel_parts: The file's path parts below the work-tree root.
        sources: Ignore sources ordered lowest precedence first.
        meter: Charged with the matching work, when given.

    Raises:
        MatchBudgetExceededError: *meter* ran out of steps.
    """
    parts = tuple(rel_parts)
    for k in range(1, len(parts)):
        if _decide(parts[:k], True, sources, meter):
            return True
    return _decide(parts, False, sources, meter)


def find_work_tree_root(start: Path) -> Path | None:
    """The nearest directory at or above *start* that holds a ``.git`` entry.

    ``.git`` may be a directory, a file (worktree, submodule) or a link; its
    presence is all that is checked, and nothing inside it is read here.
    Filesystem errors end the search (``None``).
    """
    current = start
    for _ in range(MAX_ROOT_LEVELS):
        try:
            if os.path.lexists(current / ".git"):
                return current
        except OSError:
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent
    return None


# ── Reading ───────────────────────────────────────────────────────────────────


class IgnoreStateUnknownError(Exception):
    """Whether a path is ignored can't be known: a file could not be read."""


def _home_label(path: Path, home: Path) -> str:
    """``~/…`` for a path under *home*, else its name: never a full absolute path."""
    try:
        return "~/" + path.relative_to(home).as_posix()
    except ValueError:
        return path.name


def _strip_config_value(raw: str) -> str:
    """A git config value: quotes removed, ``\\`` escapes applied, comments cut."""
    out: list[str] = []
    in_quote = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            out.append({"n": "\n", "t": "\t", "b": "\b"}.get(nxt, nxt))
            i += 2
            continue
        if ch == '"':
            in_quote = not in_quote
        elif ch in "#;" and not in_quote:
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).strip()


def excludes_file_setting(
    text: str, include: Callable[[str], str | None] | None = None
) -> str | None:
    """The last ``core.excludesFile`` value in git config *text*, if any.

    Only plain ``[core]`` sections are read (section and key names are
    case-insensitive in git).  With *include*, a plain ``[include] path = …``
    is followed one level: *include* returns the target's text, which is read
    at that point as git does, without following its own includes.
    ``includeIf`` is not followed.
    """
    value: str | None = None
    section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("["):
            end = line.find("]")
            if end < 0:
                section = ""
                continue
            section = line[1:end].strip().lower()
            line = line[end + 1 :].strip()
            if not line:
                continue
        if not line or line[0] in "#;":
            continue
        name, sep, rest = line.partition("=")
        key = name.strip().lower()
        if not sep:
            continue
        if section == "core" and key == "excludesfile":
            value = _strip_config_value(rest)
        elif section == "include" and key == "path" and include is not None:
            included = include(_strip_config_value(rest))
            nested = excludes_file_setting(included) if included else None
            if nested is not None:
                value = nested
    return value


@dataclass
class IgnoreFileReader:
    """Reads ignore sources with a per-file size cap and a total budget.

    One reader is shared by every file checked in a scan, so the global
    excludes file and a repository's ``.gitignore`` files are read once.
    Anything that can't be read (an ``OSError``, a file over
    :data:`MAX_FILE_BYTES`, the budget spent) makes the answer for the
    affected path unknown: :meth:`is_ignored` raises
    :class:`IgnoreStateUnknownError`, and :attr:`errors` says why, without
    absolute paths.

    Attributes:
        home: The home directory (``Path.home()`` when not given).
        errors: One message per unreadable file or spent budget.
        global_label: Where the global excludes file was looked for
            (``~/…``), once the global sources have been read.
    """

    home: Path | None = None
    errors: list[str] = field(default_factory=list)
    global_label: str = ""
    _cache: dict[str, tuple[IgnorePattern, ...]] = field(default_factory=dict)
    _bytes: int = 0
    _files: int = 0
    _global: tuple[IgnoreSource, ...] | None = None
    _meter: MatchMeter = field(default_factory=MatchMeter)

    def _home(self) -> Path:
        return self.home if self.home is not None else Path.home()

    def _error(self, message: str) -> None:
        if message not in self.errors:
            self.errors.append(message)

    def _read(self, path: Path, label: str) -> str | None:
        """Text of *path*, ``None`` when absent; raises when it can't be read."""
        try:
            if not path.is_file():
                return None
        except OSError as exc:
            self._error(
                f"could not check {label}: {exc.strerror or type(exc).__name__}"
            )
            raise IgnoreStateUnknownError(label) from exc
        if self._files >= MAX_FILES or self._bytes >= MAX_TOTAL_BYTES:
            self._error(
                f"ignore-file budget reached ({MAX_FILES} files or"
                f" {MAX_TOTAL_BYTES // (1024 * 1024)} MiB); {label} and later"
                " files were not read"
            )
            raise IgnoreStateUnknownError(label)
        try:
            with path.open("rb") as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
        except OSError as exc:
            self._error(f"could not read {label}: {exc.strerror or type(exc).__name__}")
            raise IgnoreStateUnknownError(label) from exc
        self._files += 1
        self._bytes += len(data)
        if len(data) > MAX_FILE_BYTES:
            self._error(
                f"{label} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB"
                " and was not read"
            )
            raise IgnoreStateUnknownError(label)
        return data.decode("utf-8", errors="replace")

    def _patterns(self, path: Path, label: str) -> tuple[IgnorePattern, ...]:
        key = os.fspath(path)
        if key not in self._cache:
            text = self._read(path, label)
            self._cache[key] = tuple(parse_ignore_text(text)) if text else ()
        return self._cache[key]

    def global_excludes_path(self) -> Path | None:
        """Where git's global excludes file is, per the global git config.

        ``None`` when ``core.excludesFile`` is set to a relative path, which
        git does not resolve against any fixed directory.
        """
        home = self._home()
        xdg = os.environ.get("XDG_CONFIG_HOME") or ""
        config_dir = Path(xdg) if xdg else home / ".config"
        setting: str | None = None
        for config, label in (
            (
                config_dir / "git" / "config",
                _home_label(config_dir / "git" / "config", home),
            ),
            (home / ".gitconfig", "~/.gitconfig"),
        ):
            text = self._read(config, label)
            if text:
                found = excludes_file_setting(text, self._includer(config.parent))
                if found is not None:
                    setting = found
        if setting is None or setting == "":
            return config_dir / "git" / "ignore"
        if setting.startswith("~/"):
            return home / setting[2:]
        if Path(setting).is_absolute():
            return Path(setting)
        return None

    def _includer(self, base: Path) -> Callable[[str], str | None]:
        """Read an ``[include] path`` target for :func:`excludes_file_setting`.

        Relative paths resolve against the including file's directory and
        ``~/`` against the home directory, as git does.  At most
        :data:`MAX_INCLUDES` targets are read per file; each is size-capped
        and counted against the budget.
        """
        remaining = [MAX_INCLUDES]
        home = self._home()

        def read(value: str) -> str | None:
            if remaining[0] <= 0 or not value:
                return None
            remaining[0] -= 1
            if value.startswith("~/"):
                target = home / value[2:]
            elif Path(value).is_absolute():
                target = Path(value)
            else:
                target = base / value
            return self._read(target, _home_label(target, home))

        return read

    def _global_sources(self) -> tuple[IgnoreSource, ...]:
        if self._global is None:
            path = self.global_excludes_path()
            if path is None:
                self.global_label = "none: core.excludesFile is a relative path"
                self._global = ()
            else:
                label = _home_label(path, self._home())
                patterns = self._patterns(path, label)
                self.global_label = label
                self._global = (IgnoreSource((), patterns, label),)
        return self._global

    def sources(self, root: Path, rel_parts: Sequence[str]) -> list[IgnoreSource]:
        """Every ignore source that applies to the file at *rel_parts* under *root*.

        Raises:
            IgnoreStateUnknownError: a source exists but could not be read.
        """
        sources = list(self._global_sources())
        name = root.name or "repository"
        git_dir = root / ".git"
        try:
            real_git_dir = git_dir.is_dir() and not git_dir.is_symlink()
        except OSError:
            real_git_dir = False
        if real_git_dir:
            label = f"{name}/.git/info/exclude"
            sources.append(
                IgnoreSource(
                    (), self._patterns(git_dir / "info" / "exclude", label), label
                )
            )
        directory = root
        dirs: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
        for k, part in enumerate(rel_parts[:-1]):
            directory = directory / part
            dirs.append((directory, tuple(rel_parts[: k + 1])))
        for directory, base in dirs:
            gitignore = directory / ".gitignore"
            label = "/".join((name, *base, ".gitignore"))
            try:
                if base and directory.is_symlink():
                    # Git records a symlinked directory as a link and never
                    # reads ignore files behind it; neither does this.
                    break
                linked = gitignore.is_symlink()
            except OSError as exc:
                self._error(
                    f"could not check {label}: {exc.strerror or type(exc).__name__}"
                )
                raise IgnoreStateUnknownError(label) from exc
            if linked:
                continue  # git >= 2.32 ignores a .gitignore that is a symlink
            sources.append(IgnoreSource(base, self._patterns(gitignore, label), label))
        return sources

    def is_ignored(self, root: Path, rel_parts: Sequence[str]) -> bool:
        """True when the file at *rel_parts* under work-tree *root* is ignored.

        Raises:
            IgnoreStateUnknownError: an ignore source could not be read, or
                the matching budget (:data:`MAX_MATCH_STEPS`) is spent.
        """
        sources = self.sources(root, rel_parts)
        try:
            return is_ignored(rel_parts, sources, self._meter)
        except MatchBudgetExceededError as exc:
            self._error(
                f"ignore-pattern matching budget reached ({self._meter.limit:,}"
                " steps); this and later files were not checked"
            )
            raise IgnoreStateUnknownError("matching budget") from exc
