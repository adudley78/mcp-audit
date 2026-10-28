"""Decide whether a path in a repository is ``.gitignore``'d, by reading files only.

MEM-003 (STORY-0098) reports an instruction-file import whose target is
matched by ``.gitignore``: such a file is normally never committed, so what it
puts in the agent's context never shows up in review or ``git diff``.  This
module answers that one question without running ``git`` — a checkout can
carry ``core.fsmonitor`` and other exec keys, and running git in it is the
attack (STORY-0089).

What is read: ``.gitignore`` in the scan root and in every directory between
the root and the target.  What is not read: ``.git/info/exclude``,
``core.excludesFile`` and the index, so a file that is tracked despite a
matching pattern (``git add -f``) still counts as ignored here (GAPS.md).

Semantics follow the gitignore documentation
(https://git-scm.com/docs/gitignore): blank lines and ``#`` comments skipped;
trailing unescaped spaces trimmed; ``!`` negates; a trailing ``/`` matches
directories only; a pattern with a ``/`` at the start or in the middle is
anchored to its ``.gitignore``'s directory, otherwise it matches the name at
any level; ``*``/``?``/``[...]`` never match ``/``; ``**/``, ``/**/`` and a
trailing ``/**`` cross directories; the last matching pattern wins, deeper
files override shallower ones; and a file can't be re-included when a parent
directory is excluded.  A ``.gitignore`` that is itself a symlink is skipped,
as git (2.32+) does.

Matching is case-insensitive: git defaults ``core.ignorecase`` to true on
the case-insensitive filesystems of macOS and Windows, and of the two
readings this is the one that reports more.

Every pattern is matched with a non-backtracking dynamic programme
(O(pattern tokens × path length)), so a hostile ``.gitignore`` cannot make
matching super-linear; files, lines and pattern lengths are capped.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

# ── Limits ────────────────────────────────────────────────────────────────────

#: Bytes read from one ``.gitignore``.
GITIGNORE_MAX_BYTES: int = 256 * 1024
#: Patterns kept from one ``.gitignore``.
GITIGNORE_MAX_RULES: int = 10_000
#: Tokens in one pattern; longer patterns are skipped (and counted).
GITIGNORE_MAX_TOKENS: int = 512
#: ``.gitignore`` files read per index (one index per scan pass).
GITIGNORE_MAX_FILES: int = 200
#: Path length matched against a pattern.
_MAX_PATH_CHARS: int = 4096

# Token kinds.
_LIT = 0  # one literal character
_ANY = 1  # ``?``: one character except ``/``
_CLASS = 2  # ``[...]``: one character except ``/``
_STAR = 3  # ``*``: any run without ``/``
_DSTAR_DIR = 4  # ``**/``: zero or more whole directories
_DSTAR_ALL = 5  # trailing ``/**``: anything

_Token = tuple[int, object]


@dataclass(frozen=True)
class GitignoreRule:
    """One parsed ``.gitignore`` pattern."""

    text: str
    tokens: tuple[_Token, ...]
    negate: bool
    dir_only: bool
    basename_only: bool


def _parse_class(pattern: str, i: int) -> tuple[_Token | None, int]:
    """Parse a ``[...]`` bracket expression starting at ``pattern[i] == '['``.

    Returns ``(token, next_index)``, or ``(None, i + 1)`` when the bracket is
    never closed (the ``[`` is then a literal, as in fnmatch).
    """
    j = i + 1
    negated = False
    if j < len(pattern) and pattern[j] in "!^":
        negated = True
        j += 1
    items: list[tuple[str, str]] = []
    first = True
    while j < len(pattern):
        c = pattern[j]
        if c == "]" and not first:
            return (_CLASS, (negated, tuple(items))), j + 1
        first = False
        if c == "\\" and j + 1 < len(pattern):
            j += 1
            c = pattern[j]
        lo = c
        if j + 2 < len(pattern) and pattern[j + 1] == "-" and pattern[j + 2] != "]":
            hi = pattern[j + 2]
            if hi == "\\" and j + 3 < len(pattern):
                hi = pattern[j + 3]
                j += 1
            items.append((lo, hi))
            j += 3
            continue
        items.append((lo, lo))
        j += 1
    return None, i + 1


def _tokenize(body: str) -> tuple[_Token, ...] | None:
    """Turn a pattern body (no ``!``, no leading/trailing ``/``) into tokens.

    Returns ``None`` for a pattern git would never match (a trailing lone
    backslash) or one longer than :data:`GITIGNORE_MAX_TOKENS`.
    """
    tokens: list[_Token] = []
    i = 0
    n = len(body)
    while i < n:
        if len(tokens) > GITIGNORE_MAX_TOKENS:
            return None
        c = body[i]
        if c == "\\":
            if i + 1 >= n:
                return None
            tokens.append((_LIT, body[i + 1]))
            i += 2
            continue
        if c == "*":
            j = i
            while j < n and body[j] == "*":
                j += 1
            run = j - i
            at_start = i == 0 or body[i - 1] == "/"
            if run >= 2 and at_start and j < n and body[j] == "/":
                tokens.append((_DSTAR_DIR, None))
                i = j + 1
                continue
            if run >= 2 and at_start and j == n and i > 0:
                tokens.append((_DSTAR_ALL, None))
                i = j
                continue
            if run >= 2 and at_start and j == n and i == 0:
                # A pattern that is only ``**`` matches everything.
                tokens.append((_DSTAR_ALL, None))
                i = j
                continue
            tokens.append((_STAR, None))
            i = j
            continue
        if c == "?":
            tokens.append((_ANY, None))
            i += 1
            continue
        if c == "[":
            tok, nxt = _parse_class(body, i)
            if tok is not None:
                tokens.append(tok)
                i = nxt
                continue
        tokens.append((_LIT, c))
        i += 1
    if len(tokens) > GITIGNORE_MAX_TOKENS:
        return None
    return tuple(tokens)


def _in_class(spec: object, ch: str) -> bool:
    negated, items = spec  # type: ignore[misc]
    hit = any(lo <= ch <= hi for lo, hi in items)
    return hit != negated


def wildmatch(tokens: tuple[_Token, ...], path: str) -> bool:
    """Return True when *tokens* match the whole of *path*.

    A single left-to-right dynamic programme over path positions per token,
    so the cost is O(len(tokens) × len(path)) whatever the pattern.
    """
    n = len(path)
    cur = [False] * (n + 1)
    cur[0] = True
    for kind, value in tokens:
        nxt = [False] * (n + 1)
        if kind == _LIT:
            for i in range(n):
                if cur[i] and path[i] == value:
                    nxt[i + 1] = True
        elif kind == _ANY:
            for i in range(n):
                if cur[i] and path[i] != "/":
                    nxt[i + 1] = True
        elif kind == _CLASS:
            for i in range(n):
                if cur[i] and path[i] != "/" and _in_class(value, path[i]):
                    nxt[i + 1] = True
        elif kind == _STAR:
            for i in range(n + 1):
                if cur[i] or (i > 0 and nxt[i - 1] and path[i - 1] != "/"):
                    nxt[i] = True
        elif kind == _DSTAR_ALL:
            for i in range(n + 1):
                if cur[i] or (i > 0 and nxt[i - 1]):
                    nxt[i] = True
        else:  # _DSTAR_DIR: "" or "a/", "a/b/", ...
            seen = False
            for i in range(n + 1):
                if cur[i] or (seen and i > 0 and path[i - 1] == "/"):
                    nxt[i] = True
                if cur[i]:
                    seen = True
        cur = nxt
        if not any(cur):
            return False
    return cur[n]


def parse_gitignore(text: str) -> tuple[list[GitignoreRule], int]:
    """Parse ``.gitignore`` text into rules.

    Returns ``(rules, skipped)`` where *skipped* counts patterns dropped for
    exceeding a limit (they are reported by the caller, never silently lost).
    """
    rules: list[GitignoreRule] = []
    skipped = 0
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line or line.startswith("#"):
            continue
        # Trailing spaces are trimmed unless escaped with a backslash.
        while line.endswith(" ") and not line.endswith("\\ "):
            line = line[:-1]
        if not line:
            continue
        negate = False
        if line.startswith("!"):
            negate = True
            line = line[1:]
        elif line.startswith("\\!") or line.startswith("\\#"):
            line = line[1:]
        dir_only = False
        if line.endswith("/") and not line.endswith("\\/"):
            dir_only = True
            line = line.rstrip("/")
        if not line:
            continue
        anchored_slash = "/" in line
        body = line[1:] if line.startswith("/") else line
        if not body:
            continue
        tokens = _tokenize(body.lower())
        if tokens is None:
            skipped += 1
            continue
        rules.append(
            GitignoreRule(
                text=raw_line.strip(),
                tokens=tokens,
                negate=negate,
                dir_only=dir_only,
                basename_only=not anchored_slash,
            )
        )
        if len(rules) >= GITIGNORE_MAX_RULES:
            skipped += 1
            break
    return rules, skipped


def _rule_matches(
    rule: GitignoreRule, rel_parts: tuple[str, ...], is_dir: bool
) -> bool:
    if rule.dir_only and not is_dir:
        return False
    subject = rel_parts[-1] if rule.basename_only else "/".join(rel_parts)
    if len(subject) > _MAX_PATH_CHARS:
        return False
    return wildmatch(rule.tokens, subject.lower())


class GitignoreIndex:
    """Lazily read ``.gitignore`` files under one root and answer queries.

    Args:
        root: The scan root (resolved).  Only ``.gitignore`` files at or
            below it are read.
        notes: Optional list that receives one line per problem (an
            unreadable or oversized file, skipped patterns, the file budget).
    """

    def __init__(self, root: Path, notes: list[str] | None = None) -> None:
        self._root = root
        self._notes = notes
        self._cache: dict[tuple[str, ...], tuple[Path, list[GitignoreRule]]] = {}
        self._files_read = 0
        self._budget_noted = False

    def _note(self, text: str) -> None:
        if self._notes is not None:
            self._notes.append(text)

    def _rules_for(
        self, dir_parts: tuple[str, ...]
    ) -> tuple[Path, list[GitignoreRule]]:
        cached = self._cache.get(dir_parts)
        if cached is not None:
            return cached
        path = self._root.joinpath(*dir_parts, ".gitignore")
        rules: list[GitignoreRule] = []
        try:
            st = os.lstat(path)
        except OSError:
            self._cache[dir_parts] = (path, rules)
            return path, rules
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            # git (2.32+) does not follow a symlinked .gitignore.
            self._cache[dir_parts] = (path, rules)
            return path, rules
        if self._files_read >= GITIGNORE_MAX_FILES:
            if not self._budget_noted:
                self._budget_noted = True
                self._note(
                    f"gitignore: stopped after {GITIGNORE_MAX_FILES} .gitignore"
                    " files; later ones were not read"
                )
            self._cache[dir_parts] = (path, rules)
            return path, rules
        self._files_read += 1
        try:
            with path.open("rb") as fh:
                data = fh.read(GITIGNORE_MAX_BYTES + 1)
        except OSError as exc:
            self._note(f"gitignore: cannot read {path}: {exc}")
            self._cache[dir_parts] = (path, rules)
            return path, rules
        if len(data) > GITIGNORE_MAX_BYTES:
            self._note(
                f"gitignore: {path} is over {GITIGNORE_MAX_BYTES} bytes;"
                " only the first part was read"
            )
            data = data[:GITIGNORE_MAX_BYTES]
        rules, skipped = parse_gitignore(data.decode("utf-8", errors="replace"))
        if skipped:
            self._note(f"gitignore: {skipped} pattern(s) in {path} skipped (too long)")
        self._cache[dir_parts] = (path, rules)
        return path, rules

    def _decide(self, parts: tuple[str, ...], is_dir: bool) -> str | None:
        """Return a description of the excluding rule for *parts*, or None.

        Deeper ``.gitignore`` files win over shallower ones, later lines over
        earlier ones; a matching negated rule means "not ignored".
        """
        for depth in range(len(parts) - 1, -1, -1):
            gi_path, rules = self._rules_for(parts[:depth])
            rel = parts[depth:]
            for rule in reversed(rules):
                if _rule_matches(rule, rel, is_dir):
                    if rule.negate:
                        return None
                    return f"{gi_path}: {rule.text}"
        return None

    def ignored_by(self, target: Path) -> str | None:
        """Return ``"<.gitignore path>: <pattern>"`` when *target* is ignored.

        *target* must be lexically inside the root; ``None`` otherwise, and
        when no rule excludes it or any of its parent directories.
        """
        try:
            rel = target.relative_to(self._root)
        except ValueError:
            return None
        parts = rel.parts
        if not parts:
            return None
        for k in range(1, len(parts) + 1):
            decided = self._decide(parts[:k], is_dir=k < len(parts))
            if decided is not None:
                return decided
        return None
