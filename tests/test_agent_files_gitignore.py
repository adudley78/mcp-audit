"""Tests for agent_files/gitignore.py: .gitignore read by file, never by git."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from mcp_audit.agent_files import gitignore as gi
from mcp_audit.agent_files.gitignore import (
    GitignoreIndex,
    _tokenize,
    parse_gitignore,
    wildmatch,
)


def _match(pattern: str, path: str) -> bool:
    tokens = _tokenize(pattern)
    assert tokens is not None
    return wildmatch(tokens, path)


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("*.md", "a.md", True),
        ("*.md", "a/b.md", False),  # * never crosses /
        ("a?c", "abc", True),
        ("a?c", "a/c", False),
        ("[a-c]x", "bx", True),
        ("[!a-c]x", "bx", False),
        ("[^a-c]x", "dx", True),
        ("[]]x", "]x", True),  # ] first in a class is literal
        ("[ab", "[ab", True),  # unclosed bracket is literal
        ("**/foo", "foo", True),
        ("**/foo", "a/b/foo", True),
        ("a/**/b", "a/b", True),
        ("a/**/b", "a/x/y/b", True),
        ("a/**", "a/x/y", True),
        ("a/**", "a", False),
        ("a**b", "axxb", True),  # not bounded by / -> plain *
        ("a**b", "ax/xb", False),
        ("**", "a/b/c", True),
        ("\\*x", "*x", True),
        ("\\*x", "ax", False),
        ("a*b*c", "axxbyyc", True),
    ],
)
def test_wildmatch_semantics(pattern: str, path: str, expected: bool) -> None:
    assert _match(pattern, path) is expected


def test_trailing_lone_backslash_pattern_never_matches() -> None:
    assert _tokenize("foo\\") is None


def test_parse_skips_comments_and_blank_lines_and_trims_spaces() -> None:
    rules, skipped = parse_gitignore("# comment\n\n*.log   \n!keep.log\n")
    assert skipped == 0
    assert [r.text for r in rules] == ["*.log", "!keep.log"]
    assert rules[0].basename_only and not rules[0].negate
    assert rules[1].negate


def test_parse_escapes_and_crlf() -> None:
    rules, _ = parse_gitignore("\\#hash\r\n\\!bang\r\nkeep\\ \r\n")
    assert _match_rule(rules[0], "#hash")
    assert _match_rule(rules[1], "!bang")
    # An escaped trailing space is kept.
    assert _match_rule(rules[2], "keep ")
    assert not _match_rule(rules[2], "keep")


def _match_rule(rule: gi.GitignoreRule, name: str) -> bool:
    return wildmatch(rule.tokens, name.lower())


def test_parse_dir_only_and_anchoring() -> None:
    rules, _ = parse_gitignore("build/\n/dist\ndocs/private\n")
    build, dist, private = rules
    assert build.dir_only and build.basename_only
    assert not dist.basename_only and not dist.dir_only
    assert not private.basename_only


def test_overlong_pattern_is_skipped_and_counted() -> None:
    long_pattern = "a" * (gi.GITIGNORE_MAX_TOKENS + 5)
    rules, skipped = parse_gitignore(f"{long_pattern}\nok\n")
    assert skipped == 1
    assert [r.text for r in rules] == ["ok"]


def _repo(tmp_path: Path, gitignore: str) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text(gitignore, encoding="utf-8")
    return root


def test_index_basename_pattern_matches_at_any_level(tmp_path: Path) -> None:
    root = _repo(tmp_path, "*.local.md\n")
    index = GitignoreIndex(root)
    hit = index.ignored_by(root / "a" / "b" / "notes.local.md")
    assert hit is not None and hit.endswith(": *.local.md")
    assert index.ignored_by(root / "a" / "notes.md") is None


def test_index_directory_exclusion_cannot_be_reincluded(tmp_path: Path) -> None:
    root = _repo(tmp_path, ".notes/\n!.notes/keep.md\n")
    index = GitignoreIndex(root)
    # git: "It is not possible to re-include a file if a parent directory of
    # that file is excluded."
    assert index.ignored_by(root / ".notes" / "keep.md") is not None


def test_index_negation_reincludes_file(tmp_path: Path) -> None:
    root = _repo(tmp_path, "*.md\n!keep.md\n")
    index = GitignoreIndex(root)
    assert index.ignored_by(root / "keep.md") is None
    assert index.ignored_by(root / "other.md") is not None


def test_index_anchored_pattern_only_at_its_level(tmp_path: Path) -> None:
    root = _repo(tmp_path, "/private.md\n")
    index = GitignoreIndex(root)
    assert index.ignored_by(root / "private.md") is not None
    assert index.ignored_by(root / "sub" / "private.md") is None


def test_index_deeper_gitignore_overrides(tmp_path: Path) -> None:
    root = _repo(tmp_path, "*.md\n")
    (root / "docs").mkdir()
    (root / "docs" / ".gitignore").write_text("!guide.md\n", encoding="utf-8")
    index = GitignoreIndex(root)
    assert index.ignored_by(root / "docs" / "guide.md") is None
    assert index.ignored_by(root / "docs" / "other.md") is not None


def test_index_dir_only_pattern_does_not_match_a_file(tmp_path: Path) -> None:
    root = _repo(tmp_path, "notes/\n")
    index = GitignoreIndex(root)
    assert index.ignored_by(root / "notes") is None  # the file "notes"
    assert index.ignored_by(root / "notes" / "x.md") is not None


def test_index_is_case_insensitive(tmp_path: Path) -> None:
    root = _repo(tmp_path, "Private/\n")
    index = GitignoreIndex(root)
    assert index.ignored_by(root / "private" / "x.md") is not None


def test_index_outside_root_is_never_ignored(tmp_path: Path) -> None:
    root = _repo(tmp_path, "*\n")
    assert GitignoreIndex(root).ignored_by(tmp_path / "elsewhere.md") is None


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_symlinked_gitignore_is_not_read(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    real = tmp_path / "real-ignore"
    real.write_text("*.md\n", encoding="utf-8")
    os.symlink(real, root / ".gitignore")
    # git 2.32+ does not follow a symlinked .gitignore.
    assert GitignoreIndex(root).ignored_by(root / "x.md") is None


def test_oversized_gitignore_is_read_partially_and_noted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gi, "GITIGNORE_MAX_BYTES", 16)
    root = _repo(tmp_path, "secret.md\n" + "#" * 64 + "\nlater.md\n")
    notes: list[str] = []
    index = GitignoreIndex(root, notes)
    assert index.ignored_by(root / "secret.md") is not None
    assert index.ignored_by(root / "later.md") is None
    assert any("only the first part" in n for n in notes)


def test_unreadable_gitignore_is_noted_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo(tmp_path, "*.md\n")
    real_open = Path.open

    def _deny(self: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if self.name == ".gitignore":
            raise PermissionError("denied")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", _deny)
    notes: list[str] = []
    assert GitignoreIndex(root, notes).ignored_by(root / "x.md") is None
    assert any("cannot read" in n for n in notes)


def test_file_budget_is_noted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gi, "GITIGNORE_MAX_FILES", 1)
    root = _repo(tmp_path, "nothing-here\n")
    (root / "a").mkdir()
    (root / "a" / ".gitignore").write_text("*.md\n", encoding="utf-8")
    notes: list[str] = []
    index = GitignoreIndex(root, notes)
    assert index.ignored_by(root / "a" / "x.md") is None
    assert any("stopped after" in n for n in notes)


def test_pathological_pattern_is_linear() -> None:
    """Many stars against a long near-miss path: DP, not backtracking."""
    pattern = "*a" * 200 + "b"
    tokens = _tokenize(pattern)
    assert tokens is not None
    path = "a" * 4000
    start = time.monotonic()
    assert wildmatch(tokens, path) is False
    assert time.monotonic() - start < 5.0
