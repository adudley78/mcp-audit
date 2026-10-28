"""No merge-conflict markers in the repository's text files.

A merge resolved with ``git checkout -m`` writes ``<<<<<<< ours`` /
``>>>>>>> theirs`` instead of ``HEAD`` / the branch name; one slipped into
CLAUDE.md during STORY-0113.  This walks the tree (never runs git) and fails on
any line that starts with a conflict marker.  ``=======`` alone is not checked:
it is a legitimate Markdown/RST heading underline.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SKIP_DIRS = frozenset(
    {".git", ".venv", "venv", "node_modules", "build", "dist", "__pycache__"}
)
_TEXT_SUFFIXES = frozenset(
    {
        ".py", ".md", ".json", ".yml", ".yaml", ".toml", ".txt", ".spec",
        ".sh", ".cfg", ".ini", ".html", ".js", ".ts", ".mdc", ".pub",
    }
)  # fmt: skip
_OPEN = "<" * 7
_CLOSE = ">" * 7


def _text_files() -> list[Path]:
    out: list[Path] = []
    stack = [_ROOT]
    while stack:
        directory = stack.pop()
        for entry in directory.iterdir():
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS and not entry.name.startswith(
                    ".pytest"
                ):
                    stack.append(entry)
            elif entry.suffix in _TEXT_SUFFIXES and entry.stat().st_size < 4_000_000:
                out.append(entry)
    return out


def _is_marker(line: str) -> bool:
    for marker in (_OPEN, _CLOSE):
        if line == marker or line.startswith(marker + " "):
            return True
    return False


def test_no_conflict_markers_in_tree() -> None:
    hits: list[str] = []
    for path in _text_files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(lines, 1):
            if _is_marker(line):
                hits.append(f"{path.relative_to(_ROOT)}:{number}")
    assert hits == [], f"merge-conflict markers left in: {hits[:20]}"


def test_marker_detector_matches_both_spellings() -> None:
    assert _is_marker(_OPEN + " HEAD")
    assert _is_marker(_OPEN + " ours")
    assert _is_marker(_CLOSE + " theirs")
    assert _is_marker(_CLOSE)
    assert not _is_marker("=" * 7)
    assert not _is_marker(_OPEN + "x")
