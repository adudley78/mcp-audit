"""CI binary-smoke must cover every release target.

Release builds four PyInstaller artifacts. A linux-only smoke job lets a
darwin/windows spec or exclude regression ship until the next tag.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _rows(job: dict) -> list[tuple[str, str, str, str]]:
    include = job["strategy"]["matrix"]["include"]
    return [(row["os"], row["target"], row["spec"], row["binary"]) for row in include]


def test_binary_smoke_matrix_matches_release_targets() -> None:
    ci = _load(CI_YML)
    release = _load(RELEASE_YML)
    assert _rows(ci["jobs"]["binary-smoke"]) == _rows(release["jobs"]["build"])


def test_binary_smoke_uses_release_install_and_inspects_archive() -> None:
    text = CI_YML.read_text(encoding="utf-8")
    assert "uv sync --all-extras" in text
    assert "scripts/inspect_frozen_binary.py" in text
    assert "uv run pyinstaller ${{ matrix.spec }}" in text
