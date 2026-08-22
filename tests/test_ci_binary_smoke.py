"""CI binary-smoke must cover every release target, via one build recipe.

Release builds four PyInstaller artifacts. A linux-only smoke job lets a
darwin/windows spec or exclude regression ship until the next tag. The
build steps themselves live in ``.github/actions/build-binary/`` so CI
and release cannot drift on interpreter, extras, spec, or PyInstaller.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"
BUILD_ACTION_YML = ROOT / ".github" / "actions" / "build-binary" / "action.yml"
BUILD_ACTION_REF = "./.github/actions/build-binary"
PINNED_PYTHON = "3.12.14"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _rows(job: dict) -> list[tuple[str, str, str, str]]:
    include = job["strategy"]["matrix"]["include"]
    return [(row["os"], row["target"], row["spec"], row["binary"]) for row in include]


def _steps(job: dict) -> list[dict]:
    return job["steps"]


def _build_step(job: dict) -> dict:
    matches = [s for s in _steps(job) if s.get("uses") == BUILD_ACTION_REF]
    assert len(matches) == 1, f"expected one {BUILD_ACTION_REF} step, got {matches}"
    return matches[0]


def test_binary_smoke_matrix_matches_release_targets() -> None:
    ci = _load(CI_YML)
    release = _load(RELEASE_YML)
    assert _rows(ci["jobs"]["binary-smoke"]) == _rows(release["jobs"]["build"])


def test_ci_and_release_call_the_shared_build_action() -> None:
    """Exactly one place answers how the shipped binary is built."""
    ci = _load(CI_YML)
    release = _load(RELEASE_YML)
    for job in (ci["jobs"]["binary-smoke"], release["jobs"]["build"]):
        step = _build_step(job)
        with_ = step["with"]
        assert with_["spec"] == "${{ matrix.spec }}"
        assert with_["binary"] == "${{ matrix.binary }}"
        assert with_["target"] == "${{ matrix.target }}"
        assert "python-version" not in with_


def test_binary_jobs_do_not_inline_the_recipe() -> None:
    """A copied uv/pyinstaller step in either workflow is the next drift."""
    ci = _load(CI_YML)
    release = _load(RELEASE_YML)
    for job in (ci["jobs"]["binary-smoke"], release["jobs"]["build"]):
        runs = "\n".join(str(s.get("run", "")) for s in _steps(job))
        uses = "\n".join(str(s.get("uses", "")) for s in _steps(job))
        assert "uv python install" not in runs
        assert "uv sync --all-extras" not in runs
        assert "pyinstaller" not in runs
        assert "inspect_frozen_binary.py" not in runs
        assert "actions/setup-python@" not in uses


def test_shared_action_is_the_binary_recipe() -> None:
    """Interpreter pin, extras, spec, PyInstaller, and libpython check live here."""
    action = _load(BUILD_ACTION_YML)
    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["python-version"]["default"] == PINNED_PYTHON

    uses = "\n".join(str(s.get("uses", "")) for s in action["runs"]["steps"])
    runs = "\n".join(str(s.get("run", "")) for s in action["runs"]["steps"])
    assert "astral-sh/setup-uv@" in uses
    assert "actions/setup-python@" not in uses
    assert "uv python install" in runs
    assert "uv sync --all-extras" in runs
    assert "uv run pyinstaller ${{ inputs.spec }}" in runs
    assert "scripts/inspect_frozen_binary.py" in runs
    assert "scripts/smoke_test.py" in runs
    assert "hostedtoolcache" in runs
    assert "52428800" in runs  # 50 MB hard fail
    assert "41943040" in runs  # 40 MB soft warn
    assert PINNED_PYTHON not in runs  # pin is the input default, not a second copy
