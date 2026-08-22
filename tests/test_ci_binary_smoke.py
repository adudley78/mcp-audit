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
COMPOSITE_INPUTS = {"spec", "binary", "target"}


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _on(workflow: dict) -> dict:
    """GitHub's ``on:`` key is YAML 1.1 boolean ``True`` under PyYAML."""
    value = workflow.get("on", workflow.get(True))
    assert isinstance(value, dict), "workflow is missing an `on:` block"
    return value


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
    """Every value a caller can get wrong: runner, target, spec, binary, `with:`."""
    ci = _load(CI_YML)
    release = _load(RELEASE_YML)
    ci_job = ci["jobs"]["binary-smoke"]
    rel_job = release["jobs"]["build"]
    assert _rows(ci_job) == _rows(rel_job)
    ci_with = _build_step(ci_job)["with"]
    rel_with = _build_step(rel_job)["with"]
    assert ci_with == rel_with
    assert set(ci_with) == COMPOSITE_INPUTS
    assert ci_with["spec"] == "${{ matrix.spec }}"
    assert ci_with["binary"] == "${{ matrix.binary }}"
    assert ci_with["target"] == "${{ matrix.target }}"
    assert "python-version" not in ci_with


def test_ci_and_release_call_the_shared_build_action() -> None:
    """Exactly one place answers how the shipped binary is built."""
    ci = _load(CI_YML)
    release = _load(RELEASE_YML)
    for job in (ci["jobs"]["binary-smoke"], release["jobs"]["build"]):
        step = _build_step(job)
        assert step["uses"] == BUILD_ACTION_REF


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


def test_publish_pypi_installs_the_composite_python_pin() -> None:
    """Wheel job copies the composite default; it cannot invoke PyInstaller."""
    pin = _load(BUILD_ACTION_YML)["inputs"]["python-version"]["default"]
    release = _load(RELEASE_YML)
    setup = next(
        s
        for s in _steps(release["jobs"]["publish-pypi"])
        if s.get("name") == "Set up Python"
    )
    assert setup["run"].strip() == f"uv python install {pin}"


def test_release_upload_consumes_composite_output() -> None:
    """The tag-push upload path must match what the composite writes."""
    upload = next(
        s
        for s in _steps(_load(RELEASE_YML)["jobs"]["build"])
        if s.get("name") == "Upload artifact"
    )
    assert upload["with"]["name"] == "${{ matrix.target }}"
    assert upload["with"]["path"] == "dist/${{ matrix.binary }}"
    assert upload["with"]["if-no-files-found"] == "error"


def test_release_dispatch_is_a_dry_run() -> None:
    """workflow_dispatch must build but never publish.

    The first tag push must not be the first release-side execution.
    """
    release = _load(RELEASE_YML)
    on = _on(release)
    assert "workflow_dispatch" in on
    assert "push" in on
    for name in ("release", "publish-pypi", "tag-major"):
        condition = release["jobs"][name].get("if", "")
        assert "github.event_name == 'push'" in condition, name
    assert "if" not in release["jobs"]["build"]


def test_no_local_linux_binary_script() -> None:
    """A second recipe is how 37.5-vs-47.5 happened. The composite is the recipe."""
    assert not (ROOT / "scripts" / "build-linux.sh").is_file()
    assert not (ROOT / "build.py").is_file()
