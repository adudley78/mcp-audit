"""CI binary-smoke must cover every release target, via one build recipe.

Release builds four PyInstaller artifacts. A linux-only smoke job lets a
darwin/windows spec or exclude regression ship until the next tag. The
build steps themselves live in ``.github/actions/build-binary/`` so CI
and release cannot drift on interpreter, extras, spec, or PyInstaller.
"""

from __future__ import annotations

import re
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
    setup_uv = next(
        s
        for s in action["runs"]["steps"]
        if "astral-sh/setup-uv@" in str(s.get("uses", ""))
    )
    assert setup_uv["with"]["version"] == "latest"
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


def test_setup_uv_sha_is_the_same_everywhere() -> None:
    """A workflow bump that leaves the composite behind re-opens interpreter drift.

    Dependabot now scans ``/.github/actions/*`` too; this test is the
    local lock if a human (or a split Dependabot PR) still desyncs them.
    """
    pattern = re.compile(r"astral-sh/setup-uv@([0-9a-f]{40})")
    found: dict[str, Path] = {}
    for path in (ROOT / ".github").rglob("*.yml"):
        for sha in pattern.findall(path.read_text(encoding="utf-8")):
            found.setdefault(sha, path)
    assert len(found) == 1, f"setup-uv SHA drift: {found}"


def test_setup_uv_stays_unpinned() -> None:
    """uv floats; downstream pins (CPython, lockfile, PYZ) are the assertion.

    ``latest-known`` was tried 2026-08-22 and resolved uv 0.12.4, which
    cannot fetch CPython 3.12.14. A hand-pinned ``0.12.5`` is also wrong:
    Dependabot does not bump action input strings.
    """
    for path in (ROOT / ".github").rglob("*.yml"):
        text = path.read_text(encoding="utf-8")
        if "astral-sh/setup-uv@" not in text:
            continue
        assert 'version: "latest"' in text, path
        assert 'version: "latest-known"' not in text, path
        assert not re.search(
            r'astral-sh/setup-uv@[0-9a-f]{40}[^\n]*\n(?:[^\n]*\n){0,12}\s+version:\s*"\d+',
            text,
        ), path


def test_dependabot_scans_every_composite() -> None:
    """``directory: "/"`` only covers workflows. Composites must be listed."""
    cfg = _load(ROOT / ".github" / "dependabot.yml")
    actions_update = next(
        u for u in cfg["updates"] if u["package-ecosystem"] == "github-actions"
    )
    directories = set(actions_update["directories"])
    assert "/" in directories
    assert "/.github/actions/*" in directories
    assert "/setup-action" in directories
    assert "directory" not in actions_update
    assert actions_update["open-pull-requests-limit"] == 5
    group = actions_update["groups"]["github-actions"]
    assert group["patterns"] == ["*"]
    assert group["group-by"] == "dependency-name"

    # Every third-party-action composite is a scanned directory.
    scanned_roots = {ROOT / ".github" / "actions", ROOT / "setup-action"}
    for action_yml in ROOT.rglob("action.yml"):
        if "examples" in action_yml.parts or action_yml == ROOT / "action.yml":
            continue
        parent = action_yml.parent
        if parent.parent == ROOT / ".github" / "actions":
            continue  # covered by the glob
        assert parent in scanned_roots or parent.parent in scanned_roots, parent
