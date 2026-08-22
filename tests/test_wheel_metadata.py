"""Wheel Core-Metadata must stay acceptable to the publish action's Twine.

v0.15.0 failed at the tag because hatchling floated to Metadata-Version 2.5
while the then-pinned action still bundled Twine 6. The invariant is that
check, not a hatchling pin. CI job ``wheel-check`` runs it on every PR;
this module asserts the job exists and that the check actually fails.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"
BUILD_ACTION_YML = ROOT / ".github" / "actions" / "build-binary" / "action.yml"
PYPROJECT = ROOT / "pyproject.toml"

_PUBLISH_SHA = re.compile(r"pypa/gh-action-pypi-publish@([0-9a-f]{40})")
_CI_TWINE = re.compile(r"uvx (twine==\d+\.\d+\.\d+) check --strict")
_RUNTIME_TWINE = re.compile(r"^twine==(\S+)", re.MULTILINE)


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _ci_twine_pin() -> str:
    match = _CI_TWINE.search(CI_YML.read_text(encoding="utf-8"))
    assert match, "ci.yml wheel-check is missing `uvx twine==X.Y.Z check --strict`"
    return match.group(1)


def _publish_action_sha() -> str:
    match = _PUBLISH_SHA.search(RELEASE_YML.read_text(encoding="utf-8"))
    assert match, "release.yml is missing a SHA-pinned gh-action-pypi-publish"
    return match.group(1)


def test_hatchling_stays_unpinned() -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    assert 'requires = ["hatchling"]' in text
    assert "hatchling==" not in text.split("[project]")[0]


def test_wheel_check_lives_in_ci_not_the_binary_composite() -> None:
    ci = _load(CI_YML)
    job = ci["jobs"]["wheel-check"]
    runs = "\n".join(str(s.get("run", "")) for s in job["steps"])
    pin = _load(BUILD_ACTION_YML)["inputs"]["python-version"]["default"]
    twine = _ci_twine_pin()
    assert f"uv python install {pin}" in runs
    assert "uv build --wheel" in runs
    assert f"uvx {twine} check --strict dist/*.whl" in runs

    # Header comments may mention twine; the recipe must not run it.
    composite_runs = "\n".join(
        str(s.get("run", "")) for s in _load(BUILD_ACTION_YML)["runs"]["steps"]
    )
    assert "twine" not in composite_runs
    assert "uv build" not in composite_runs


def test_wheel_check_twine_matches_publish_action_runtime() -> None:
    """Dependabot can bump the action SHA; CI's Twine pin must follow runtime.txt.

    Fetches requirements/runtime.txt at the pinned SHA, not a tag or main.
    Offline fallback: ci.yml must still match the twine== recorded next to
    the uses: line in release.yml.
    """
    sha = _publish_action_sha()
    ci_pin = _ci_twine_pin()
    recorded = re.search(
        rf"{re.escape(sha)}.*twine==(\d+\.\d+\.\d+)",
        RELEASE_YML.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    )
    assert recorded, (
        "record `twine==X.Y.Z` on the gh-action-pypi-publish uses: line "
        "so this assertion works offline"
    )
    assert ci_pin == f"twine=={recorded.group(1)}"

    url = (
        "https://raw.githubusercontent.com/pypa/gh-action-pypi-publish/"
        f"{sha}/requirements/runtime.txt"
    )
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310
            runtime = resp.read().decode("utf-8")
    except OSError as exc:
        pytest.skip(f"could not fetch runtime.txt at {sha}: {exc}")
    match = _RUNTIME_TWINE.search(runtime)
    assert match, f"runtime.txt at {sha} has no twine== pin"
    assert ci_pin == f"twine=={match.group(1)}", (
        f"ci.yml wheel-check pins {ci_pin} but the publish action at {sha} "
        f"bundles twine=={match.group(1)}. Update the uvx pin to match "
        "requirements/runtime.txt."
    )


def test_twine_rejects_unknown_metadata_version(tmp_path: Path) -> None:
    """The assertion must be seen to fail, not only to pass."""
    dist_info = "bad-0.0.0.dist-info"
    whl = tmp_path / "bad-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        zf.writestr(
            f"{dist_info}/METADATA",
            "Metadata-Version: 99.0\nName: bad\nVersion: 0.0.0\nSummary: x\n",
        )
        zf.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
            "Tag: py3-none-any\n",
        )
        zf.writestr("bad/__init__.py", "")

    uvx = shutil.which("uvx")
    assert uvx is not None, "uvx is required to prove twine rejects bad metadata"
    proc = subprocess.run(  # noqa: S603
        [uvx, _ci_twine_pin(), "check", "--strict", str(whl)],
        check=False,
        capture_output=True,
        text=True,
    )
    combined = re.sub(r"\s+", " ", (proc.stdout + proc.stderr).lower())
    assert proc.returncode != 0
    assert "not a valid metadata version" in combined
