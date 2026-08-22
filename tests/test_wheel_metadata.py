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
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"
BUILD_ACTION_YML = ROOT / ".github" / "actions" / "build-binary" / "action.yml"
PYPROJECT = ROOT / "pyproject.toml"
TWINE = "twine==7.0.0"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_hatchling_stays_unpinned() -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    assert 'requires = ["hatchling"]' in text
    assert "hatchling==" not in text.split("[project]")[0]


def test_wheel_check_lives_in_ci_not_the_binary_composite() -> None:
    ci = _load(CI_YML)
    job = ci["jobs"]["wheel-check"]
    runs = "\n".join(str(s.get("run", "")) for s in job["steps"])
    pin = _load(BUILD_ACTION_YML)["inputs"]["python-version"]["default"]
    assert f"uv python install {pin}" in runs
    assert "uv build --wheel" in runs
    assert f"uvx {TWINE} check --strict dist/*.whl" in runs

    # Header comments may mention twine; the recipe must not run it.
    composite_runs = "\n".join(
        str(s.get("run", "")) for s in _load(BUILD_ACTION_YML)["runs"]["steps"]
    )
    assert "twine" not in composite_runs
    assert "uv build" not in composite_runs


def test_publish_action_sha_is_unchanged() -> None:
    """Do not silently move the publisher; the Twine 7 pin tracks this SHA."""
    text = RELEASE_YML.read_text(encoding="utf-8")
    assert (
        "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33" in text
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
        [uvx, TWINE, "check", "--strict", str(whl)],
        check=False,
        capture_output=True,
        text=True,
    )
    combined = re.sub(r"\s+", " ", (proc.stdout + proc.stderr).lower())
    assert proc.returncode != 0
    assert "not a valid metadata version" in combined
