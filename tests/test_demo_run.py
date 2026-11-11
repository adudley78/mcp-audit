"""demo/run/run.sh reproduces EPIC-0009's Phase 1 exit (refused + withheld)."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "demo" / "run" / "run.sh"
SCRIPTS_DIR = Path(sysconfig.get_path("scripts"))

pytestmark = [
    pytest.mark.skipif(sys.platform == "win32", reason="bash demo script"),
    pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash"),
    pytest.mark.skipif(
        importlib.util.find_spec("mcp") is None,
        reason="lock --connect needs the mcp extra",
    ),
    pytest.mark.skipif(
        not (SCRIPTS_DIR / "mcp-audit").exists(),
        reason="mcp-audit console script not installed next to this Python",
    ),
]


def test_demo_runs_and_every_case_holds() -> None:
    env = {**os.environ, "PATH": f"{SCRIPTS_DIR}{os.pathsep}{os.environ['PATH']}"}
    # python3 on PATH must be one that can run the demo's stdlib scripts.
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env['PATH']}"
    result = subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT)],  # noqa: S607
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "add(2, 3) -> 5" in out
    assert "id_rsa" in out  # the unwrapped launch shows the injection
    assert "withheld: LOCK-008" in out
    assert "refused: LOCK-001" in out
    assert "all three cases behaved as expected" in out


def test_demo_leaves_the_repository_unchanged() -> None:
    assert not (SCRIPT.parent / "description.txt").exists()
    assert not (SCRIPT.parent / ".mcp.json").exists()
    assert not (SCRIPT.parent / "mcp-lock.json").exists()
