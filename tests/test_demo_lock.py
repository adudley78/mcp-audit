"""Runs ``demo/lock/run.sh`` as an integration test of the `lock` workflow.

Gated on ``MCP_AUDIT_DEMO_NETWORK=1`` — the script's first step (``mcp-audit
lock``) resolves each server's package version against the npm registry, so
running it unconditionally on every ``pytest`` invocation would make the full
suite network-dependent. CI sets the variable on the ubuntu/py3.12 leg only
(see ``.github/workflows/ci.yml``); everywhere else this test skips cleanly
with a reason naming exactly why.

This is the same script a developer runs directly (``bash demo/lock/run.sh``)
to reproduce the exact output shown in README.md's first screen — the test
just asserts on it instead of eyeballing it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUN_SH = ROOT / "demo" / "lock" / "run.sh"

needs_demo_network = pytest.mark.skipif(
    os.environ.get("MCP_AUDIT_DEMO_NETWORK") != "1",
    reason=(
        "requires MCP_AUDIT_DEMO_NETWORK=1 — this test resolves real npm "
        "package versions over the network via `mcp-audit lock`; set the "
        "env var to opt in (CI sets it on the ubuntu/py3.12 leg only)"
    ),
)


@needs_demo_network
class TestDemoLockRunScript:
    def test_run_sh_exits_zero_with_exactly_one_lock_001(self) -> None:
        """The full lock -> drift -> verify -> accept -> verify sequence passes.

        Mirrors the acceptance criteria in STORY-0072: exit 0 overall, and
        exactly one ``LOCK-001`` in the captured output (from the deliberate
        one-line drift the script introduces at step b).
        """
        assert RUN_SH.exists(), f"missing fixture script: {RUN_SH}"
        bash = shutil.which("bash")
        assert bash is not None, "bash not found on PATH"

        result = subprocess.run(  # noqa: S603
            [bash, str(RUN_SH)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        combined = result.stdout + result.stderr
        assert result.returncode == 0, (
            f"demo/lock/run.sh exited {result.returncode}; output:\n{combined}"
        )
        assert combined.count("LOCK-001") == 1, (
            f"expected exactly one LOCK-001 in output, found "
            f"{combined.count('LOCK-001')}:\n{combined}"
        )
        assert "LOCK-002" not in combined
        assert "LOCK-005" not in combined
        assert "demo/lock: PASS" in combined

    def test_fixture_is_restored_after_run(self) -> None:
        """The script's cleanup trap must leave no generated files behind.

        Runs after the sequence above (pytest runs methods in definition
        order within a class) and checks the working tree, not just the
        script's own exit code — a bug in the trap could still exit 0.
        """
        lock_file = ROOT / "demo" / "lock" / "mcp-lock.json"
        config_file = ROOT / "demo" / "lock" / ".cursor" / "mcp.json"

        assert not lock_file.exists(), (
            "demo/lock/run.sh left mcp-lock.json behind after exit"
        )
        assert "@1.0.0" not in config_file.read_text(encoding="utf-8"), (
            "demo/lock/run.sh did not restore the fixture's original config"
        )


@pytest.mark.skipif(
    sys.platform == "win32", reason="run.sh is bash; not exercised on Windows"
)
def test_run_sh_is_executable() -> None:
    """The script carries the executable bit so `bash demo/lock/run.sh` needs
    no extra `chmod` step, matching `demo/run_demo.sh`'s convention."""
    assert RUN_SH.exists(), f"missing fixture script: {RUN_SH}"
    assert os.access(RUN_SH, os.X_OK), f"{RUN_SH} is not executable"
