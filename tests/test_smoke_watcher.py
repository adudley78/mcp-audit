"""The smoke-test watcher step must not leak a long-running watch process.

R15's local smoke run was killed after Check 9/10 and attributed to a watcher
hang. Reproduction showed ``step_watcher_round_trip`` returning OK while
``uv run`` / PyInstaller-parent ``Popen.kill()`` left ``mcp-audit watch``
children alive. Those orphans keep watching CWD and can stall later steps.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SMOKE_PATH = ROOT / "scripts" / "smoke_test.py"


def _load_smoke() -> ModuleType:
    spec = importlib.util.spec_from_file_location("mcp_audit_smoke_test", SMOKE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _watch_pids() -> set[int]:
    ps = shutil.which("ps")
    if ps is None:
        return set()
    result = subprocess.run(  # noqa: S603
        [ps, "-ax", "-o", "pid=,command="],
        capture_output=True,
        text=True,
        check=False,
    )
    pids: set[int] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if "mcp-audit watch --path" not in line:
            continue
        pid_s, _, _rest = line.partition(" ")
        if pid_s.isdigit():
            pids.add(int(pid_s))
    return pids


def test_kill_process_tree_reaps_grandchild() -> None:
    """A child-of-child must die with the process group, not only the parent."""
    if shutil.which("pgrep") is None:
        pytest.skip("pgrep not available to assert grandchild pid")
    smoke = _load_smoke()
    proc = smoke._grouped_popen(
        [
            sys.executable,
            "-c",
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "time.sleep(60)\n",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        time.sleep(0.4)
        assert proc.poll() is None, "precondition: parent still running"
        pgrep = shutil.which("pgrep")
        assert pgrep is not None
        kids = subprocess.run(  # noqa: S603
            [pgrep, "-P", str(proc.pid)],
            capture_output=True,
            text=True,
            check=False,
        )
        grand_pids = [int(x) for x in kids.stdout.split() if x.strip().isdigit()]
        assert grand_pids, "precondition: grandchild must exist before kill"

        smoke._kill_process_tree(proc)
        time.sleep(0.3)
        assert proc.poll() is not None
        still_alive = []
        for gp in grand_pids:
            try:
                os.kill(gp, 0)
                still_alive.append(gp)
            except OSError:
                pass
        assert not still_alive, f"grandchild(s) survived killpg: {still_alive}"
    finally:
        smoke._kill_process_tree(proc)


@pytest.mark.skipif(
    os.name == "nt" or shutil.which("ps") is None,
    reason="ps process listing",
)
def test_watcher_round_trip_does_not_leak_watch_process() -> None:
    smoke = _load_smoke()
    before = _watch_pids()
    assert smoke.step_watcher_round_trip(["uv", "run", "mcp-audit"]) is True
    time.sleep(0.5)
    leaked = _watch_pids() - before
    assert not leaked, f"watch process leaked after smoke step: {leaked}"
