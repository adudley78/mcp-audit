"""Tests for scripts/dev_build_guard.py — the shared stale-build guard.

R45: unifies two previously independent implementations of "am I running
against a stale, separately-installed mcp-audit instead of this checkout's
dev source" — see the module's own docstring for the full history
(``scripts/audit_registry.py``'s R39 check, and
``docs/manual-test-matrix.md``'s R43 Setup Guard). This file tests the shared
module directly; ``tests/test_audit_registry.py::TestAssertMcpAuditIsRepoLocal``
separately confirms ``audit_registry.py`` still gets the identical behaviour
through its import of this module.
"""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path

import pytest

from tests.conftest import unwrapped

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import dev_build_guard as mod  # noqa: E402


class TestAssertMcpAuditIsRepoLocal:
    """assert_mcp_audit_is_repo_local(): fail loudly on a non-dev-tree import."""

    def test_passes_for_the_real_dev_install(self) -> None:
        # Under `uv run pytest`, mcp_audit resolves to this repo's src tree —
        # must not raise/exit.
        mod.assert_mcp_audit_is_repo_local()

    def test_default_repo_root_is_this_repo(self) -> None:
        """The default repo_root is derived from this file's own location,
        not hardcoded, so the module works correctly if the repo is cloned
        anywhere."""
        assert Path(__file__).resolve().parent.parent == mod.REPO_ROOT

    def test_exits_loudly_for_a_foreign_install(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        foreign = tmp_path / "somewhere-else" / "site-packages" / "mcp_audit"
        foreign.mkdir(parents=True)
        foreign_init = foreign / "__init__.py"
        foreign_init.write_text("", encoding="utf-8")

        fake = types.ModuleType("mcp_audit")
        fake.__file__ = str(foreign_init)
        monkeypatch.setitem(sys.modules, "mcp_audit", fake)

        with pytest.raises(SystemExit) as exc_info:
            mod.assert_mcp_audit_is_repo_local()

        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "FATAL" in err
        assert "uv run" in err
        # Path formatting is platform-native (backslashes on Windows) —
        # compare against str(Path(...).resolve()), not a hardcoded POSIX
        # string.
        assert str(foreign_init.resolve()) in err

    def test_explicit_repo_root_overrides_default(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A caller outside this repo's own scripts/ can pass its own root."""
        # Build a fake "repo" whose src/mcp_audit contains the currently
        # imported mcp_audit's own file, so passing that root explicitly
        # must NOT raise even though it differs from mod.REPO_ROOT.
        import mcp_audit  # noqa: PLC0415

        real_file = Path(mcp_audit.__file__).resolve()
        fake_repo_root = real_file.parent.parent.parent
        mod.assert_mcp_audit_is_repo_local(fake_repo_root)


class TestMain:
    """The CLI entry point used by docs/manual-test-matrix.md's Setup Guard."""

    def test_main_prints_ok_and_exits_zero_for_dev_install(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        mod.main()
        out = capsys.readouterr().out
        assert out.startswith("OK: mcp_audit resolved to")
        assert "this repo's dev source" in out

    def test_running_as_subprocess_exits_zero(self) -> None:
        """End-to-end: `python3 scripts/dev_build_guard.py` from the repo,
        exactly how docs/manual-test-matrix.md's Setup Guard invokes it."""
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(ROOT / "scripts" / "dev_build_guard.py")],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "OK: mcp_audit resolved to" in unwrapped(result.stdout)
