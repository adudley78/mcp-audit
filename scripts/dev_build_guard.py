#!/usr/bin/env python3
"""Shared guard: is the code actually under test THIS repo's dev source?

R45: two independent implementations of "am I accidentally running against a
stale, separately-installed mcp-audit instead of this checkout's dev build"
already existed, written a day apart by two different tasks that never knew
about each other:

1. ``_assert_mcp_audit_is_repo_local()`` (R39, formerly private to
   ``scripts/audit_registry.py``) — a Python-import-resolution check: does
   ``import mcp_audit`` resolve inside ``<repo>/src/mcp_audit``? R39 needed
   this after a bare ``python3`` (instead of ``uv run python3``) silently
   resolved a stale, separately pip-installed ``mcp_audit`` that predated the
   ``CLOUD`` capability, undercounting a live measurement by one.
2. ``docs/manual-test-matrix.md``'s "Setup guard" (R43) — a shell-level
   ``$PATH`` check: does the bare ``mcp-audit`` command on ``$PATH`` report
   the same version as ``pyproject.toml``? R43 needed this after a stale
   globally pip-installed ``mcp-audit 0.14.1`` shadowed the dev build on
   ``$PATH`` and made ``feed``/``advise`` (added after 0.14.1) report
   "No such command" — not a version mismatch, a missing feature.

Same failure mode (a stale build silently answering for this checkout),
two files, two mechanisms. This module is the single shared home so a third
instance doesn't grow up somewhere neither of the first two covers:

* :func:`assert_mcp_audit_is_repo_local` is the one Python-level check —
  ``scripts/audit_registry.py`` now imports and calls this directly instead
  of keeping a private copy (behaviour is unchanged: same message shape,
  same ``sys.exit(2)``).
* Running this file directly (``python3 scripts/dev_build_guard.py``, after
  a caller has already put the intended ``.venv/bin`` first on ``$PATH``)
  gives ``docs/manual-test-matrix.md``'s Setup Guard a strictly more
  reliable replacement for its own former version-string comparison: two
  installs can coincidentally report the same version string, but they
  cannot coincidentally resolve to the same file path. The matrix still
  owns the ``$PATH``-prepending *fix* (this module only detects; it does
  not, and should not, mutate the caller's environment) — see the Setup
  Guard section itself for that half.

This module is deliberately NOT wired into ``mcp_audit`` package code or the
CLI itself: an end user running a normally-installed ``mcp-audit`` is not an
error, and a guard that fires on ordinary use is worse than no guard at all.
It lives in ``scripts/`` — the repo's own dev-tooling area, excluded from the
package build and from ``ruff``'s ``src/ tests/`` lint scope — alongside the
other contributor-only scripts that already cross-import each other this way
(see ``generate_release_sbom.py``'s ``sys.path.insert`` of this same
directory).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def assert_mcp_audit_is_repo_local(repo_root: Path = REPO_ROOT) -> None:
    """Fail loudly if the importable ``mcp_audit`` is not *repo_root*'s dev source.

    Any contributor script that imports ``mcp_audit`` modules to reuse real
    detection logic (enum values, constants, functions) instead of forking a
    copy that could drift only makes sense if the imported code IS the
    intended repo's code. A stale, separately-installed ``mcp_audit`` (e.g.
    an older ``pip install mcp-audit-scanner`` on the same machine, resolved
    because a bare ``python3``/``pytest`` was used instead of ``uv run``) has
    no legitimate reading here: it would silently measure or test against a
    different, possibly older, version of the detection logic. A measurement
    or test that can silently run against the wrong build produces confident
    wrong results, which is worse than producing none.

    Args:
        repo_root: The repository root whose ``src/mcp_audit`` the imported
            ``mcp_audit`` package must resolve inside. Defaults to this
            file's own repo (``scripts/dev_build_guard.py``'s parent's
            parent) — callers outside this repo's own ``scripts/`` directory
            should pass their own root explicitly.

    Raises:
        SystemExit: With code 2 and the actually-resolved path, if
            ``mcp_audit.__file__`` does not resolve inside
            ``<repo_root>/src/mcp_audit``.
    """
    import mcp_audit  # noqa: PLC0415

    resolved = Path(mcp_audit.__file__).resolve()
    expected_root = (repo_root / "src" / "mcp_audit").resolve()
    try:
        resolved.relative_to(expected_root)
    except ValueError:
        print(
            f"FATAL: 'mcp_audit' resolved to {resolved!s}, not this repo's dev "
            f"source tree at {expected_root!s}. A script or test that imports "
            "mcp_audit modules requires them to be THIS repo's code — run via "
            "`uv run python3 ...` (or `uv run pytest`), not a bare `python3`/"
            "`pytest` that may resolve a stale, separately installed copy. "
            "Refusing to run rather than silently measuring the wrong build.",
            file=sys.stderr,
        )
        sys.exit(2)


def main() -> None:
    """CLI entry point: run the check and print a one-line confirmation.

    Used directly (not imported) by ``docs/manual-test-matrix.md``'s Setup
    Guard, after it has already prepended this checkout's ``.venv/bin`` to
    ``$PATH`` — at that point a bare ``python3`` resolves the same venv the
    bare ``mcp-audit`` console script does, so this check and the matrix's
    subsequent bare ``mcp-audit ...`` invocations are verifying the same
    resolution.
    """
    assert_mcp_audit_is_repo_local()
    import mcp_audit  # noqa: PLC0415

    print(f"OK: mcp_audit resolved to {mcp_audit.__file__} (this repo's dev source)")


if __name__ == "__main__":
    main()
