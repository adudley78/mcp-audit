"""Shared pytest configuration and fixtures.

Historical note
---------------
mcp-audit was previously sold in Community/Pro/Enterprise tiers.  The
``pro_enabled`` fixture was used to flip the Pro gate on in formatter tests.
Gating has been removed entirely (all features are available to all users);
``pro_enabled`` is retained as a no-op so test classes that already reference
it keep collecting cleanly.
"""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

# ── Deterministic terminal width for the whole test session ────────────────────
#
# R54 (2026-09-10): two prior prompts (R52, R53) each ended with a single test
# failure dismissed as a "pre-existing Rich word-wrap artifact from a long macOS
# tmp path," and neither named the test. Reading the code path instead of
# re-asserting that verdict found the real mechanism is console *width*, not
# path length: under a stripped `env -i` shell (no COLUMNS/TERM), Rich falls
# back to whatever `shutil.get_terminal_size()` reports, which is unrelated to
# the actual terminal a developer or CI runner has. A sweep of the full suite
# across widths 20-79 (`env -i COLUMNS=<n> pytest tests/ -q`) surfaced two
# further mechanisms `unwrapped()` below cannot fix at all, because the
# asserted text is not merely reformatted, it is destroyed or reassembled with
# an extra character:
#   1. Rich Table columns collapse to an ellipsis ("…") at extreme widths,
#      deleting the cell content the test asserts on outright (e.g. baseline,
#      extensions, rules, and OWASP-report tables).
#   2. Rich hard-folds a single unbreakable token (a URL, CVE ID, or long
#      filesystem path) character-by-character when it alone exceeds the
#      available width, inserting a newline with **no** original space at that
#      position — collapsing whitespace to a single space would wrongly
#      *insert* a space that was never there (this is what actually broke
#      `tests/test_scanner.py::TestInvalidJsonPathHandling::
#      test_invalid_json_path_shows_error_message`, the test R52/R53 saw and
#      never named).
#
# Pinning COLUMNS here — once, for the whole session, before `mcp_audit.cli`
# (and every module-level `Console()` singleton in it) is ever imported — is
# the only fix that reaches both of those without touching production console
# behaviour: it does not change what a real user's terminal renders, only what
# width `CliRunner`-invoked commands see during this test run, in exactly the
# same way a CI runner's own terminal width is incidental to the assertions.
# See `unwrapped()` below for the complementary, narrower fix that documents
# *why* a phrase can still be split even at a generous width, and converts the
# assertions that can be.
os.environ["COLUMNS"] = "200"


@pytest.fixture(autouse=True)
def _isolate_claude_plugins(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point plugin discovery at an empty root for every test.

    Plugin MCP servers and PLUGIN-001/002 are part of default discovery
    (STORY-0080), and ``plugins_root()`` falls back to the real
    ``~/.claude/plugins``.  Without this, a contributor with Claude Code
    plugins installed would see extra servers and findings in any test that
    runs a default scan.  Tests that need plugins set the variable themselves.
    """
    monkeypatch.setenv(
        "CLAUDE_CODE_PLUGIN_CACHE_DIR",
        str(tmp_path_factory.getbasetemp() / "no-claude-plugins"),
    )
    # Mods (STORY-0085) also come from ~/.claude/dev-mods, CLAUDE_CODE_PLUGIN_DIRS
    # and the managed settings directory.  Point all three at nothing.
    monkeypatch.setenv(
        "CLAUDE_CONFIG_DIR", str(tmp_path_factory.getbasetemp() / "no-claude-config")
    )
    monkeypatch.delenv("CLAUDE_CODE_PLUGIN_DIRS", raising=False)
    monkeypatch.setattr(
        "mcp_audit.plugins.mods.managed_settings_dir",
        lambda: tmp_path_factory.getbasetemp() / "no-managed-settings",
    )
    # User-level subagent definitions (~/.claude/agents/, STORY-0094) join
    # default discovery with their inline MCP servers.  Same reason as above.
    monkeypatch.setattr(
        "mcp_audit.discovery._agent_definitions_home",
        lambda: tmp_path_factory.getbasetemp() / "no-claude-agents-home",
    )
    # Skill packages (STORY-0095) are read from ~/.claude/skills in every
    # default scan.  Point that at nothing; tests that need skills patch it.
    monkeypatch.setattr(
        "mcp_audit.agent_files.skill_package._skills_home",
        lambda: tmp_path_factory.getbasetemp() / "no-skills-home",
    )
    # A default scan also reads ~/.openclaw/workspace/HEARTBEAT.md (MEM-004,
    # STORY-0098); keep a contributor's own OpenClaw workspace out of it.
    monkeypatch.setattr(
        "mcp_audit.agent_files.reach._user_heartbeat_files", lambda errors: []
    )
    # MCP gateway configs (STORY-0111): ~/.mcptoon, ~/.config/1mcp,
    # ~/.config/mcphub and their environment overrides.  Point at nothing.
    monkeypatch.setattr(
        "mcp_audit.gateways._gateway_home",
        lambda: tmp_path_factory.getbasetemp() / "no-gateways-home",
    )
    monkeypatch.setattr("mcp_audit.gateways._gateway_environ", lambda: {})
    # Codex and Gemini CLI user configs (STORY-0110) join default discovery:
    # keep a contributor's own ~/.codex/config.toml and ~/.gemini/settings.json
    # (and any CODEX_HOME) out of it.  Tests that need them patch these back.
    monkeypatch.setenv(
        "CODEX_HOME", str(tmp_path_factory.getbasetemp() / "no-codex-home")
    )
    monkeypatch.setattr(
        "mcp_audit.discovery.gemini_user_config_path",
        lambda: tmp_path_factory.getbasetemp() / "no-gemini-home" / "settings.json",
    )


@pytest.fixture(autouse=True)
def _isolate_cwd_git_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the test runner's own git checkout out of default-discovery scans.

    A default scan checks the repository git would use from the current
    directory (TRUST-006/TRUST-007, STORY-0089), and tests run from this repo's
    checkout: a contributor's husky ``core.hooksPath``, git-lfs filters or
    pre-commit hooks, or the ``includeIf`` entries actions/checkout writes on
    CI, would add findings to any test that runs a default scan.  Tests that
    exercise the check call ``mcp_audit.analyzers.git_exec`` directly or
    restore the real function (see ``tests/test_git_exec.py``).
    """
    monkeypatch.setattr(
        "mcp_audit.analyzers.git_exec.scan_cwd_repository", lambda *_a, **_k: []
    )


@pytest.fixture()
def pro_enabled() -> None:  # type: ignore[return]
    """Historical no-op fixture — all features are available to all users."""
    yield  # type: ignore[misc]


def split_runner() -> CliRunner:
    """A ``CliRunner`` whose ``result.stdout`` holds stdout only.

    Click 8.1 mixes stderr into ``stdout`` unless ``mix_stderr=False``; Click
    8.2 removed that argument and always keeps the streams apart (``output``
    is the mix, ``stdout``/``stderr`` are separate). Tests that check what a
    pipe consumer reads from stdout use this on either version.
    """
    try:
        return CliRunner(mix_stderr=False)  # type: ignore[call-arg]
    except TypeError:
        return CliRunner()


def unwrapped(text: str) -> str:
    """Collapse runs of whitespace (including newlines) to a single space.

    Rich word-wraps ``console.print()``/``Panel`` output to the console's
    detected width. A CLI error message that reads as one line in a normal
    terminal can be split across several lines under a narrow or undetected
    width (e.g. a stripped ``env -i`` shell with no ``COLUMNS``/``TERM``), so a
    literal multi-word substring assertion against ``result.output`` is
    testing the terminal width, not the message. ``unwrapped()`` reconstructs
    the original spacing so the assertion tests the message text instead.

    This is deliberately a test-only normalisation. Do not "fix" the fragility
    by pinning the production `console = Console()` in `cli/__init__.py` to a
    fixed width — that console renders the full scan report and dashboard
    summary, and forcing a fixed width would truncate real output for every
    user on a wide terminal. Wrapping to the user's actual terminal is correct
    production behaviour; the test assumption that it will never wrap is what
    was wrong. (R54, 2026-09-10.)

    Only fixes *soft* wraps that break a phrase at a space that was already
    there — collapsing "single config \\npath" back to "single config path" is
    lossless because the newline replaced a real space. It does **not** fix a
    *hard* fold of a single unbreakable token (a URL, CVE ID, or long path)
    that exceeds the console width on its own: Rich inserts a newline with no
    original space at that position, so collapsing it to a space would wrongly
    add a character that was never there (e.g. "CVE-2026-278\\n26" must not
    become "CVE-2026-278 26"). Those cases, and Rich Table cell truncation via
    ellipsis (which deletes content rather than reformatting it), are handled
    instead by pinning `COLUMNS` for the whole test session above — see that
    comment for the evidence.
    """
    return " ".join(text.split())
