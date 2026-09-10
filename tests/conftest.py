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


@pytest.fixture()
def pro_enabled() -> None:  # type: ignore[return]
    """Historical no-op fixture — all features are available to all users."""
    yield  # type: ignore[misc]


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
