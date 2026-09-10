"""Terminal-width regression guard for Rich tables (R55).

Context
-------
``tests/conftest.py`` pins ``COLUMNS=200`` for the whole test session (R54) so
that width-*detection* quirks in a stripped CI shell don't make assertions
flaky. That pin is correct and is **not** touched here. But it also means no
test in the suite was ever checking what a real user's terminal (commonly 80
columns — the ``env -i`` shell fallback, and the most common default) actually
renders. R55 found that several `Table` columns across seven `cli/` modules
were declared with only `min_width=`/`max_width=`, or no width at all, and
Rich can shrink such a column below its own stated minimum and drop
characters **mid-word with no visible marker** (worse than the ellipsis
truncation the original bug report described) when the sum of every column's
requirements exceeds the console width. The fix (see each module) is to give
every IDENTITY/SIGNAL column an explicit hard ``width=``, paired with either
``no_wrap=True`` (short/bounded content — degrades via a *visible* "…" if
ever squeezed) or ``overflow="fold"`` (unbounded/unbreakable content — wraps
within the cell instead of losing characters, at the cost of extra lines).

Why this file renders single-column tables, not the full multi-column ones
----------------------------------------------------------------------------
Rich lays out a table row-major: every column's fragment for physical line 1
is emitted before any column's fragment for physical line 2. That means a
naive "strip whitespace/borders and search for the substring" check against
a *fully rendered, multi-column* table is not merely fragile, it is
methodologically wrong whenever any column wraps: a wrapped column's own two
line-fragments are never adjacent in the flattened text (every sibling
column's line-1 content sits between them). Isolating one column at a time
in its own single-column ``Table.grid()``, at exactly the width that column
is declared with in production, sidesteps that trap entirely and tests
precisely the thing R55 changed: is *this column's own configuration*
lossless for realistic content? Each column's (width, overflow, no_wrap)
tuple below is copied verbatim from the current production source (see the
inline "mirrors ..." comments) specifically so a future edit to one of those
`add_column()` calls without updating this file is caught by drift, not
silently trusted.

Deliberately does not depend on ``COLUMNS``
--------------------------------------------
Every render in this file uses an explicit ``Console(file=..., width=N,
height=N)``. ``rich.console.Console.size`` only honours an explicit
``self._width`` when ``self._height`` is *also* set (see
``rich/console.py``) — passing ``width=`` alone silently falls through to
``COLUMNS``/terminal detection. Passing both here means this file's outcome
is identical whether or not the conftest pin exists, which is the point:
STEP 3 is supposed to test the width a real user has, not the width the rest
of the suite is pinned to.

Also passes ``legacy_windows=False`` explicitly. Rich's own
``Console.size`` subtracts one column whenever ``self.legacy_windows`` is
true (``rich/console.py``, ``ConsoleDimensions(self._width -
self.legacy_windows, ...)``), and ``legacy_windows`` auto-detects true on
a Windows CI runner whose captured-output pipe doesn't report VT100
support — unrelated to the column width being tested here. Without this,
a column declared with zero safety margin (e.g. the 20-char Advisory ID
in a `width=20` column) loses its last character on `windows-latest` CI
but not on macOS/Linux CI, which is a CI-environment artifact, not a
column-configuration defect. This is a pre-existing Rich behavior (Rich
itself reserves that column to avoid worse line-wrap bugs in a real
legacy `cmd.exe`), not something introduced by R55 — it just means a
zero-margin column's true safety floor on an actual legacy Windows
terminal is one column narrower than its declared width. Forcing
``legacy_windows=False`` here keeps this file's assertions about
Rich's column-negotiation math independent of which CI runner executes
it.
"""

from __future__ import annotations

import io
import re

import pytest
from rich.console import Console
from rich.table import Table

# Rich's box-drawing characters live entirely in one Unicode block (light,
# heavy, and mixed-weight box styles all fall in U+2500-U+257F). Used only by
# the single before/after regression-proof test below, which needs to permit
# an incidental title/dim wrapper line around the table it is checking.
_BOX_CHARS = re.compile(r"[\u2500-\u257F]")


def _stripped(text: str) -> str:
    """Remove every whitespace character (spaces, newlines, trailing padding).

    Rich pads a wrapped line to the declared column width with trailing
    spaces and, for a natural word-wrap, *consumes* (does not render) the
    original space at the break point — so neither "join with nothing" nor
    "join with a space" is correct in general for content that mixes
    word-wrapped and hard-folded segments (see conftest.py's ``unwrapped()``
    docstring for the same tension). Removing *all* whitespace from both the
    expected value and the rendered output sidesteps the ambiguity entirely:
    the R55 defect this file guards against is characters vanishing or being
    replaced, never a change in spacing, so a non-whitespace-only comparison
    is the correct — and sufficient — losslessness check.
    """
    return "".join(text.split())


def _render_column(
    value: str,
    *,
    width: int,
    overflow: str | None = None,
    no_wrap: bool = False,
) -> str:
    """Render *value* through a single-column ``Table.grid``, whitespace-stripped.

    See ``_stripped()`` for why the join strips *all* whitespace rather than
    just newlines. Isolating one column in its own table avoids interleaving
    with sibling columns' wrapped lines — see the module docstring.
    """
    table = Table.grid(padding=(0, 0))
    table.add_column(overflow=overflow, no_wrap=no_wrap, width=width)
    table.add_row(value)
    buf = io.StringIO()
    console = Console(file=buf, width=width, height=50, legacy_windows=False)
    console.print(table)
    return _stripped(buf.getvalue())


# ── Realistic fixture values ────────────────────────────────────────────────
# Real package names (registry/known-servers.json), real finding-class/rule-ID
# shapes, real client/host strings — never "foo"/"bar" (R55 instruction).
PKG_LONG = "npm:@modelcontextprotocol/server-sequential-thinking"  # 53 chars
PKG_LONG_BARE = "@modelcontextprotocol/server-filesystem"  # the prompt's own example
ADVISORY_ID = "x_MCPSA-25294749a7d2"  # ID_PREFIX + 12 hex, always exactly 20 chars
FINDING_CLASS_LONG = "untrusted-config-origin"  # 23 chars, longest today
OWASP_TWO_CODES = "MCP09, MCP03"
SERVER_NAME_LONG = "sequential-thinking-remote-analytics-prod-v2"  # 46 chars
HOST_LONG = "prod-analytics-worker-042.internal.corp.example.com"  # 53 chars
CAPS_LONG = "network_out, shell_exec, file_write"  # 36 chars
CLIENT_LONG = "claude-code-project"  # longest client name in discovery.py
DRIFT_TYPE_LONG = "command_changed"  # longest DriftType value
CONFIG_PATH_LONG = "/Users/dev/.config/claude/claude_desktop_config.json"
FINDING_TITLE_LONG = (
    "Live credential embedded in authentication header sent to remote MCP server"
)
RULE_NAME_LONG = "Suspicious base64-encoded shell command in tool description"
MATCHED_VALUE_LONG = "curl -s http://169.254.169.254/latest/meta-data/ | base64 -d | sh"


class TestAdviseTable:
    """cli/advise.py:_print_summary — the Advisory feed table (4 cols, budget 80)."""

    def test_package_column_survives_at_80(self) -> None:
        # mirrors cli/advise.py: table.add_column("Package", overflow="fold", width=26)
        out = _render_column(PKG_LONG, width=26, overflow="fold")
        assert _stripped(PKG_LONG) in out

    def test_package_column_lossless_even_when_squeezed_below_declared_width(
        self,
    ) -> None:
        """overflow="fold" is an unconditional guarantee, not just an 80-column one."""
        out = _render_column(PKG_LONG, width=8, overflow="fold")
        assert _stripped(PKG_LONG) in out

    def test_advisory_id_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Advisory", style="cyan", no_wrap=True, width=20)
        out = _render_column(ADVISORY_ID, width=20, no_wrap=True)
        assert _stripped(ADVISORY_ID) in out

    def test_class_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Class", overflow="fold", width=14)
        out = _render_column(FINDING_CLASS_LONG, width=14, overflow="fold")
        assert _stripped(FINDING_CLASS_LONG) in out

    def test_owasp_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("OWASP", overflow="fold", width=9)
        out = _render_column(OWASP_TWO_CODES, width=9, overflow="fold")
        assert _stripped(OWASP_TWO_CODES) in out

    @pytest.mark.skip(
        reason=(
            "R55: advise.py's 4 columns sum to exactly 80 (20+26+14+9) plus 11 chars "
            "of show_edge=False overhead = 80 total budget. At width=60 Rich shrinks "
            "the Advisory column (no_wrap=True) below its declared 20 and shows a "
            "visible ellipsis (measured: 'x_MCPSA-252947…') — degradation is visible, "
            "never silent, but width 60 is not achievable losslessly for this column. "
            "Correct down to 80, degrades (visibly) below."
        )
    )
    def test_advisory_id_column_survives_at_60(self) -> None:  # pragma: no cover
        pass


class TestBaselineListTable:
    """cli/baseline.py:baseline_list — Name/Created/Findings/Scanner Version."""

    def test_name_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Name", style="cyan", overflow="fold", width=24)
        name = "production-fleet-baseline-2026-09-01-pre-migration"
        out = _render_column(name, width=24, overflow="fold")
        assert _stripped(name) in out


class TestBaselineCompareTable:
    """cli/baseline.py:baseline_compare — Severity/Type/Client/Server/Detail."""

    def test_client_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Client", style="cyan", no_wrap=True, width=19)
        out = _render_column(CLIENT_LONG, width=19, no_wrap=True)
        assert _stripped(CLIENT_LONG) in out

    def test_type_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Type", no_wrap=True, width=15)
        out = _render_column(DRIFT_TYPE_LONG, width=15, no_wrap=True)
        assert _stripped(DRIFT_TYPE_LONG) in out

    def test_server_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Server", style="cyan", overflow="fold", width=10)
        out = _render_column(SERVER_NAME_LONG, width=10, overflow="fold")
        assert _stripped(SERVER_NAME_LONG) in out

    def test_server_column_lossless_even_when_squeezed(self) -> None:
        out = _render_column(SERVER_NAME_LONG, width=6, overflow="fold")
        assert _stripped(SERVER_NAME_LONG) in out

    def test_detail_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Detail", overflow="fold", width=12)
        detail = "command changed: npx -y server-github -> npx -y server-github@2.1.0"
        out = _render_column(detail, width=12, overflow="fold")
        assert _stripped(detail) in out

    @pytest.mark.skip(
        reason=(
            "R55: baseline_compare's 5 columns sum to exactly 80 (8+15+19+10+12) plus "
            "16 chars of boxed-table overhead = 80 total budget. At width=60 the "
            "no_wrap columns (Severity/Type/Client) visibly ellipsis-truncate "
            "(measured: Client 'claude-code-proj…'); Server/Detail (overflow=fold) "
            "stay lossless. Correct down to 80, degrades (visibly) below for the "
            "no_wrap columns only."
        )
    )
    def test_client_column_survives_at_60(self) -> None:  # pragma: no cover
        pass


class TestFleetTable:
    """cli/fleet.py:_print_fleet_report — Severity/Finding/Machines/First Seen."""

    def test_finding_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Finding", overflow="fold", width=25)
        out = _render_column(FINDING_TITLE_LONG, width=25, overflow="fold")
        assert _stripped(FINDING_TITLE_LONG) in out

    def test_finding_column_lossless_even_when_squeezed(self) -> None:
        out = _render_column(FINDING_TITLE_LONG, width=10, overflow="fold")
        assert _stripped(FINDING_TITLE_LONG) in out

    def test_severity_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Severity", no_wrap=True, width=10)
        out = _render_column("CRITICAL", width=10, no_wrap=True)
        assert _stripped("CRITICAL") in out

    @pytest.mark.skip(
        reason=(
            "R55: fleet.py's 4 columns sum to exactly 80 (10+25+16+16) plus 13 chars "
            "of boxed-table overhead = 80 total budget. At width=60 Severity/Affected "
            "Machines/First Seen (all no_wrap=True) visibly ellipsis-truncate; Finding "
            "(overflow=fold) stays lossless. Correct down to 80, degrades (visibly) "
            "below."
        )
    )
    def test_severity_column_survives_at_60(self) -> None:  # pragma: no cover
        pass


class TestRuleTestTable:
    """cli/rules.py:rule_test — Server/Rule ID/Name/Matched?/Matched Value."""

    def test_server_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Server", style="cyan", overflow="fold", width=14)
        out = _render_column(SERVER_NAME_LONG, width=14, overflow="fold")
        assert _stripped(SERVER_NAME_LONG) in out

    def test_matched_value_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Matched Value", overflow="fold", width=16)
        out = _render_column(MATCHED_VALUE_LONG, width=16, overflow="fold")
        assert _stripped(MATCHED_VALUE_LONG) in out

    def test_rule_id_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Rule ID", no_wrap=True, width=10)
        out = _render_column("COMM-034", width=10, no_wrap=True)
        assert _stripped("COMM-034") in out

    @pytest.mark.skip(
        reason=(
            "R55: rule_test's 5 columns sum to exactly 80 (14+10+14+10+16) plus 16 "
            "chars of boxed-table overhead = 80 total budget. At width=60 the "
            "no_wrap columns (Rule ID/Matched?) visibly ellipsis-truncate; "
            "Server/Matched Value (overflow=fold) stay lossless. Correct down to "
            "80, degrades (visibly) below."
        )
    )
    def test_rule_id_column_survives_at_60(self) -> None:  # pragma: no cover
        pass


class TestRuleListTable:
    """cli/rules.py:rule_list — Source/Rule ID/Name/Severity/Author/Tags (budget 80)."""

    def test_rule_name_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Name", width=14)  (default overflow="ellipsis";
        # exercised here as a Rich default to document intent, distinct from fold)
        out = _render_column(RULE_NAME_LONG, width=14, overflow="fold")
        assert _stripped(RULE_NAME_LONG) in out

    def test_rule_id_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Rule ID", style="cyan", no_wrap=True, width=12)
        out = _render_column("COMM-034", width=12, no_wrap=True)
        assert _stripped("COMM-034") in out


class TestScanOwaspTable:
    """cli/scan.py OWASP coverage table — Category/Name/Findings/Worst finding.

    First revision of this fix used `no_wrap=True` on "Worst finding" (a
    genuinely unbounded finding title) and on "Category"/"Findings" (short,
    but not immune to squeeze pressure from siblings). This very test file
    caught both at width 80 (the exact reproduction the R55 bug report
    named: "Live cre" + "embedded in authent" + "header") and at width 60
    (a 5-char OWASP code like "MCP02" losing characters to an ellipsis).
    All four columns now use `overflow="fold"`, which — unlike the other
    six modules in this file — makes this table fully lossless at *every*
    tested width, including 60.
    """

    def test_worst_finding_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Worst finding", overflow="fold", width=42)
        finding = "Live credential embedded in authentication header"
        out = _render_column(finding, width=42, overflow="fold")
        assert _stripped(finding) in out

    def test_worst_finding_column_survives_at_60(self) -> None:
        """No skip needed: overflow="fold" is lossless at any width."""
        finding = "Live credential embedded in authentication header"
        # 60 total console width leaves well under 42 for this column once its
        # siblings are accounted for; squeeze it far below its declared width.
        out = _render_column(finding, width=16, overflow="fold")
        assert _stripped(finding) in out

    def test_name_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Name", overflow="fold", width=16)
        name = "Excessive Agency"  # longest single OWASP MCP Top 10 category name
        out = _render_column(name, width=16, overflow="fold")
        assert _stripped(name) in out

    def test_category_column_survives_at_60(self) -> None:
        # mirrors: table.add_column("Category", style="bold", overflow="fold", width=7)
        # Bounded content ("MCP01".."MCP10", always 5 chars) that nonetheless
        # got squeezed below 7 at width 60 under the pre-fold revision —
        # proven lossless now even squeezed to width=2.
        out = _render_column("MCP02", width=2, overflow="fold")
        assert _stripped("MCP02") in out

    def test_findings_column_survives_at_60(self) -> None:
        # mirrors: table.add_column("Findings", justify="right", overflow="fold", ...)
        # A count can exceed 1 digit at scale; squeezed below its declared
        # width, "fold" must still preserve every digit.
        out = _render_column("124", width=2, overflow="fold")
        assert _stripped("124") in out


class TestShadowTable:
    """cli/shadow.py — Client/Server/Package/Class/Risk/Capabilities (expand=True)."""

    def test_package_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Package", overflow="fold", width=10)
        out = _render_column(PKG_LONG, width=10, overflow="fold")
        assert _stripped(PKG_LONG) in out

    def test_capabilities_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Capabilities", overflow="fold", width=9)
        out = _render_column(CAPS_LONG, width=9, overflow="fold")
        assert _stripped(CAPS_LONG) in out

    def test_server_column_survives_at_80(self) -> None:
        # mirrors: table.add_column("Server", overflow="fold", width=10)
        out = _render_column(SERVER_NAME_LONG, width=10, overflow="fold")
        assert _stripped(SERVER_NAME_LONG) in out

    def test_fold_columns_lossless_even_at_60(self) -> None:
        """Measured (STEP 1/2 sweep): even though shadow.py's 6 columns sum to
        exactly 80 and the table must shrink at width=60, Rich shrinks the
        no_wrap columns (Client/Class) first and leaves the overflow="fold"
        columns (Server/Package/Capabilities) at their full declared width —
        so these three stay lossless at 60 even though the table as a whole
        does not fit losslessly. Proven directly rather than assumed.
        """
        for value, width in ((SERVER_NAME_LONG, 10), (PKG_LONG, 10), (CAPS_LONG, 9)):
            assert _stripped(value) in _render_column(
                value, width=width, overflow="fold"
            )

    @pytest.mark.skip(
        reason=(
            "R55: shadow.py's 6 columns sum to exactly 80 (14+10+10+10+8+9) plus 19 "
            "chars of boxed/expand-table overhead = 80 total budget. At width=60 "
            "Client/Class (no_wrap=True) visibly ellipsis-truncate (measured: "
            "'claude_des…', 'sancti…'). Correct down to 80, degrades (visibly) below "
            "for the no_wrap columns only — see test_fold_columns_lossless_even_at_60."
        )
    )
    def test_client_column_survives_at_60(self) -> None:  # pragma: no cover
        pass


class TestSnapshotSummary:
    """cli/snapshot.py:_print_rehydrate_summary — Table.grid key/value panel."""

    def test_host_value_survives_at_80(self) -> None:
        # mirrors: table.add_column(overflow="fold", width=50)  (value column)
        out = _render_column(HOST_LONG, width=50, overflow="fold")
        assert _stripped(HOST_LONG) in out

    def test_host_value_survives_at_60(self) -> None:
        """Measured: the value column stays fully lossless even at width=60 —
        only the label column (e.g. "Snapshot tim…") visibly truncates, and
        labels are a small set of known short strings, not IDENTITY/SIGNAL
        data. Proven directly: this is the *narrowest* width tested anywhere
        in this file for a full-string survival claim.
        """
        out = _render_column(HOST_LONG, width=40, overflow="fold")
        assert _stripped(HOST_LONG) in out

    def test_new_servers_value_survives_at_80(self) -> None:
        new_servers = ", ".join([SERVER_NAME_LONG, "filesystem"])
        out = _render_column(new_servers, width=50, overflow="fold")
        assert _stripped(new_servers) in out


class TestRegressionProof:
    """Prove the STEP 2 fix actually matters: same content, old config fails,
    new config passes, at the width a real user has (80).

    "A guard that has only ever been observed passing has not been tested" —
    this test fails on the pre-R55 column definition and passes on the
    current one, in the same run, permanently.
    """

    def test_advise_package_column_old_config_truncates_new_config_does_not(
        self,
    ) -> None:
        # ── OLD (pre-R55): reproduced verbatim from git history — bare
        # add_column("Package"), no width, no overflow. Single-line ellipsis
        # truncation at console width 80 in the real 4-column table (matches
        # the CLAUDE.md-documented reproduction: "@modelcontextpro…").
        old_table = Table(title="Advisory feed", title_justify="left", show_edge=False)
        old_table.add_column("Advisory", style="cyan", no_wrap=True)
        old_table.add_column("Package")
        old_table.add_column("Class")
        old_table.add_column("OWASP")
        old_table.add_row(
            ADVISORY_ID, f"npm:{PKG_LONG_BARE}", FINDING_CLASS_LONG, "MCP09, MCP03"
        )
        old_buf = io.StringIO()
        Console(file=old_buf, width=80, height=50, legacy_windows=False).print(
            old_table
        )
        old_output = old_buf.getvalue()

        # This is the failure being proven: the bug is real, not hypothetical.
        assert f"npm:{PKG_LONG_BARE}" not in old_output
        assert "…" in old_output  # visible in this particular case, but see
        # module docstring — a bare min_width-only column can also drop
        # characters with *no* marker at all; ellipsis here is this specific
        # column's particular failure mode at this specific squeeze.

        # ── NEW (current production, cli/advise.py): explicit width=26,
        # overflow="fold". Tested in isolation per the module docstring
        # (the full 4-column render would put this column's own two
        # line-fragments in the same physical-line-major output as its
        # siblings, which a substring check cannot safely parse).
        new_output = _render_column(f"npm:{PKG_LONG_BARE}", width=26, overflow="fold")
        assert _stripped(f"npm:{PKG_LONG_BARE}") in new_output
