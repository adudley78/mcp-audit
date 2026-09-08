"""Assert countable facts in docs/manual-test-matrix.md, not its prose.

`docs/manual-test-matrix.md` went four minor versions (v0.11.0 -> v0.15.0) and
nine release prompts without ever being re-run against `main` (R43). Two of its
claims are the kind that silently rot: the list of CLI commands it exercises,
and the community-rule count it states in Section 15. Nothing previously
checked either one against the live source of truth, so both drifted (the
matrix once claimed 30 community rules; the real, current count is derived
below).

Following the R26 pattern (see `tests/test_release_notes_facts.py`): this
module asserts *facts* extracted from the document — a command name, an
integer count — never prose. A reworded "Expected:" sentence, a reordered
section, or new explanatory text must NOT fail these tests. Section wording,
section order, and expected-output prose are explicitly UNASSERTED here; that
is deliberate, not an oversight — an assertion that claims to check more than
it actually does is the exact failure mode this test file exists to close off
(the matrix rotted quietly for the same reason: nothing was checking it, and a
prose-diffing check would itself rot the moment anyone rewords a sentence).

Two facts are checked:

1. Every top-level CLI command registered on the Typer ``app`` (derived live
   from ``mcp_audit.cli.app`` via Click, not a hardcoded literal) is invoked
   somewhere in a ```bash fenced code block in the matrix, and the matrix
   invokes no top-level command name that Typer does not actually register.
2. The community rule count stated in Section 15 of the matrix equals the
   real number of rule IDs loaded from ``rules/community/`` by
   ``load_bundled_community_rules()`` — the exact function `rule list` calls.
"""

from __future__ import annotations

import re
from pathlib import Path

import typer.main

from mcp_audit.cli import app
from mcp_audit.rules.engine import load_bundled_community_rules

ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = ROOT / "docs" / "manual-test-matrix.md"

# A handful of Click builtins/aliases that are not "commands you invoke to
# exercise a feature" and therefore have no reason to appear in the matrix.
_NON_FEATURE_COMMAND_NAMES: frozenset[str] = frozenset()


def _registered_top_level_commands() -> set[str]:
    """Return every top-level command/group name registered on the real app.

    Derived from the live Typer ``app`` via ``typer.main.get_command`` (which
    returns the underlying Click ``Group``), not a hand-maintained literal —
    a new ``@app.command()`` or ``app.add_typer(...)`` is picked up
    automatically the next time this test runs.
    """
    click_group = typer.main.get_command(app)
    assert hasattr(click_group, "commands"), (
        "mcp_audit.cli.app did not resolve to a Click Group with .commands — "
        "typer's internal API may have changed; update this helper."
    )
    return set(click_group.commands.keys()) - _NON_FEATURE_COMMAND_NAMES


def _bash_blocks(matrix_text: str) -> list[str]:
    """Return the contents of every ```bash fenced code block in *matrix_text*."""
    return re.findall(r"```bash\n(.*?)```", matrix_text, re.DOTALL)


def extract_commands_from_matrix(matrix_text: str) -> set[str]:
    """Return every top-level ``mcp-audit <command>`` name invoked in the matrix.

    Only scans inside ```bash fenced blocks (the actual commands a human or CI
    runs), never inside "Expected:" prose, which may quote command *output*
    (e.g. the literal string "mcp-audit v0.15.0 — MCP Security Scanner")
    that is not itself an invocation.

    A line's first whitespace-delimited token after ``mcp-audit`` is the
    command name if it starts with a letter (an option like ``--help`` is
    excluded by construction, since options never appear immediately after
    the bare word ``mcp-audit`` in this document's style — every invocation
    names a command first).
    """
    commands: set[str] = set()
    pattern = re.compile(r"^\s*mcp-audit\s+([a-zA-Z][\w-]*)", re.MULTILINE)
    for block in _bash_blocks(matrix_text):
        commands.update(pattern.findall(block))
    return commands


def extract_community_rule_count_from_matrix(matrix_text: str) -> int:
    """Return the integer community-rule-count claim from Section 15.

    Fails loudly (rather than silently returning 0) if Section 15's sentence
    shape changes — the whole point of this test is to notice drift, not to
    paper over a doc rewrite by matching nothing.
    """
    match = re.search(r"lists (\d+) rule\(s\) total", matrix_text)
    assert match, (
        "Could not find 'lists N rule(s) total' in docs/manual-test-matrix.md "
        "Section 15 — the sentence shape changed; update this test's regex "
        "to match the new wording (keep asserting the fact, not the prose)."
    )
    return int(match.group(1))


class TestAllTopLevelCommandsCoveredByMatrix:
    """Section 1 of two facts asserted: CLI command <-> matrix coverage."""

    def test_every_registered_command_appears_in_matrix(self) -> None:
        matrix_text = MATRIX_PATH.read_text(encoding="utf-8")
        registered = _registered_top_level_commands()
        covered = extract_commands_from_matrix(matrix_text)
        missing = sorted(registered - covered)
        assert not missing, (
            f"{len(missing)} top-level command(s) registered in "
            f"src/mcp_audit/cli/ are never invoked in "
            f"docs/manual-test-matrix.md: {missing}. Add a section (or a "
            "line in an existing section) that exercises each one."
        )

    def test_matrix_names_no_nonexistent_command(self) -> None:
        matrix_text = MATRIX_PATH.read_text(encoding="utf-8")
        registered = _registered_top_level_commands()
        covered = extract_commands_from_matrix(matrix_text)
        phantom = sorted(covered - registered)
        assert not phantom, (
            f"{len(phantom)} command name(s) invoked in "
            f"docs/manual-test-matrix.md do not correspond to any top-level "
            f"command registered in src/mcp_audit/cli/: {phantom}. Either "
            "the command was removed/renamed and the matrix is stale, or "
            "this is a typo."
        )


class TestCommunityRuleCountMatchesMatrix:
    """Section 2 of two facts asserted: Section 15's stated rule count."""

    def test_matrix_rule_count_matches_load_bundled_community_rules(self) -> None:
        matrix_text = MATRIX_PATH.read_text(encoding="utf-8")
        stated_count = extract_community_rule_count_from_matrix(matrix_text)
        real_count = len(load_bundled_community_rules())
        assert stated_count == real_count, (
            f"docs/manual-test-matrix.md Section 15 states {stated_count} "
            f"bundled community rule(s), but "
            f"load_bundled_community_rules() (the function `mcp-audit rule "
            f"list` actually calls) currently loads {real_count}. Update "
            "Section 15's count (and ID range) to match — see "
            "PROVENANCE.md for the reserved/unissued COMM-032 explanation."
        )
