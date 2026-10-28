"""Tests for agent_files/imports.py: Claude Code @imports and prose references."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from mcp_audit.agent_files import imports as im
from mcp_audit.agent_files.imports import (
    ReadBudget,
    extract_imports,
    extract_references,
    follow_references,
    mask_for_imports,
)
from mcp_audit.agent_files.models import AgentFile, AgentFileSurface

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="symlinks")


def _raws(text: str) -> list[str]:
    return [c.raw for c in extract_imports(text)]


# ── Import syntax (code.claude.com/docs/en/memory) ───────────────────────────


def test_basic_import_shapes() -> None:
    text = (
        "See @README for an overview and @package.json.\n- @~/x.md and @/abs/y.md @./z"
    )
    assert _raws(text) == ["README", "package.json.", "~/x.md", "/abs/y.md", "./z"]


def test_trailing_punctuation_gets_a_trimmed_variant() -> None:
    (cand,) = extract_imports("Read @docs/style.md.")
    assert cand.variants == ("docs/style.md.", "docs/style.md")


def test_email_and_scoped_package_are_not_imports() -> None:
    # "@" must start the text or follow whitespace; "@@" and "@#" never import.
    assert _raws("mail me@example.com or @@scope or @#tag or @ alone") == []


def test_quoted_path_is_not_imported() -> None:
    # "A path wrapped in quotes isn't imported at all"
    assert _raws('Load @"Design Docs/api.md" now') == []


def test_backslash_escaped_space_continues_the_path() -> None:
    (cand,) = extract_imports("- API conventions @Design\\ Docs/api-conventions.md")
    assert cand.variants[0] == "Design Docs/api-conventions.md"


def test_unescaped_space_ends_the_path() -> None:
    assert [c.variants[0] for c in extract_imports("@Design Docs/x.md")] == ["Design"]


def test_fragment_is_stripped() -> None:
    (cand,) = extract_imports("@docs/guide.md#setup")
    assert cand.variants[0] == "docs/guide.md"


def test_code_spans_and_fences_are_skipped() -> None:
    text = (
        "Inline `@README` stays literal.\n"
        "``a ` @in-double-span``\n"
        "```\n@in-fence.md\n```\n"
        "~~~text\n@in-tilde.md\n~~~\n"
        "after @real.md\n"
    )
    assert _raws(text) == ["real.md"]


def test_unclosed_fence_hides_the_rest() -> None:
    assert _raws("@a.md\n```\n@b.md\n") == ["a.md"]


def test_html_comments_are_skipped() -> None:
    text = (
        "<!-- @hidden.md\n\nstill comment @also.md -->\nvisible @shown.md <!-- @x -->"
    )
    assert _raws(text) == ["shown.md"]


def test_unclosed_comment_is_scanned() -> None:
    # Stricter reading: an unclosed <!-- hides nothing.
    assert _raws("<!-- @x.md") == ["x.md"]


def test_import_right_after_a_code_span_counts() -> None:
    # Claude Code reads the text after a code span as a new text token.
    assert _raws("see `x`@after.md") == ["after.md"]


def test_markdown_emphasis_and_links_give_trimmed_variants() -> None:
    (strong,) = extract_imports("**@docs/a.md**")
    assert "docs/a.md" in strong.variants
    (link,) = extract_imports("[@docs/b.md](https://example.com)")
    assert "docs/b.md" in link.variants
    # Claude Code does not import "(@x)" (one text token, "(" before "@").
    assert extract_imports("(@docs/c.md)") == []


def test_indented_code_is_scanned_stricter_reading() -> None:
    assert _raws("text\n\n    @indented.md\n") == ["indented.md"]


def test_line_numbers_point_at_the_original_line() -> None:
    cands = extract_imports("one\n```\n@skip\n```\nfive @five.md\n")
    assert [(c.raw, c.line) for c in cands] == [("five.md", 5)]


def test_mask_preserves_length_and_lines() -> None:
    text = "a `b` <!-- c\nd --> e\n```\nf\n```\n"
    masked = mask_for_imports(text)
    assert len(masked) == len(text)
    assert masked.count("\n") == text.count("\n")


def test_import_limit() -> None:
    text = " ".join(f"@f{i}.md" for i in range(500))
    assert len(extract_imports(text, limit=10)) == 10


@pytest.mark.parametrize(
    "text",
    [
        "`" * 200_000,
        "` " * 200_000,
        "<!--" * 100_000,
        "@" + "a" * 500_000,
        "@\\" * 200_000,
        ("`x " * 50_000) + "\n\n" + ("``y " * 50_000),
    ],
    # Short ids: pytest puts the id in PYTEST_CURRENT_TEST, and Windows caps an
    # environment variable at 32,767 characters.
    ids=[
        "backticks",
        "spaced-backticks",
        "comment-openers",
        "long-path",
        "escapes",
        "mixed-runs",
    ],
)
def test_pathological_import_inputs_are_linear(text: str) -> None:
    start = time.monotonic()
    extract_imports(text)
    assert time.monotonic() - start < 5.0


# ── Prose references (Bad Memory, arXiv 2607.14611) ──────────────────────────


def test_reference_shapes() -> None:
    text = (
        "Read the files in `knowledge/` before recommending anything.\n"
        "Before starting any task, read docs/agent-rules.md.\n"
        "Read this file at the start of every conversation alongside `identity.md`.\n"
        "- **Always** consult `core/behaviors.md` first.\n"
        "1. Follow `team/conventions.md`.\n"
    )
    refs = [(r.raw, r.is_dir) for r in extract_references(text)]
    assert refs == [
        ("knowledge/", True),
        ("docs/agent-rules.md", False),
        ("identity.md", False),
        ("core/behaviors.md", False),
        ("team/conventions.md", False),
    ]


def test_cross_references_are_not_orders() -> None:
    # "see X" and a mid-sentence "read more in X" are documentation links, not
    # orders; following them pulled 33 ordinary docs into this repository's
    # own scan when "see" counted.
    text = (
        "See `../core/behaviors.md` for universal behavioral rules.\n"
        "The scanner is fast; see `docs/scoring.md`.\n"
        "Rules are described in detail, and you can read more in docs/rules.md.\n"
    )
    assert extract_references(text) == []


def test_references_ignore_urls_absolute_home_and_fences() -> None:
    text = (
        "Read https://example.com/guide.md and /etc/notes.md and ~/x.md.\n"
        "```\nread docs/in-fence.md\n```\n"
        "docs/no-verb.md is here\n"
    )
    assert extract_references(text) == []


def test_reference_needs_the_same_sentence() -> None:
    assert extract_references("Read carefully. Then docs/x.md exists.") == []


def test_pathological_reference_input_is_bounded() -> None:
    text = "read " * 400_000
    start = time.monotonic()
    extract_references(text)
    assert time.monotonic() - start < 5.0


# ── Following ─────────────────────────────────────────────────────────────────


def _af(
    path: Path,
    *,
    scope: str = "project",
    surface: AgentFileSurface = AgentFileSurface.CLAUDE_MEMORY,
    follows: bool = True,
) -> AgentFile:
    text = path.read_text(encoding="utf-8")
    return AgentFile(
        path=path,
        surface=surface,
        client="claude-code",
        scope=scope,
        raw_content=text,
        body=text,
        follows_imports=follows,
    )


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root.resolve()


def test_follows_inside_root_and_inherits_surface(repo: Path, tmp_path: Path) -> None:
    (repo / "docs").mkdir()
    (repo / "docs" / "a.md").write_text("A @b.md", encoding="utf-8")
    (repo / "docs" / "b.md").write_text("B", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("@docs/a.md", encoding="utf-8")
    root_af = _af(repo / "CLAUDE.md")
    reached = follow_references([root_af], project_root=repo, home=tmp_path)
    assert [f.path.name for f in reached] == ["a.md", "b.md"]
    a, b = reached
    assert a.imported_from == repo / "CLAUDE.md"
    assert b.imported_from == repo / "docs" / "a.md"  # relative to the importer
    assert a.surface == AgentFileSurface.CLAUDE_MEMORY and a.follows_imports
    assert [(e.raw, e.status) for e in root_af.edges] == [("docs/a.md", "followed")]


def test_outside_root_is_an_edge_and_never_read(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("secret", encoding="utf-8")
    (repo / "CLAUDE.md").write_text(f"@../outside.md @{outside.as_posix()}")
    real = im.read_text_capped
    read: list[Path] = []

    def _spy(path: Path, cap: int = im.READ_CAP_BYTES) -> tuple[str, bool]:
        read.append(path)
        return real(path, cap)

    monkeypatch.setattr(im, "read_text_capped", _spy)
    root_af = _af(repo / "CLAUDE.md")
    assert follow_references([root_af], project_root=repo, home=tmp_path) == []
    assert [e.status for e in root_af.edges] == ["outside", "outside"]
    assert outside not in read


def test_missing_targets_produce_no_edge(repo: Path, tmp_path: Path) -> None:
    (repo / "CLAUDE.md").write_text("@nope.md @/definitely/not/here.md @~/none.md")
    root_af = _af(repo / "CLAUDE.md")
    follow_references([root_af], project_root=repo, home=tmp_path)
    assert root_af.edges == []


def test_home_import_resolves_against_home(repo: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "mine.md").write_text("x", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("@~/.claude/mine.md")
    root_af = _af(repo / "CLAUDE.md")
    follow_references([root_af], project_root=repo, home=home)
    (edge,) = root_af.edges
    assert edge.status == "outside" and edge.target == home / ".claude" / "mine.md"


def test_ignored_target_is_read_and_marked(repo: Path, tmp_path: Path) -> None:
    (repo / ".gitignore").write_text(".notes/\n", encoding="utf-8")
    (repo / ".notes").mkdir()
    (repo / ".notes" / "local.md").write_text("n", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("@.notes/local.md")
    root_af = _af(repo / "CLAUDE.md")
    reached = follow_references([root_af], project_root=repo, home=tmp_path)
    assert [f.path.name for f in reached] == ["local.md"]
    (edge,) = root_af.edges
    assert edge.status == "ignored" and edge.detail.endswith(": .notes/")


def test_references_never_get_outside_or_ignored_status(
    repo: Path, tmp_path: Path
) -> None:
    (repo / ".gitignore").write_text("private.md\n", encoding="utf-8")
    (repo / "private.md").write_text("p", encoding="utf-8")
    (tmp_path / "out.md").write_text("o", encoding="utf-8")
    (repo / "AGENTS.md").write_text("Read `private.md` and see ../out.md first.")
    root_af = _af(repo / "AGENTS.md", surface=AgentFileSurface.AGENTS_MD)
    reached = follow_references([root_af], project_root=repo, home=tmp_path)
    assert [f.path.name for f in reached] == ["private.md"]
    assert [(e.kind, e.status) for e in root_af.edges] == [("reference", "followed")]


def test_directory_reference_takes_markdown_children(
    repo: Path, tmp_path: Path
) -> None:
    (repo / "knowledge").mkdir()
    for name in ("a.md", "b.md", "c.txt"):
        (repo / "knowledge" / name).write_text(name, encoding="utf-8")
    (repo / "CLAUDE.md").write_text("Read the files in `knowledge/` before acting.")
    reached = follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path
    )
    assert sorted(f.path.name for f in reached) == ["a.md", "b.md"]


def test_references_can_be_disabled(repo: Path, tmp_path: Path) -> None:
    (repo / "x.md").write_text("x", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("Read `x.md` first.")
    reached = follow_references(
        [_af(repo / "CLAUDE.md")],
        project_root=repo,
        home=tmp_path,
        include_references=False,
    )
    assert reached == []


def test_referenced_file_does_not_expand_imports(repo: Path, tmp_path: Path) -> None:
    (repo / "guide.md").write_text("@inner.md", encoding="utf-8")
    (repo / "inner.md").write_text("i", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("Read `guide.md` before starting.")
    reached = follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path
    )
    # An @ in a file the agent opens on its own is not an import.
    assert [f.path.name for f in reached] == ["guide.md"]
    assert reached[0].follows_imports is False


def test_non_import_surface_does_not_expand(repo: Path, tmp_path: Path) -> None:
    (repo / "x.md").write_text("x", encoding="utf-8")
    (repo / "AGENTS.override.md").write_text("@x.md")
    af = _af(
        repo / "AGENTS.override.md", surface=AgentFileSurface.AGENTS_MD, follows=False
    )
    assert follow_references([af], project_root=repo, home=tmp_path) == []


def test_skill_surface_is_not_followed(repo: Path, tmp_path: Path) -> None:
    (repo / "x.md").write_text("x", encoding="utf-8")
    (repo / "SKILL.md").write_text("Read `x.md` and @x.md")
    af = _af(repo / "SKILL.md", surface=AgentFileSurface.CLAUDE_SKILL)
    assert follow_references([af], project_root=repo, home=tmp_path) == []


def test_depth_is_four_hops(repo: Path, tmp_path: Path) -> None:
    for i in range(1, 7):
        (repo / f"f{i}.md").write_text(f"@f{i + 1}.md", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("@f1.md")
    reached = follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path
    )
    # "Imported files can recursively import other files, with a maximum
    # depth of four hops."
    assert [f.path.name for f in reached] == ["f1.md", "f2.md", "f3.md", "f4.md"]


def test_cycles_terminate(repo: Path, tmp_path: Path) -> None:
    (repo / "a.md").write_text("@b.md", encoding="utf-8")
    (repo / "b.md").write_text("@a.md @CLAUDE.md", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("@a.md")
    reached = follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path
    )
    assert [f.path.name for f in reached] == ["a.md", "b.md"]


def test_budget_stop_is_noted(repo: Path, tmp_path: Path) -> None:
    for i in range(5):
        (repo / f"f{i}.md").write_text("x", encoding="utf-8")
    (repo / "CLAUDE.md").write_text(" ".join(f"@f{i}.md" for i in range(5)))
    root_af = _af(repo / "CLAUDE.md")
    notes: list[str] = []
    reached = follow_references(
        [root_af],
        project_root=repo,
        home=tmp_path,
        budget=ReadBudget(max_files=2),
        notes=notes,
    )
    assert len(reached) == 2
    assert [e.status for e in root_af.edges].count("skipped") == 3
    assert any("stopped after 2 files" in n for n in notes)


def test_oversized_import_is_truncated_and_noted(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(im, "READ_CAP_BYTES", 8)
    (repo / "big.md").write_text("0123456789abcdef", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("@big.md")
    notes: list[str] = []
    real = im.read_text_capped
    monkeypatch.setattr(im, "read_text_capped", lambda p, cap=8: real(p, cap))
    (reached,) = follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path, notes=notes
    )
    assert reached.truncated and reached.body == "01234567"
    assert any("only the first part" in n for n in notes)


def test_windows_trailing_dots_and_spaces_are_dropped() -> None:
    # Win32 opens "style.md." as "style.md"; name the target the same way.
    got = im._win32_name(Path("docs") / "style.md.", windows=True)
    assert got == Path("docs") / "style.md"
    assert im._win32_name(Path("a ") / "b. .", windows=True) == Path("a") / "b"
    assert im._win32_name(Path("..") / "x.md", windows=True) == Path("..") / "x.md"
    assert im._win32_name(Path("style.md."), windows=False) == Path("style.md.")


def test_crlf_is_normalised_like_text_mode(tmp_path: Path) -> None:
    target = tmp_path / "crlf.md"
    target.write_bytes(b"one\r\ntwo\rthree\n")
    assert im.read_text_capped(target) == ("one\ntwo\nthree\n", False)


def test_binary_target_is_not_scanned(repo: Path, tmp_path: Path) -> None:
    (repo / "blob.md").write_bytes(b"\x00\x01\x02binary")
    (repo / "CLAUDE.md").write_text("@blob.md")
    root_af = _af(repo / "CLAUDE.md")
    assert follow_references([root_af], project_root=repo, home=tmp_path) == []
    assert [e.status for e in root_af.edges] == ["followed"]


def test_unreadable_target_is_noted_not_raised(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (repo / "x.md").write_text("x", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("@x.md")

    def _deny(path: Path, cap: int = 0) -> tuple[str, bool]:
        raise PermissionError("denied")

    monkeypatch.setattr(im, "read_text_capped", _deny)
    notes: list[str] = []
    assert (
        follow_references(
            [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path, notes=notes
        )
        == []
    )
    assert any("cannot read" in n for n in notes)


def test_frontmatter_offsets_line_numbers(repo: Path, tmp_path: Path) -> None:
    (repo / "x.md").write_text("x", encoding="utf-8")
    raw = "---\npaths:\n  - src/**\n---\nrule @x.md\n"
    af = AgentFile(
        path=repo / "rule.md",
        surface=AgentFileSurface.CLAUDE_RULE,
        client="claude-code",
        scope="project",
        raw_content=raw,
        body="rule @x.md\n",
        follows_imports=True,
    )
    (repo / "rule.md").write_text(raw, encoding="utf-8")
    follow_references([af], project_root=repo, home=tmp_path)
    assert af.edges[0].line == 5


@posix_only
def test_symlinked_target_outside_is_trust002_high_and_not_read(
    repo: Path, tmp_path: Path
) -> None:
    secret = tmp_path / "secret.md"
    secret.write_text("s", encoding="utf-8")
    os.symlink(secret, repo / "notes.md")
    (repo / "CLAUDE.md").write_text("@notes.md")
    root_af = _af(repo / "CLAUDE.md")
    skip: list = []
    reached = follow_references(
        [root_af], project_root=repo, home=tmp_path, skip_findings=skip
    )
    assert reached == []
    assert [(f.id, f.severity.value) for f in skip] == [("TRUST-002", "HIGH")]
    assert root_af.edges[0].status == "symlink"


@posix_only
def test_symlinked_intermediate_directory_stops_the_edge(
    repo: Path, tmp_path: Path
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "x.md").write_text("x", encoding="utf-8")
    os.symlink(elsewhere, repo / "docs")
    (repo / "CLAUDE.md").write_text("@docs/x.md")
    skip: list = []
    reached = follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path, skip_findings=skip
    )
    assert reached == []
    assert len(skip) == 1 and skip[0].id == "TRUST-002"
    assert skip[0].finding_path == str(repo / "docs")
    assert skip[0].severity.value == "HIGH"


@posix_only
def test_symlink_inside_root_is_medium(repo: Path, tmp_path: Path) -> None:
    (repo / "real.md").write_text("r", encoding="utf-8")
    os.symlink(repo / "real.md", repo / "link.md")
    (repo / "CLAUDE.md").write_text("@link.md")
    skip: list = []
    follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path, skip_findings=skip
    )
    assert [(f.id, f.severity.value) for f in skip] == [("TRUST-002", "MEDIUM")]


@posix_only
def test_symlinked_start_file_is_not_followed(repo: Path, tmp_path: Path) -> None:
    (repo / "x.md").write_text("x", encoding="utf-8")
    (tmp_path / "real-claude.md").write_text("@x.md", encoding="utf-8")
    os.symlink(tmp_path / "real-claude.md", repo / "CLAUDE.md")
    af = _af(repo / "CLAUDE.md")
    assert follow_references([af], project_root=repo, home=tmp_path) == []
    assert af.edges == []


@posix_only
def test_user_scope_symlink_is_trust004(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (tmp_path / "dot.md").write_text("d", encoding="utf-8")
    os.symlink(tmp_path / "dot.md", home / ".claude" / "dot.md")
    (home / ".claude" / "CLAUDE.md").write_text("@dot.md")
    skip: list = []
    af = _af(home / ".claude" / "CLAUDE.md", scope="user")
    assert (
        follow_references([af], project_root=None, home=home, skip_findings=skip) == []
    )
    assert [f.id for f in skip] == ["TRUST-004"]


def test_user_scope_reads_inside_home_but_not_outside(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "mine.md").write_text("m", encoding="utf-8")
    (tmp_path / "elsewhere.md").write_text("e", encoding="utf-8")
    (home / ".claude" / "CLAUDE.md").write_text(
        f"@mine.md @{(tmp_path / 'elsewhere.md').as_posix()}"
    )
    af = _af(home / ".claude" / "CLAUDE.md", scope="user")
    reached = follow_references([af], project_root=None, home=home)
    assert [f.path.name for f in reached] == ["mine.md"]
    # No "outside" edge for a user's own file: that is their configuration.
    assert [e.status for e in af.edges] == ["followed"]


# ── Review round: parity shapes ───────────────────────────────────────────────

_PARITY_SHAPES = [
    "- item ` one\n- @../outside/evil.md ` two\n",
    "Intro ` tick\n# Heading\n@../outside/evil.md ` end\n",
    "Text with a lone ` backtick\n   \n@../outside/evil.md\nanother ` here\n",
    "Notes <!-- draft\n\n@../outside/evil.md\n\nend -->\n",
    "<!-- maintainer note\n```\n-->\n@../outside/evil.md\n```\n",
]


@pytest.mark.parametrize("text", _PARITY_SHAPES)
def test_markup_that_cannot_span_blocks_does_not_hide_an_import(text: str) -> None:
    assert _raws(text) == ["../outside/evil.md"]


def test_parenthesised_import_is_not_extracted() -> None:
    assert _raws("see (@~/x.md) and (@../x.md)") == []


# ── Review round: network paths, NUL bytes, caps ──────────────────────────────

_NETWORK = [
    "//evil.example/share/x.md",
    "/net/host/x.md",
    "/Network/Servers/x.md",
]


@pytest.mark.parametrize(
    "raw", ["\\\\host\\share\\x.md", "\\\\?\\C:\\x", "//h/s", "/net/h/x", "/Network/x"]
)
def test_is_network_path_matches_unc_device_and_automount_forms(raw: str) -> None:
    assert im.is_network_path(raw)
    assert not im.is_network_path("docs/x.md")


@pytest.mark.parametrize("target", _NETWORK)
def test_network_paths_are_reported_by_text_and_never_touched(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    (repo / "CLAUDE.md").write_text(f"@{target.replace(' ', chr(92) + ' ')}\n")
    root_af = _af(repo / "CLAUDE.md")

    touched: list[str] = []
    marker = target.replace("\\", "/").strip("/").split("/")[0:2]
    needle = (
        marker[-1] if marker[0] in ("net", "Network") or len(marker) < 2 else marker[0]
    )

    def _spy(real: object):  # type: ignore[no-untyped-def]
        def _wrapped(*args: object, **kwargs: object) -> object:
            touched.extend(str(a) for a in args if needle in str(a).replace("\\", "/"))
            return real(*args, **kwargs)  # type: ignore[operator]

        return _wrapped

    for name in ("stat", "lstat", "open"):
        monkeypatch.setattr(os, name, _spy(getattr(os, name)))
    for name in ("is_file", "is_dir", "exists", "is_symlink", "stat", "lstat"):
        monkeypatch.setattr(Path, name, _spy(getattr(Path, name)))
    follow_references([root_af], project_root=repo, home=tmp_path)
    monkeypatch.undo()
    assert touched == []
    assert [e.status for e in root_af.edges] == ["outside"]


def test_nul_byte_in_import_or_reference_is_dropped(repo: Path, tmp_path: Path) -> None:
    (repo / "CLAUDE.md").write_text("@a\x00b.md @ok.md\nsee docs/a\x00b.md\n")
    (repo / "ok.md").write_text("fine", encoding="utf-8")
    assert _raws("@a\x00b.md") == []
    root_af = _af(repo / "CLAUDE.md")
    reached = follow_references([root_af], project_root=repo, home=tmp_path)
    assert [f.path.name for f in reached] == ["ok.md"]


def test_nul_byte_does_not_lose_the_default_pass(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit.agent_files.reach import default_scan_findings, project_scan_findings

    (repo / "CLAUDE.md").write_text("@a\x00b.md @../outside.md\n", encoding="utf-8")
    (tmp_path / "outside.md").write_text("x", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for fn in (default_scan_findings, project_scan_findings):
        errors: list[str] = []
        found = fn(repo, errors)
        assert any(f.id == "MEM-003" for f in found), (fn.__name__, errors)


def test_raw_token_flood_does_not_hide_a_later_external_import(
    repo: Path, tmp_path: Path
) -> None:
    users = " ".join(f"@user{i}" for i in range(500))
    (repo / "CLAUDE.md").write_text(f"{users}\n@../outside.md\n", encoding="utf-8")
    (tmp_path / "outside.md").write_text("x", encoding="utf-8")
    root_af = _af(repo / "CLAUDE.md")
    follow_references([root_af], project_root=repo, home=tmp_path)
    assert [e.status for e in root_af.edges] == ["outside"]


def test_edge_cap_is_noted(repo: Path, tmp_path: Path) -> None:
    for i in range(im.MAX_EDGES_PER_FILE + 5):
        (repo / f"f{i}.md").write_text("x", encoding="utf-8")
    body = " ".join(f"@f{i}.md" for i in range(im.MAX_EDGES_PER_FILE + 5))
    (repo / "CLAUDE.md").write_text(body, encoding="utf-8")
    notes: list[str] = []
    follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path, notes=notes
    )
    assert any("CLAUDE.md" in n and "200" in n for n in notes), notes


def test_token_and_verb_caps_are_noted() -> None:
    notes: list[str] = []
    extract_imports(" ".join(f"@u{i}" for i in range(40)), limit=10, notes=notes)
    assert notes
    notes = []
    extract_references(
        " ".join(f"read x{i}.md." for i in range(50)), limit=5, notes=notes
    )
    assert notes


def test_directory_reference_cap_is_noted(repo: Path, tmp_path: Path) -> None:
    d = repo / "docs"
    d.mkdir()
    for i in range(im.MAX_DIRECTORY_REFERENCE_FILES + 3):
        (d / f"n{i:02}.md").write_text("x", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("Read the files in `docs/` before acting.\n")
    notes: list[str] = []
    follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path, notes=notes
    )
    assert any("docs" in n for n in notes), notes


def test_import_of_an_ignored_file_is_not_flagged_ignored(
    repo: Path, tmp_path: Path
) -> None:
    (repo / ".gitignore").write_text(".claude/worktrees/\n", encoding="utf-8")
    wt = repo / ".claude" / "worktrees" / "w1"
    wt.mkdir(parents=True)
    (wt / "CLAUDE.md").write_text("@AGENTS.md", encoding="utf-8")
    (wt / "AGENTS.md").write_text("x", encoding="utf-8")
    root_af = _af(wt / "CLAUDE.md")
    follow_references([root_af], project_root=repo, home=tmp_path)
    assert [e.status for e in root_af.edges] == ["followed"]


def test_project_walk_skips_claude_worktrees(repo: Path) -> None:
    from mcp_audit.agent_files.discovery import discover_agent_files

    (repo / "CLAUDE.md").write_text("top", encoding="utf-8")
    wt = repo / ".claude" / "worktrees" / "w1"
    wt.mkdir(parents=True)
    (wt / "CLAUDE.md").write_text("copy", encoding="utf-8")
    found = discover_agent_files(project_root=repo, include_user_global=False)
    assert [f.path for f in found if f.path.name == "CLAUDE.md"] == [repo / "CLAUDE.md"]


def test_secret_like_path_text_is_redacted_in_notes(repo: Path, tmp_path: Path) -> None:
    secret = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105
    body = " ".join(f"@{secret}{i}.md" for i in range(im.MAX_EDGES_PER_FILE + 5))
    for i in range(im.MAX_EDGES_PER_FILE + 5):
        (repo / f"{secret}{i}.md").write_text("x", encoding="utf-8")
    (repo / "CLAUDE.md").write_text(body, encoding="utf-8")
    notes: list[str] = []
    follow_references(
        [_af(repo / "CLAUDE.md")], project_root=repo, home=tmp_path, notes=notes
    )
    assert notes and all(secret not in n for n in notes)


def test_masking_of_unclosed_markup_is_linear() -> None:
    for unit in ("` ", "<!-- ", "[a](", "- ` ", "> ` ", "<b "):
        text = (unit + "@a.md\n") * 4000
        start = time.monotonic()
        extract_imports(text)
        assert time.monotonic() - start < 10.0, unit


def test_nul_byte_does_not_crash_the_cli(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from mcp_audit.cli import app

    (repo / "CLAUDE.md").write_text("@a\x00b.md @../o.md\nread x\x00y.md\n")
    (tmp_path / "o.md").write_text("x", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    runner = CliRunner()
    for args in (
        ["agent-files", "scan", "--project", str(repo)],
        ["scan", "--project", str(repo), "--include-agent-files", "--format", "json"],
    ):
        result = runner.invoke(app, args)
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "MEM-003" in result.output or "outside the project" in result.output
