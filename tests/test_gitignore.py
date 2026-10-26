"""Tests for _gitignore.py: deciding git-ignore state by reading files only.

Expected answers follow gitignore(5); the matcher was also compared with
``git ls-files --others --ignored --exclude-standard`` on 1,350 pattern
combinations during development (STORY-0093), including byte-order marks,
``***`` segments and empty segments, with no disagreement.  Nothing here runs
git.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from mcp_audit import _gitignore as gi

LOCAL = (".claude", "settings.local.json")


def _ignored(rel: tuple[str, ...], *files: tuple[tuple[str, ...], str]) -> bool:
    sources = [
        gi.IgnoreSource(base, tuple(gi.parse_ignore_text(text)), "t")
        for base, text in files
    ]
    return gi.is_ignored(rel, sources)


class TestPatterns:
    @pytest.mark.parametrize(
        "text",
        [
            ".claude/settings.local.json",
            "/.claude/settings.local.json",
            "**/.claude/settings.local.json",
            "settings.local.json",
            "*.local.json",
            ".claude/",
            ".claude",
            ".claude/*",
            ".claude/**",
            "**",
            "*",
            "[s]ettings.local.json",
            "settings.local.jso[!x]",
            "settings.local.jso?",
            "s*l*l*.json",
            "[[:alpha:]]ettings.local.json",
            "settings.local.json   ",  # trailing spaces are dropped
            "settings.local.json\r",  # CRLF file
            "a**b\nsettings.local.json",
            "\ufeffsettings.local.json",  # UTF-8 byte-order mark
            "\ufeff.claude/",
            ".claude/***",  # a whole segment of *** is **
            "***/settings.local.json",
            "**/**/**/settings.local.json",  # consecutive ** collapse
            "/**/.claude/**/**",
        ],
    )
    def test_ignores_root_local_file(self, text: str) -> None:
        assert _ignored(LOCAL, ((), text))

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "# settings.local.json",
            "\\#settings.local.json",
            "settings.json",
            "/settings.local.json",  # anchored at the root, not in .claude/
            ".claude/settings.local.json/",  # directory-only
            "settings.local.json\n!settings.local.json",
            ".claude/*\n!.claude/settings.local.json",
            "*.json\n!settings.local.json",
            "settings.local.jso[",  # malformed: matches nothing, like wildmatch
            "settings.local.json\\",
            "[[:nope:]]ettings.local.json",
            ".claude/**/x",
            ".claude//settings.local.json",  # an empty segment matches nothing
            "/.claude//settings.local.json",
            "**//settings.local.json",
            ".claude//",
            "\ufeff# settings.local.json",  # still a comment after the BOM
        ],
    )
    def test_does_not_ignore_root_local_file(self, text: str) -> None:
        assert not _ignored(LOCAL, ((), text))

    def test_excluded_parent_cannot_be_reincluded(self) -> None:
        assert _ignored(LOCAL, ((), ".claude/\n!.claude/settings.local.json"))
        # but a pattern on the children leaves the directory open
        assert not _ignored(LOCAL, ((), ".claude/*\n!.claude/settings.local.json"))

    def test_trailing_globstar_needs_something_inside(self) -> None:
        assert _ignored(LOCAL, ((), ".claude/**"))
        assert not _ignored((".claude",), ((), ".claude/**"))

    def test_anchored_pattern_does_not_reach_nested(self) -> None:
        nested = ("sub", ".claude", "settings.local.json")
        assert not _ignored(nested, ((), ".claude/settings.local.json"))
        assert _ignored(nested, ((), "**/.claude/settings.local.json"))
        assert _ignored(nested, ((), "sub/**/settings.local.json"))
        assert _ignored(nested, ((), "sub/*/settings.local.json"))

    def test_lower_level_file_overrides_higher(self) -> None:
        nested = ("sub", ".claude", "settings.local.json")
        assert not _ignored(
            nested, ((), "settings.local.json"), (("sub",), "!settings.local.json")
        )
        assert _ignored(
            nested,
            ((), "!settings.local.json"),
            (("sub", ".claude"), "settings.local.json"),
        )

    def test_a_file_does_not_apply_to_its_own_directory(self) -> None:
        # .claude/.gitignore with "*" ignores what is in .claude, not .claude.
        assert _ignored(LOCAL, (((".claude",), "*")))
        assert not _ignored((".claude",), (((".claude",), "*")))

    def test_triple_star_inside_a_segment_is_a_wildcard(self) -> None:
        assert _ignored(LOCAL, ((), ".cl***e/settings.local.json"))
        assert not _ignored(("sub",) + LOCAL, ((), "/***x/.claude/settings.local.json"))

    def test_anchored_long_patterns_are_rejected_by_length(self) -> None:
        line = "/" + "/".join(["a"] * 2000)
        [pattern] = gi.parse_ignore_text(line)
        assert pattern.min_parts == 2000
        meter = gi.MatchMeter()
        assert not pattern.matches(LOCAL, False, meter)
        assert meter.steps == 0  # rejected before any segment is compared
        [globbed] = gi.parse_ignore_text("/a/**/**/b/**")
        assert globbed.min_parts == 3

    def test_long_anchored_lines_against_deep_paths_stay_bounded(self) -> None:
        start = time.perf_counter()
        line = "/" + "/".join(["a"] * 2000)
        text = "\n".join([line] * 250)
        deep = tuple(["a"] * 1999) + ("settings.local.json",)
        meter = gi.MatchMeter(limit=200_000)
        sources = [gi.IgnoreSource((), tuple(gi.parse_ignore_text(text)), "t")]
        with pytest.raises(gi.MatchBudgetExceededError):
            for _ in range(1000):
                gi.is_ignored(deep, sources, meter)
        assert time.perf_counter() - start < 5

    def test_pathological_wildcards_run_in_linear_time(self) -> None:
        start = time.perf_counter()
        text = "*a" * 40 + "b\n" + "\n".join(f"x{i}*y*z" for i in range(20_000))
        assert not _ignored(("a" * 250,), ((), text))
        assert time.perf_counter() - start < 5


class TestGitConfig:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("[core]\n\texcludesFile = ~/.gitignore_global\n", "~/.gitignore_global"),
            ("[CORE]\nEXCLUDESFILE=/etc/ignore ; comment\n", "/etc/ignore"),
            ('[core] excludesfile = "~/my ignore"\n', "~/my ignore"),
            ("[core]\nexcludesfile = a\n[core]\nexcludesfile = b\n", "b"),
            ('[core "x"]\nexcludesfile = a\n', None),
            ("[user]\nexcludesfile = a\n", None),
            ("excludesfile = a\n", None),
            ("[core]\n# excludesfile = a\n", None),
            ("[core\nexcludesfile = a\n", None),
            ("", None),
        ],
    )
    def test_excludes_file_setting(self, text: str, expected: str | None) -> None:
        assert gi.excludes_file_setting(text) == expected

    def test_plain_include_is_followed_one_level(self) -> None:
        files = {
            "~/.gitconfig.local": (
                "[core]\nexcludesFile = ~/inc\n[include]\npath = deeper"
            ),
            "deeper": "[core]\nexcludesFile = ~/too-deep\n",
        }
        asked: list[str] = []

        def include(value: str) -> str | None:
            asked.append(value)
            return files.get(value)

        text = "[core]\nexcludesFile = ~/main\n[include]\n\tpath = ~/.gitconfig.local\n"
        assert gi.excludes_file_setting(text, include) == "~/inc"
        assert asked == ["~/.gitconfig.local"]  # the nested include is not read
        # A later core.excludesFile in the including file wins, as in git.
        assert gi.excludes_file_setting(
            text + "[core]\nexcludesFile = ~/last\n", include
        ) == ("~/last")

    def test_include_if_is_not_followed(self) -> None:
        text = '[includeIf "gitdir:~/work/"]\npath = ~/.gitconfig.work\n'
        assert (
            gi.excludes_file_setting(text, lambda _v: "[core]\nexcludesFile = x")
            is None
        )


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    path = tmp_path / "home"
    path.mkdir()
    return path


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git" / "info").mkdir(parents=True)
    (root / ".claude").mkdir()
    return root


class TestReader:
    def test_default_global_excludes(self, tmp_path: Path, home: Path) -> None:
        root = _repo(tmp_path)
        reader = gi.IgnoreFileReader(home=home)
        assert not reader.is_ignored(root, LOCAL)
        (home / ".config" / "git").mkdir(parents=True)
        (home / ".config" / "git" / "ignore").write_text(
            "**/.claude/settings.local.json\n"
        )
        assert gi.IgnoreFileReader(home=home).is_ignored(root, LOCAL)

    def test_xdg_config_home(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        xdg = tmp_path / "xdg"
        (xdg / "git").mkdir(parents=True)
        (xdg / "git" / "ignore").write_text("settings.local.json\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        assert gi.IgnoreFileReader(home=home).is_ignored(_repo(tmp_path), LOCAL)

    def test_core_excludes_file_replaces_the_default(
        self, tmp_path: Path, home: Path
    ) -> None:
        root = _repo(tmp_path)
        (home / ".config" / "git").mkdir(parents=True)
        (home / ".config" / "git" / "ignore").write_text("settings.local.json\n")
        (home / ".gitconfig").write_text("[core]\n\texcludesFile = ~/.gi_global\n")
        assert not gi.IgnoreFileReader(home=home).is_ignored(root, LOCAL)
        (home / ".gi_global").write_text(".claude/\n")
        assert gi.IgnoreFileReader(home=home).is_ignored(root, LOCAL)

    def test_relative_core_excludes_file_reads_no_global_file(
        self, tmp_path: Path, home: Path
    ) -> None:
        (home / ".config" / "git").mkdir(parents=True)
        (home / ".config" / "git" / "ignore").write_text("settings.local.json\n")
        (home / ".gitconfig").write_text("[core]\nexcludesFile = rel/ignore\n")
        reader = gi.IgnoreFileReader(home=home)
        assert not reader.is_ignored(_repo(tmp_path), LOCAL)
        assert "relative" in reader.global_label

    def test_info_exclude_and_nested_gitignore(
        self, tmp_path: Path, home: Path
    ) -> None:
        root = _repo(tmp_path)
        (root / ".git" / "info" / "exclude").write_text("settings.local.json\n")
        assert gi.IgnoreFileReader(home=home).is_ignored(root, LOCAL)
        (root / ".git" / "info" / "exclude").write_text("")
        (root / ".claude" / ".gitignore").write_text("settings.local.json\n")
        assert gi.IgnoreFileReader(home=home).is_ignored(root, LOCAL)

    def test_git_file_worktree_skips_info_exclude(
        self, tmp_path: Path, home: Path
    ) -> None:
        root = tmp_path / "wt"
        (root / ".claude").mkdir(parents=True)
        (root / ".git").write_text("gitdir: /elsewhere\n")
        assert gi.find_work_tree_root(root / ".claude") == root
        assert not gi.IgnoreFileReader(home=home).is_ignored(root, LOCAL)

    @pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlinks")
    def test_symlinked_gitignore_is_not_honoured(
        self, tmp_path: Path, home: Path
    ) -> None:
        root = _repo(tmp_path)
        target = tmp_path / "elsewhere"
        target.write_text(".claude/\n")
        try:
            (root / ".gitignore").symlink_to(target)
        except OSError:
            pytest.skip("cannot create symlinks here")
        assert not gi.IgnoreFileReader(home=home).is_ignored(root, LOCAL)

    @pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlinks")
    def test_never_reads_through_a_symlinked_directory(
        self, tmp_path: Path, home: Path
    ) -> None:
        root = tmp_path / "repo"
        (root / ".git").mkdir(parents=True)
        real = tmp_path / "outside"
        real.mkdir()
        (real / ".gitignore").write_text("settings.local.json\n")
        try:
            (root / "sub").symlink_to(real, target_is_directory=True)
        except OSError:
            pytest.skip("cannot create symlinks here")
        reader = gi.IgnoreFileReader(home=home)
        labels = [s.label for s in reader.sources(root, ("sub", "settings.local.json"))]
        assert "repo/sub/.gitignore" not in labels

    def test_unreadable_file_makes_the_state_unknown(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _repo(tmp_path)
        (root / ".gitignore").write_text("x\n")
        real_open = Path.open

        def deny(self: Path, *args: object, **kwargs: object):  # noqa: ANN202
            if self.name == ".gitignore":
                raise PermissionError(13, "Permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", deny)
        reader = gi.IgnoreFileReader(home=home)
        with pytest.raises(gi.IgnoreStateUnknownError):
            reader.is_ignored(root, LOCAL)
        assert reader.errors == ["could not read repo/.gitignore: Permission denied"]
        assert str(tmp_path) not in reader.errors[0]

    def test_oversized_file_is_not_read(self, tmp_path: Path, home: Path) -> None:
        root = _repo(tmp_path)
        (root / ".gitignore").write_bytes(b"#" * (gi.MAX_FILE_BYTES + 1))
        reader = gi.IgnoreFileReader(home=home)
        with pytest.raises(gi.IgnoreStateUnknownError):
            reader.is_ignored(root, LOCAL)
        assert "larger than 1 MiB" in reader.errors[0]

    def test_budget_is_reported(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gi, "MAX_FILES", 1)
        root = _repo(tmp_path)
        (root / ".gitignore").write_text("a\n")
        (root / ".claude" / ".gitignore").write_text("b\n")
        reader = gi.IgnoreFileReader(home=home)
        with pytest.raises(gi.IgnoreStateUnknownError):
            reader.is_ignored(root, LOCAL)
        assert "budget reached" in reader.errors[0]

    def test_core_excludes_file_from_an_included_file(
        self, tmp_path: Path, home: Path
    ) -> None:
        root = _repo(tmp_path)
        (home / ".gitconfig").write_text("[include]\n\tpath = .gitconfig.local\n")
        (home / ".gitconfig.local").write_text("[core]\nexcludesFile = ~/.gi_inc\n")
        (home / ".gi_inc").write_text("**/.claude/settings.local.json\n")
        reader = gi.IgnoreFileReader(home=home)
        assert reader.is_ignored(root, LOCAL)
        assert reader.global_label == "~/.gi_inc"

    def test_include_targets_are_capped(self, tmp_path: Path, home: Path) -> None:
        root = _repo(tmp_path)
        lines = "".join(f"[include]\npath = inc{i}\n" for i in range(50))
        (home / ".gitconfig").write_text(lines)
        for i in range(50):
            (home / f"inc{i}").write_text(f"[core]\nexcludesFile = ~/gi{i}\n")
        reader = gi.IgnoreFileReader(home=home)
        reader.is_ignored(root, LOCAL)
        assert reader.global_label == f"~/gi{gi.MAX_INCLUDES - 1}"

    def test_matching_budget_makes_the_state_unknown(
        self, tmp_path: Path, home: Path
    ) -> None:
        root = _repo(tmp_path)
        (root / ".gitignore").write_text("\n".join(f"x{i}*" for i in range(100)))
        reader = gi.IgnoreFileReader(home=home, _meter=gi.MatchMeter(limit=50))
        with pytest.raises(gi.IgnoreStateUnknownError):
            reader.is_ignored(root, LOCAL)
        assert reader.errors == [
            "ignore-pattern matching budget reached (50 steps); this and later"
            " files were not checked"
        ]

    def test_files_are_read_once(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _repo(tmp_path)
        (root / ".gitignore").write_text("nothing\n")
        reader = gi.IgnoreFileReader(home=home)
        for _ in range(5):
            reader.is_ignored(root, LOCAL)
            reader.is_ignored(root, (".claude", "settings.json"))
        assert reader._files == 1  # only the root .gitignore exists


class TestWorkTreeRoot:
    def test_nearest_git_entry(self, tmp_path: Path) -> None:
        outer = tmp_path / "outer"
        inner = outer / "vendor" / "inner"
        (outer / ".git").mkdir(parents=True)
        (inner / ".git").mkdir(parents=True)
        (inner / "a" / "b").mkdir(parents=True)
        assert gi.find_work_tree_root(inner / "a" / "b") == inner
        assert gi.find_work_tree_root(outer / "vendor") == outer

    def test_none_outside_a_repository(self, tmp_path: Path) -> None:
        if gi.find_work_tree_root(tmp_path) is not None:
            pytest.skip("the temporary directory sits inside a git work tree")
        assert gi.find_work_tree_root(tmp_path / "a" / "b") is None

    def test_filesystem_error_ends_the_search(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(_path: object) -> bool:
            raise PermissionError(13, "denied")

        monkeypatch.setattr(gi.os.path, "lexists", boom)
        assert gi.find_work_tree_root(tmp_path) is None
