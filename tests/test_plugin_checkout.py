"""Tests for plugins/checkout.py — plugin pin vs the actual checkout (STORY-0096).

PLUGIN-003 compares a pinned plugin's checkout HEAD with the marketplace pin;
PLUGIN-004 reports SHA-shaped refs in a checkout (HIGH), a short pin (MEDIUM)
and a pinned source outside github.com (LOW).  TRUST-006/007 run on plugin and
marketplace checkouts.

Fixture checkouts are built by hand (files only, laid out as ``git clone`` +
``git checkout <sha>`` leaves them, and as the Plugin4Shell swap leaves them);
no test runs git.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.models import Finding, Severity
from mcp_audit.plugins import checkout as checkout_mod
from mcp_audit.plugins.analyzer import analyze_plugin_integrity
from mcp_audit.plugins.checkout import (
    analyze_plugin_pins,
    read_git_checkout,
    source_host,
)
from mcp_audit.plugins.discovery import discover_installed_plugins
from mcp_audit.plugins.models import InstalledPlugin

S = "af5b74e2dac50335a8202ff3ec5f09ef8bec63a5"  # the pin
A = "6e85f8f8e191e1a175f6d4e53b4cd9465ed9450b"  # the attacker's commit
N = "99bb6f4c695cb9268ab732cf77389af3bcc01de6"  # a newer pin
S256 = "ab" * 32
FAKE_GH_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105
_WINDOWS = os.name == "nt"

# ── Fixture builders ─────────────────────────────────────────────────────────


def _git(
    work: Path,
    head: str,
    *,
    loose: dict[str, str] | None = None,
    packed: dict[str, str] | None = None,
    config: str = "",
) -> Path:
    """Lay out ``work/.git`` as a clone leaves it (files only)."""
    g = work / ".git"
    (g / "objects").mkdir(parents=True)
    (g / "refs" / "heads").mkdir(parents=True)
    (g / "refs" / "tags").mkdir()
    (g / "hooks").mkdir()
    (g / "hooks" / "pre-commit.sample").write_text("#!/bin/sh\n")
    (g / "HEAD").write_text(head + "\n")
    (g / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        '[remote "origin"]\n\turl = https://github.com/acme/p.git\n'
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n" + config
    )
    for name, value in (loose or {}).items():
        path = g / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n")
    if packed:
        (g / "packed-refs").write_text(
            "# pack-refs with: peeled fully-peeled sorted \n"
            + "".join(f"{oid} {name}\n" for name, oid in packed.items())
        )
    return g


def _plugin(
    root: Path,
    name: str = "p",
    *,
    source: dict | str | None = None,
    version: str | None = None,
    git_commit_sha: str | None = None,
    manifest_version: str | None = None,
    entry_version: str | None = None,
    install_path: Path | None = None,
) -> InstalledPlugin:
    if source is None:
        source = {"source": "url", "url": "https://github.com/acme/p.git", "sha": S}
    return InstalledPlugin(
        plugin_id=f"{name}@mkt",
        name=name,
        marketplace="mkt",
        scope="user",
        project_path=None,
        install_path=install_path
        if install_path is not None
        else root / "cache" / "mkt" / name / (version or "v"),
        version=version,
        source=source,
        entry_version=entry_version,
        manifest_version=manifest_version,
        record_path=root / "installed_plugins.json",
        git_commit_sha=git_commit_sha,
    )


def _ids(findings: list[Finding]) -> list[tuple[str, str]]:
    return sorted((f.id, f.severity.value) for f in findings)


def _only(findings: list[Finding], fid: str) -> Finding:
    [f] = [x for x in findings if x.id == fid]
    return f


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "plugins"
    r.mkdir()
    return r


def _installed(root: Path, name: str = "p", version: str = "v") -> Path:
    path = root / "cache" / "mkt" / name / version
    path.mkdir(parents=True)
    return path


# ── Reading a checkout ───────────────────────────────────────────────────────


class TestReadCheckout:
    def test_detached_head(self, root: Path) -> None:
        work = _installed(root)
        _git(work, S)
        co = read_git_checkout(work, root=root)
        assert co is not None and co.located
        assert (co.head_ref, co.head_commit, co.unresolved) == (None, S, None)

    def test_attached_loose_and_packed(self, root: Path) -> None:
        work = _installed(root, "a")
        _git(work, "ref: refs/heads/main", loose={"refs/heads/main": A})
        co = read_git_checkout(work, root=root)
        assert (co.head_ref, co.head_commit) == ("refs/heads/main", A)
        work = _installed(root, "b")
        g = _git(work, "ref: refs/heads/main", packed={"refs/heads/main": A})
        # A peeled line and a comment are skipped, as git does.
        (g / "packed-refs").write_text(
            f"# pack-refs with: peeled\n{N} refs/tags/v1\n^{S}\n{A} refs/heads/main\n"
        )
        co = read_git_checkout(work, root=root)
        assert (co.head_ref, co.head_commit) == ("refs/heads/main", A)

    def test_upper_case_object_id_is_normalised(self, root: Path) -> None:
        work = _installed(root)
        _git(work, S.upper())
        assert read_git_checkout(work, root=root).head_commit == S

    def test_symref_chain_and_its_limit(self, root: Path) -> None:
        work = _installed(root, "a")
        _git(
            work,
            "ref: refs/heads/x",
            loose={"refs/heads/x": "ref: refs/heads/y", "refs/heads/y": A},
        )
        assert read_git_checkout(work, root=root).head_commit == A
        work = _installed(root, "b")
        chain = {f"refs/heads/c{i}": f"ref: refs/heads/c{i + 1}" for i in range(6)}
        _git(work, "ref: refs/heads/c0", loose=chain)
        co = read_git_checkout(work, root=root)
        assert co.head_commit is None and "longer than git allows" in co.unresolved

    def test_unborn_branch_and_malformed_head(self, root: Path) -> None:
        work = _installed(root, "a")
        _git(work, "ref: refs/heads/main")
        co = read_git_checkout(work, root=root)
        assert co.head_commit is None and "unborn" in co.unresolved
        work = _installed(root, "b")
        _git(work, "ref: refs/heads/main", loose={"refs/heads/main": "garbage"})
        co = read_git_checkout(work, root=root)
        assert co.head_commit is None and "not a commit id" in co.unresolved

    def test_unusual_ref_names_are_not_followed(self, root: Path) -> None:
        for i, target in enumerate(
            ["refs/heads/../../config", "refs/heads/a b", "HEAD", "refs/x\\y"]
        ):
            work = _installed(root, f"n{i}")
            _git(work, S)
            (work / ".git" / "HEAD").write_text(f"ref: {target}\n")
            co = read_git_checkout(work, root=root)
            # git's own repository test rejects some of these heads outright.
            assert co is None or (co.head_commit is None and co.unresolved)

    def test_no_git_or_invalid_git_dir_is_not_a_checkout(self, root: Path) -> None:
        work = _installed(root, "a")
        assert read_git_checkout(work, root=root) is None
        (work / ".git").mkdir()  # no HEAD/objects/refs: git skips it
        assert read_git_checkout(work, root=root) is None
        work = _installed(root, "b")
        (work / ".git").write_text("not a gitdir pointer\n")
        assert read_git_checkout(work, root=root) is None

    def test_gitdir_file_inside_and_outside_root(
        self, root: Path, tmp_path: Path
    ) -> None:
        inner = root / "gitdirs" / "p"
        inner.mkdir(parents=True)
        _git(inner, S)
        work = _installed(root, "a")
        (work / ".git").write_text(f"gitdir: {inner / '.git'}\n")
        co = read_git_checkout(work, root=root)
        assert co.located and co.head_commit == S
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        _git(outside, S)
        work = _installed(root, "b")
        (work / ".git").write_text(f"gitdir: {outside / '.git'}\n")
        co = read_git_checkout(work, root=root)
        assert not co.located and "outside the plugins root" in co.unresolved

    def test_symlinked_dot_git_is_not_followed(
        self, root: Path, tmp_path: Path
    ) -> None:
        real = tmp_path / "real"
        real.mkdir()
        _git(real, S)
        work = _installed(root)
        _symlink_or_skip(work / ".git", real / ".git")
        co = read_git_checkout(work, root=root)
        assert not co.located and "symbolic link" in co.unresolved

    @pytest.mark.skipif(_WINDOWS, reason="POSIX symlink semantics")
    def test_symlinked_head_is_read_as_a_legacy_symref(self, root: Path) -> None:
        work = _installed(root)
        g = _git(work, S, loose={"refs/heads/main": A})
        (g / "HEAD").unlink()
        _symlink_or_skip(g / "HEAD", Path("refs/heads/main"))
        co = read_git_checkout(work, root=root)
        assert (co.head_ref, co.head_commit) == ("refs/heads/main", A)

    def test_symlinked_ref_or_ref_dir_is_unverifiable(
        self, root: Path, tmp_path: Path
    ) -> None:
        elsewhere = tmp_path / "x"
        elsewhere.mkdir()
        (elsewhere / "main").write_text(S + "\n")
        work = _installed(root, "a")
        g = _git(work, "ref: refs/heads/main")
        _symlink_or_skip(g / "refs" / "heads" / "main", elsewhere / "main")
        co = read_git_checkout(work, root=root)
        assert co.head_commit is None and "symbolic link" in co.unresolved
        work = _installed(root, "b")
        g = _git(work, "ref: refs/heads/main")
        (g / "refs" / "heads").rmdir()
        _symlink_or_skip(g / "refs" / "heads", elsewhere)
        co = read_git_checkout(work, root=root)
        assert co.head_commit is None and "symbolic link" in co.unresolved
        assert co.refs_incomplete and "not followed" in co.refs_incomplete

    def test_permission_error_is_unverifiable_not_a_crash(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        work = _installed(root)
        g = _git(work, "ref: refs/heads/main", loose={"refs/heads/main": A})
        real_lstat = os.lstat

        def deny(path: object, *a: object, **k: object) -> os.stat_result:
            if str(path).endswith(os.path.join("refs", "heads", "main")):
                raise PermissionError(13, "Permission denied", str(path))
            return real_lstat(path, *a, **k)  # type: ignore[arg-type]

        monkeypatch.setattr(checkout_mod.os, "lstat", deny)
        co = read_git_checkout(work, root=root)
        assert co.head_commit is None and "could not be read" in co.unresolved
        assert g.exists()

    def test_oversize_files_and_spent_budget(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        work = _installed(root, "a")
        _git(work, "ref: refs/heads/main", loose={"refs/heads/main": A + " " * 8000})
        co = read_git_checkout(work, root=root)
        assert co.head_commit is None and "larger than this scan reads" in co.unresolved
        monkeypatch.setattr(checkout_mod, "_MAX_PACKED_REFS_BYTES", 64)
        work = _installed(root, "b")
        _git(
            work,
            "ref: refs/heads/main",
            packed={f"refs/heads/b{i}": N for i in range(10)} | {"refs/heads/main": A},
        )
        co = read_git_checkout(work, root=root)
        assert co.head_commit is None and "packed-refs" in co.unresolved
        assert co.refs_incomplete
        work = _installed(root, "c")
        _git(work, S)
        co = read_git_checkout(
            work, root=root, budget=checkout_mod._Budget(bytes_left=0)
        )
        assert co.head_commit is None and "budget" in co.unresolved

    def test_sha_shaped_refs_loose_and_packed(self, root: Path) -> None:
        work = _installed(root)
        _git(
            work,
            S,
            loose={
                f"refs/heads/{S}": A,
                f"refs/tags/{N}": A,
                "refs/remotes/origin/FETCH_HEAD": A,
                "refs/remotes/origin/HEAD": "ref: refs/remotes/origin/main",
                "refs/remotes/origin/main": A,
                f"refs/heads/feature/{S}": A,  # not a bare SHA name
                f"refs/heads/{S[:39]}": A,  # 39 hex
                f"refs/notes/{S}": A,  # not a branch, tag or remote branch
            },
            packed={f"refs/remotes/origin/{S256}": A, "refs/heads/FETCH_HEAD": A},
        )
        co = read_git_checkout(work, root=root)
        assert set(co.sha_shaped_refs) == {
            f"refs/heads/{S}",
            f"refs/tags/{N}",
            "refs/remotes/origin/FETCH_HEAD",
            f"refs/remotes/origin/{S256}",
            "refs/heads/FETCH_HEAD",
        }

    def test_reftable_checkout_is_named_not_guessed(self, root: Path) -> None:
        work = _installed(root)
        g = _git(work, "ref: refs/heads/.invalid")
        (g / "reftable").mkdir()
        (g / "reftable" / "tables.list").write_text(
            "0x000000000001-0x000000000001.ref\n"
        )
        co = read_git_checkout(work, root=root)
        assert co.head_commit is None and "reftable" in co.unresolved

    def test_loose_ref_walk_has_a_cap(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(checkout_mod, "_MAX_LOOSE_REFS", 5)
        work = _installed(root)
        _git(work, S, loose={f"refs/heads/b{i}": A for i in range(20)})
        co = read_git_checkout(work, root=root)
        assert co.head_commit == S and "more loose refs" in co.refs_incomplete

    def test_huge_packed_refs_and_hostile_strings_stay_linear(self, root: Path) -> None:
        work = _installed(root)
        g = _git(work, "ref: refs/heads/main")
        lines = "".join(f"{N} refs/heads/b{i}\n" for i in range(150_000))
        (g / "packed-refs").write_text(
            lines + "z" * 2_000_000 + f"\n{A} refs/heads/main\n"
        )
        start = time.monotonic()
        co = read_git_checkout(work, root=root)
        assert co.head_commit == A
        for hostile in ("a" * 1_000_000, "a@" * 300_000, "a:" * 300_000):
            source_host({"source": "url", "url": hostile})
        assert time.monotonic() - start < 10


# ── PLUGIN-003: HEAD against the pin ─────────────────────────────────────────


class TestPinVsCheckout:
    def test_head_at_the_pin_is_silent(self, root: Path) -> None:
        plugin = _plugin(root, version=S[:12], git_commit_sha=S)
        _git(plugin.install_path, S)
        assert analyze_plugin_pins([plugin], root=root) == []

    @pytest.mark.parametrize("recorded", [(S[:12], S), (A[:12], A), (S[:12], None)])
    def test_plugin4shell_branch_named_like_the_pin_is_critical(
        self, root: Path, recorded: tuple[str, str | None]
    ) -> None:
        version, sha = recorded
        plugin = _plugin(root, version=version, git_commit_sha=sha)
        _git(
            plugin.install_path,
            f"ref: refs/heads/{S}",
            loose={f"refs/heads/{S}": A},
            packed={f"refs/remotes/origin/{S}": A, "refs/remotes/origin/main": A},
        )
        findings = analyze_plugin_pins([plugin], root=root)
        assert _ids(findings) == [("PLUGIN-003", "CRITICAL"), ("PLUGIN-004", "HIGH")]
        crit = _only(findings, "PLUGIN-003")
        assert "named the pinned SHA" in crit.description
        assert (
            "Plugin4Shell" in crit.description and "did not run git" in crit.description
        )
        assert f"HEAD: refs/heads/{S} -> {A}" in crit.evidence
        assert "claude plugin disable p@mkt" in crit.remediation
        assert crit.cwe == "CWE-494" and crit.owasp_mcp_top_10 == ["MCP04"]
        assert crit.finding_path == str(plugin.install_path)
        high = _only(findings, "PLUGIN-004")
        assert f"refs/heads/{S}" in high.evidence
        assert f"refs/remotes/origin/{S}" in high.evidence

    def test_fetch_head_branch_and_other_sha_branch_are_critical(
        self, root: Path
    ) -> None:
        a = _plugin(root, "a", version=S[:12])
        _git(
            a.install_path,
            "ref: refs/heads/FETCH_HEAD",
            loose={"refs/heads/FETCH_HEAD": A},
        )
        b = _plugin(root, "b", version=A[:12])
        _git(b.install_path, f"ref: refs/heads/{N}", loose={f"refs/heads/{N}": A})
        findings = analyze_plugin_pins([a, b], root=root)
        crits = [f for f in findings if f.id == "PLUGIN-003"]
        assert {f.severity for f in crits} == {Severity.CRITICAL}
        assert "`FETCH_HEAD`" in _only(crits[:1], "PLUGIN-003").description
        assert (
            "a commit SHA" in [f for f in crits if f.server == "b@mkt"][0].description
        )

    @pytest.mark.parametrize(
        ("version", "sha"), [(S[:12], None), ("1.0.0", S)], ids=["version", "gitsha"]
    )
    def test_record_claims_the_pin_but_head_differs_is_critical(
        self, root: Path, version: str, sha: str | None
    ) -> None:
        plugin = _plugin(
            root,
            version=version,
            git_commit_sha=sha,
            manifest_version="1.0.0" if version == "1.0.0" else None,
        )
        _git(plugin.install_path, A)  # detached at another commit
        [f] = analyze_plugin_pins([plugin], root=root)
        assert (f.id, f.severity) == ("PLUGIN-003", Severity.CRITICAL)
        assert "record and the code on disk disagree" in f.description

    def test_pin_drift_matching_the_record_is_left_to_plugin_001(
        self, root: Path
    ) -> None:
        source = {"source": "github", "repo": "acme/p", "sha": N}
        plugin = _plugin(root, source=source, version=S[:12], git_commit_sha=S)
        _git(plugin.install_path, S)
        assert analyze_plugin_pins([plugin], root=root) == []
        assert [f.id for f in analyze_plugin_integrity([plugin])] == ["PLUGIN-001"]
        # A version string set: PLUGIN-001 is skipped, and gitCommitSha explains it.
        versioned = _plugin(
            root,
            "v",
            source=source,
            version="1.0.0",
            manifest_version="1.0.0",
            git_commit_sha=S,
        )
        _git(versioned.install_path, S)
        assert analyze_plugin_pins([versioned], root=root) == []

    def test_unexplained_difference_is_medium(self, root: Path) -> None:
        source = {"source": "github", "repo": "acme/p", "sha": N}
        plugin = _plugin(root, source=source, version="1.0.0", manifest_version="1.0.0")
        _git(plugin.install_path, S)
        [f] = analyze_plugin_pins([plugin], root=root)
        assert (f.id, f.severity) == ("PLUGIN-003", Severity.MEDIUM)
        assert "names no commit" in f.description
        assert "cannot tell which" in f.description

    def test_head_on_an_ordinary_branch_is_medium_even_if_recorded(
        self, root: Path
    ) -> None:
        plugin = _plugin(root, version=A[:12], git_commit_sha=A)
        _git(plugin.install_path, "ref: refs/heads/main", loose={"refs/heads/main": A})
        [f] = analyze_plugin_pins([plugin], root=root)
        assert (f.id, f.severity) == ("PLUGIN-003", Severity.MEDIUM)
        assert "HEAD is on branch `main`" in f.description
        assert "was not installed from the pin" in f.description

    def test_unresolvable_head_is_medium_for_a_pinned_plugin(self, root: Path) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(plugin.install_path, "ref: refs/heads/main")
        [f] = analyze_plugin_pins([plugin], root=root)
        assert (f.id, f.severity) == ("PLUGIN-003", Severity.MEDIUM)
        assert "could not be verified" in f.title and "unborn" in f.evidence

    def test_sha256_checkout_cannot_be_compared(self, root: Path) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(plugin.install_path, S256)
        [f] = analyze_plugin_pins([plugin], root=root)
        assert (f.id, f.severity) == ("PLUGIN-003", Severity.MEDIUM)
        assert "SHA-256" in f.description

    def test_unpinned_or_non_git_plugins_get_no_pin_verdict(self, root: Path) -> None:
        errors: list[str] = []
        unpinned = _plugin(root, "u", source={"source": "github", "repo": "a/b"})
        _git(
            unpinned.install_path, "ref: refs/heads/main", loose={"refs/heads/main": A}
        )
        broken = _plugin(root, "b", source={"source": "github", "repo": "a/b"})
        _git(broken.install_path, "ref: refs/heads/main")
        relative = _plugin(root, "r", source="./plugins/r")
        _git(
            relative.install_path,
            f"ref: refs/heads/{S}",
            loose={f"refs/heads/{S}": A},
        )
        findings = analyze_plugin_pins(
            [unpinned, broken, relative], root=root, errors=errors
        )
        assert findings == []
        assert any("unborn" in e for e in errors)

    def test_git_subdir_uses_the_recorded_commit_not_the_version(
        self, root: Path
    ) -> None:
        source = {"source": "git-subdir", "url": "acme/mono", "path": "p", "sha": S}
        drift = _plugin(
            root, "d", source=source, version=A[:12] + "abcd", git_commit_sha=A
        )
        _git(drift.install_path, A)
        claims = _plugin(root, "c", source=source, version="x", git_commit_sha=S)
        _git(claims.install_path, A)
        findings = analyze_plugin_pins([drift, claims], root=root)
        assert [(f.server, f.severity) for f in findings] == [
            ("c@mkt", Severity.CRITICAL)
        ]


# ── PLUGIN-004: the update channel ───────────────────────────────────────────


class TestShapedRefs:
    def test_shaped_refs_fire_for_git_sources_pinned_or_not(self, root: Path) -> None:
        pinned = _plugin(root, "a", version=S[:12])
        _git(pinned.install_path, S, packed={f"refs/remotes/origin/{N}": A})
        unpinned = _plugin(root, "b", source={"source": "github", "repo": "a/b"})
        _git(unpinned.install_path, A, loose={"refs/heads/FETCH_HEAD": A})
        findings = analyze_plugin_pins([pinned, unpinned], root=root)
        assert _ids(findings) == [("PLUGIN-004", "HIGH"), ("PLUGIN-004", "HIGH")]
        assert "pins this plugin to" in _only(findings[:1], "PLUGIN-004").description

    def test_many_refs_are_summarised(self, root: Path) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(
            plugin.install_path, S, loose={f"refs/tags/{i:040x}": A for i in range(14)}
        )
        f = _only(analyze_plugin_pins([plugin], root=root), "PLUGIN-004")
        assert "holds 14 ref(s)" in f.description and "and 4 more" in f.evidence


class TestPosture:
    def test_short_sha_is_medium_and_plugin_002_still_fires(self, root: Path) -> None:
        plugin = _plugin(root, source={"source": "github", "repo": "a/b", "sha": S[:7]})
        f = _only(analyze_plugin_pins([plugin], root=root), "PLUGIN-004")
        assert f.severity == Severity.MEDIUM and repr(S[:7]) in f.evidence
        assert "ref name first" in f.description
        assert [x.id for x in analyze_plugin_integrity([plugin])] == ["PLUGIN-002"]

    @pytest.mark.parametrize("sha", [12345, ["x"], "z" * 40, S + "0"])
    def test_other_invalid_pins_are_medium(self, root: Path, sha: object) -> None:
        plugin = _plugin(
            root, source={"source": "url", "url": "https://github.com/a/b", "sha": sha}
        )
        assert _ids(analyze_plugin_pins([plugin], root=root)) == [
            ("PLUGIN-004", "MEDIUM")
        ]

    @pytest.mark.parametrize("sha", [None, "", "  "])
    def test_no_pin_is_left_to_plugin_002(self, root: Path, sha: object) -> None:
        source = {"source": "url", "url": "https://gitlab.com/a/b"}
        if sha is not None:
            source["sha"] = sha
        assert analyze_plugin_pins([_plugin(root, source=source)], root=root) == []

    def test_upper_case_full_sha_is_a_full_pin(self, root: Path) -> None:
        plugin = _plugin(
            root, source={"source": "github", "repo": "a/b", "sha": S.upper()}
        )
        assert analyze_plugin_pins([plugin], root=root) == []

    @pytest.mark.parametrize(
        "source",
        [
            {"source": "github", "repo": "acme/p"},
            {"source": "url", "url": "https://github.com/acme/p.git"},
            {"source": "url", "url": "https://GitHub.COM:443/acme/p"},
            {"source": "url", "url": "git@github.com:acme/p.git"},
            {"source": "url", "url": "ssh://git@github.com/acme/p.git"},
            {"source": "url", "url": "https://user@github.com/acme/p.git"},
            {"source": "git-subdir", "url": "acme/mono", "path": "p"},
            {"source": "git-subdir", "url": "https://github.com/acme/mono.git"},
        ],
    )
    def test_github_hosts_are_silent(self, root: Path, source: dict) -> None:
        source = source | {"sha": S}
        assert analyze_plugin_pins([_plugin(root, source=source)], root=root) == []

    @pytest.mark.parametrize(
        ("url", "host"),
        [
            ("https://gitlab.com/acme/p.git", "gitlab.com"),
            ("git@bitbucket.org:acme/p.git", "bitbucket.org"),
            ("https://github.com.evil.example/p", "github.com.evil.example"),
            ("https://github.com@evil.example/p", "evil.example"),
            ("https://evil.example\\@github.com/p", ""),
            ("https://www.github.com/acme/p", "www.github.com"),
            ("https://[::1]/p", ""),
            ("file:///srv/git/p", ""),
            ("C:\\repos\\p", ""),
            ("acme/p", ""),  # owner/repo shorthand is not valid for `url`
        ],
    )
    def test_other_hosts_are_low(self, root: Path, url: str, host: str) -> None:
        source = {"source": "url", "url": url, "sha": S}
        assert source_host(source)[0] == host
        f = _only(
            analyze_plugin_pins([_plugin(root, source=source)], root=root), "PLUGIN-004"
        )
        assert f.severity == Severity.LOW
        assert "2.1.179" in f.description

    def test_credentials_in_the_url_never_reach_the_report(self, root: Path) -> None:
        source = {
            "source": "url",
            "url": f"https://bob:{FAKE_GH_TOKEN}@gitlab.example/p.git?t={FAKE_GH_TOKEN}",
            "sha": S,
        }
        f = _only(
            analyze_plugin_pins([_plugin(root, source=source)], root=root), "PLUGIN-004"
        )
        text = f.model_dump_json()
        assert FAKE_GH_TOKEN not in text and "bob" not in text
        assert "https://gitlab.example/p.git" in f.evidence

    def test_posture_once_per_plugin_id(self, root: Path) -> None:
        source = {"source": "url", "url": "https://gitlab.com/a/b", "sha": S}
        records = [_plugin(root, source=source, version=f"v{i}") for i in range(3)]
        assert len(analyze_plugin_pins(records, root=root)) == 1


# ── TRUST-006/007 on plugin and marketplace checkouts ────────────────────────


class TestGitChecksOnCheckouts:
    def test_plugin_checkout_config_is_checked(self, root: Path) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(plugin.install_path, S, config="[core]\n\tfsmonitor = ./evil.sh\n")
        findings = analyze_plugin_pins([plugin], root=root)
        assert ("TRUST-006", "HIGH") in _ids(findings)

    def test_marketplace_clones_are_checked(self, root: Path) -> None:
        bad = root / "marketplaces" / "bad"
        bad.mkdir(parents=True)
        _git(
            bad,
            "ref: refs/heads/main",
            loose={"refs/heads/main": A},
            config='[core]\n\tsshCommand = "ssh -o ProxyCommand=evil"\n',
        )
        clean = root / "marketplaces" / "clean"
        clean.mkdir()
        _git(clean, "ref: refs/heads/main", loose={"refs/heads/main": A})
        (root / "marketplaces" / "tarball").mkdir()  # no .git (a GCS drop)
        findings = analyze_plugin_pins([], root=root)
        assert [(f.id, f.severity.value) for f in findings] == [("TRUST-006", "HIGH")]
        assert str(bad) in findings[0].finding_path

    def test_symlinked_marketplace_or_dot_git_is_not_read(
        self, root: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        _git(outside, S, config="[core]\n\tfsmonitor = ./evil.sh\n")
        (root / "marketplaces").mkdir()
        _symlink_or_skip(root / "marketplaces" / "linked", outside)
        dotgit = root / "marketplaces" / "dotgit"
        dotgit.mkdir()
        _symlink_or_skip(dotgit / ".git", outside / ".git")
        errors: list[str] = []
        assert analyze_plugin_pins([], root=root, errors=errors) == []
        assert any("linked" in e and "symbolic link" in e for e in errors)
        assert any("dotgit" in e and "symbolic link" in e for e in errors)

    def test_unlistable_marketplaces_dir_is_reported_not_raised(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (root / "marketplaces").mkdir()
        real_listdir = os.listdir

        def deny(path: object) -> list[str]:
            if str(path).endswith("marketplaces"):
                raise PermissionError(13, "Permission denied", str(path))
            return real_listdir(path)  # type: ignore[arg-type]

        monkeypatch.setattr(checkout_mod.os, "listdir", deny)
        errors: list[str] = []
        assert analyze_plugin_pins([], root=root, errors=errors) == []
        assert any("could not be listed" in e for e in errors)


class TestRootAndSymlinks:
    def test_install_path_outside_root_is_skipped_silently(
        self, root: Path, tmp_path: Path
    ) -> None:
        local = tmp_path / "my-plugin"
        local.mkdir()
        _git(
            local,
            "ref: refs/heads/main",
            loose={"refs/heads/main": A},
            config="[core]\n\tfsmonitor = ./x\n",
        )
        plugin = _plugin(root, install_path=local, version=S[:12])
        errors: list[str] = []
        assert analyze_plugin_pins([plugin], root=root, errors=errors) == []
        assert errors == []

    def test_symlinked_directory_under_root_is_not_followed(
        self, root: Path, tmp_path: Path
    ) -> None:
        elsewhere = tmp_path / "elsewhere" / "p" / "v"
        elsewhere.mkdir(parents=True)
        _git(elsewhere, f"ref: refs/heads/{S}", loose={f"refs/heads/{S}": A})
        (root / "cache").mkdir()
        _symlink_or_skip(root / "cache" / "mkt", tmp_path / "elsewhere")
        plugin = _plugin(
            root, version=S[:12], install_path=root / "cache" / "mkt" / "p" / "v"
        )
        errors: list[str] = []
        assert analyze_plugin_pins([plugin], root=root, errors=errors) == []
        assert any("symbolic link; not followed" in e for e in errors)

    def test_symlinked_plugins_root_is_followed(self, tmp_path: Path) -> None:
        real_root = tmp_path / "dotfiles" / "plugins"
        real_root.mkdir(parents=True)
        link = tmp_path / "plugins-link"
        _symlink_or_skip(link, real_root)
        plugin = _plugin(link, version=S[:12])
        _git(plugin.install_path, f"ref: refs/heads/{S}", loose={f"refs/heads/{S}": A})
        assert ("PLUGIN-003", "CRITICAL") in _ids(
            analyze_plugin_pins([plugin], root=link)
        )

    def test_records_sharing_an_install_path_are_checked_once(self, root: Path) -> None:
        a = _plugin(root, version=S[:12])
        _git(a.install_path, f"ref: refs/heads/{S}", loose={f"refs/heads/{S}": A})
        b = _plugin(root, version=S[:12])
        assert _ids(analyze_plugin_pins([a, b], root=root)) == [
            ("PLUGIN-003", "CRITICAL"),
            ("PLUGIN-004", "HIGH"),
        ]


# ── Wiring: default scan, check, plugins scan ────────────────────────────────


def _write_root(root: Path) -> Path:
    """A plugins root, laid out as Claude Code writes it, with a swapped plugin."""
    mkt = root / "marketplaces" / "mkt"
    (mkt / ".claude-plugin").mkdir(parents=True)
    (mkt / ".claude-plugin" / "marketplace.json").write_text(
        json.dumps(
            {
                "name": "mkt",
                "owner": {"name": "t"},
                "plugins": [
                    {
                        "name": "p",
                        "source": {
                            "source": "url",
                            "url": f"https://bob:{FAKE_GH_TOKEN}@git.example/p.git",
                            "sha": S,
                        },
                    }
                ],
            }
        )
    )
    install = root / "cache" / "mkt" / "p" / S[:12]
    install.mkdir(parents=True)
    _git(install, f"ref: refs/heads/{S}", loose={f"refs/heads/{S}": A})
    (root / "installed_plugins.json").write_text(
        json.dumps(
            {
                "version": 2,
                "plugins": {
                    "p@mkt": [
                        {
                            "scope": "user",
                            "installPath": str(install),
                            "version": S[:12],
                            "gitCommitSha": S,
                        }
                    ]
                },
            }
        )
    )
    (root / "known_marketplaces.json").write_text(
        json.dumps(
            {
                "mkt": {
                    "source": {"source": "github", "repo": "a/mkt"},
                    "installLocation": str(mkt),
                }
            }
        )
    )
    return install


class TestWiring:
    @pytest.fixture
    def scan_env(
        self, root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> Path:
        _write_root(root)
        monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(root))
        monkeypatch.setattr("mcp_audit.discovery._home", lambda: tmp_path / "home")
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("mcp_audit.analyzers.rug_pull._STATE_DIR", tmp_path / "st")
        monkeypatch.setattr(
            "mcp_audit.analyzers.rug_pull.DEFAULT_STATE_PATH",
            tmp_path / "st" / "s.json",
        )
        return root

    def test_discovery_reads_git_commit_sha(self, scan_env: Path) -> None:
        [plugin] = discover_installed_plugins(scan_env)
        assert plugin.git_commit_sha == S

    def test_default_scan_reports_and_scores_it(
        self, scan_env: Path, tmp_path: Path
    ) -> None:
        from mcp_audit.scanner import run_scan

        result = run_scan(skip_rug_pull=True)
        got = sorted(
            (f.id, f.severity.value)
            for f in result.findings
            if f.id.startswith("PLUGIN")
        )
        assert got == [
            ("PLUGIN-003", "CRITICAL"),
            ("PLUGIN-004", "HIGH"),
            ("PLUGIN-004", "LOW"),
        ]
        assert result.score is not None and result.score.numeric_score < 100
        for kwargs in (
            {"include_plugins": False},
            {"extra_paths": [tmp_path / "x.json"]},
        ):
            (tmp_path / "x.json").write_text('{"mcpServers": {}}')
            other = run_scan(skip_rug_pull=True, **kwargs)  # type: ignore[arg-type]
            assert not [f for f in other.findings if f.id.startswith("PLUGIN")]

    def test_a_crash_in_the_pin_check_is_recorded_not_fatal(
        self, scan_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan

        def boom(*_a: object, **_k: object) -> list[Finding]:
            raise RuntimeError("synthetic")

        monkeypatch.setattr(checkout_mod, "analyze_plugin_pins", boom)
        result = run_scan(skip_rug_pull=True)
        assert any("plugin checkout check error" in e for e in result.errors)

    def test_check_exits_1_and_outputs_are_redacted(
        self, scan_env: Path, tmp_path: Path
    ) -> None:
        from mcp_audit.cli import app

        runner = CliRunner()
        out = runner.invoke(app, ["check"])
        assert out.exit_code == 1, out.output
        text = " ".join(out.output.split())
        assert (
            "[CRITICAL] Plugin checkout is not the commit its marketplace pins" in text
        )
        # check's hint is the finding's own first remediation sentence.
        assert "claude plugin disable p@mkt" in text
        for fmt in ("terminal", "json", "sarif"):
            report = tmp_path / f"r.{fmt}"
            args = ["scan", "--offline", "--format", fmt]
            if fmt != "terminal":
                args += ["-o", str(report)]
            res = runner.invoke(app, args)
            assert res.exit_code == 1, res.output
            text = res.output + (report.read_text() if fmt != "terminal" else "")
            assert ("PLUGIN-003" in text) or (
                fmt == "terminal" and "Plugin checkout is not the commit" in text
            )
            assert FAKE_GH_TOKEN not in text and "bob:" not in text

    def test_plugins_discover_shows_the_recorded_commit(self, scan_env: Path) -> None:
        from mcp_audit.cli import app

        out = CliRunner().invoke(app, ["plugins", "discover", "--format", "json"])
        assert out.exit_code == 0, out.output
        [row] = json.loads(out.output)
        assert (row["pinned_sha"], row["git_commit_sha"]) == (S, S)

    def test_advisory_class(self) -> None:
        from mcp_audit.advisory.classify import finding_class_for, is_advisable

        for fid in ("PLUGIN-003", "PLUGIN-004"):
            assert finding_class_for(fid) == "unverified-provenance"
            assert is_advisable(fid)

    def test_plugins_scan_reports_it(self, scan_env: Path) -> None:
        from mcp_audit.cli import app

        out = CliRunner().invoke(app, ["plugins", "scan", "--format", "json"])
        assert out.exit_code == 1, out.output
        ids = {f["id"] for f in json.loads(out.output)}
        assert {"PLUGIN-003", "PLUGIN-004"} <= ids

    def test_no_process_is_started(
        self, scan_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def trap(*_a: object, **_k: object) -> None:
            raise AssertionError("a process was started")

        for name in ("run", "Popen", "call", "check_call", "check_output"):
            monkeypatch.setattr(subprocess, name, trap)
        for name in ("system", "popen", "execv", "execvp", "spawnv"):
            monkeypatch.setattr(os, name, trap, raising=False)
        findings = analyze_plugin_pins(
            discover_installed_plugins(scan_env), root=scan_env
        )
        assert ("PLUGIN-003", "CRITICAL") in _ids(findings)

    def test_demo_configs_produce_no_new_ids(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan

        demo = Path(__file__).resolve().parents[1] / "demo" / "configs"
        result = run_scan(extra_paths=sorted(demo.glob("*.json")), skip_rug_pull=True)
        assert not [f for f in result.findings if f.id in ("PLUGIN-003", "PLUGIN-004")]


# ── Review fixes: swap shape beats "unverifiable" ────────────────────────────


class TestSwapShapeBeatsUnverifiable:
    def test_sha256_repo_attached_to_the_pin_named_branch_is_critical(
        self, root: Path
    ) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(
            plugin.install_path,
            f"ref: refs/heads/{S}",
            loose={f"refs/heads/{S}": S256},
        )
        [f, *_] = [
            x for x in analyze_plugin_pins([plugin], root=root) if x.id == "PLUGIN-003"
        ]
        assert f.severity == Severity.CRITICAL
        assert "Plugin4Shell" in f.description

    def test_unborn_swap_branch_is_critical(self, root: Path) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(plugin.install_path, f"ref: refs/heads/{S}")  # no ref file at all
        findings = analyze_plugin_pins([plugin], root=root)
        assert ("PLUGIN-003", "CRITICAL") in _ids(findings)

    def test_swap_name_further_down_a_symref_chain_is_critical(
        self, root: Path
    ) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(
            plugin.install_path,
            "ref: refs/heads/a",
            loose={
                "refs/heads/a": "ref: refs/heads/b",
                "refs/heads/b": f"ref: refs/heads/{S}",
                f"refs/heads/{S}": A,
            },
        )
        findings = analyze_plugin_pins([plugin], root=root)
        f = _only(findings, "PLUGIN-003")
        assert f.severity == Severity.CRITICAL
        assert "further down HEAD's chain" in f.description
        checkout = read_git_checkout(plugin.install_path, root=root)
        assert checkout is not None
        assert checkout.head_chain == (
            "refs/heads/a",
            "refs/heads/b",
            f"refs/heads/{S}",
        )

    def test_chain_without_a_swap_name_stays_medium_when_unresolved(
        self, root: Path
    ) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(
            plugin.install_path,
            "ref: refs/heads/a",
            loose={"refs/heads/a": "ref: refs/heads/b"},
        )
        [f] = analyze_plugin_pins([plugin], root=root)
        assert (f.id, f.severity) == ("PLUGIN-003", Severity.MEDIUM)

    def test_fetch_head_branch_with_foreign_hash_length_is_critical(
        self, root: Path
    ) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(
            plugin.install_path,
            "ref: refs/heads/FETCH_HEAD",
            loose={"refs/heads/FETCH_HEAD": S256},
        )
        assert ("PLUGIN-003", "CRITICAL") in _ids(
            analyze_plugin_pins([plugin], root=root)
        )


class TestShortPin:
    def test_short_pin_swap_is_critical_when_the_branch_is_the_pin(
        self, root: Path
    ) -> None:
        source = {"source": "github", "repo": "acme/p", "sha": S[:7]}
        plugin = _plugin(root, source=source, version="1.0.0")
        _git(
            plugin.install_path,
            f"ref: refs/heads/{S[:7]}",
            loose={f"refs/heads/{S[:7]}": A},
        )
        findings = analyze_plugin_pins([plugin], root=root)
        assert ("PLUGIN-003", "CRITICAL") in _ids(findings)
        assert ("PLUGIN-004", "MEDIUM") in _ids(findings)

    def test_short_pin_is_compared_as_a_prefix(self, root: Path) -> None:
        source = {"source": "github", "repo": "acme/p", "sha": S[:9].upper()}
        good = _plugin(root, "g", source=source, version="1.0.0")
        _git(good.install_path, S)
        bad = _plugin(root, "b", source=source, version="1.0.0")
        _git(bad.install_path, A)
        findings = analyze_plugin_pins([good, bad], root=root)
        [f] = [x for x in findings if x.id == "PLUGIN-003"]
        assert f.server == "b@mkt" and f.severity == Severity.MEDIUM


# ── Review fixes: NUL bytes, '..', FIFOs ─────────────────────────────────────


class TestHostileInputs:
    def test_nul_in_install_path_does_not_stop_a_later_swap(self, root: Path) -> None:
        nul = _plugin(root, "n", install_path=root / "cache" / "x\x00y")
        swapped = _plugin(root, "s", version=S[:12])
        _git(
            swapped.install_path,
            f"ref: refs/heads/{S}",
            loose={f"refs/heads/{S}": A},
        )
        errors: list[str] = []
        findings = analyze_plugin_pins([nul, swapped], root=root, errors=errors)
        assert ("PLUGIN-003", "CRITICAL") in _ids(findings)
        assert all("\x00" not in e for e in errors)

    def test_nul_in_a_dot_git_file_does_not_stop_a_later_swap(self, root: Path) -> None:
        bad = _plugin(root, "n", version="v1")
        bad.install_path.mkdir(parents=True)
        (bad.install_path / ".git").write_text("gitdir: ../x\x00y\n")
        swapped = _plugin(root, "s", version=S[:12])
        _git(
            swapped.install_path,
            f"ref: refs/heads/{S}",
            loose={f"refs/heads/{S}": A},
        )
        findings = analyze_plugin_pins([bad, swapped], root=root, errors=[])
        assert ("PLUGIN-003", "CRITICAL") in _ids(findings)

    def test_one_record_raising_is_recorded_and_the_rest_continue(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = _plugin(root, "f", version="v1")
        swapped = _plugin(root, "s", version=S[:12])
        _git(
            swapped.install_path,
            f"ref: refs/heads/{S}",
            loose={f"refs/heads/{S}": A},
        )
        real = checkout_mod._checkout_at

        def flaky(path: Path | None, *a: object, **k: object):  # type: ignore[no-untyped-def]
            if path == first.install_path:
                raise ValueError("embedded null byte")
            return real(path, *a, **k)  # type: ignore[arg-type]

        monkeypatch.setattr(checkout_mod, "_checkout_at", flaky)
        errors: list[str] = []
        findings = analyze_plugin_pins([first, swapped], root=root, errors=errors)
        assert ("PLUGIN-003", "CRITICAL") in _ids(findings)
        assert any("not checked: ValueError" in e for e in errors)

    def test_a_broken_marketplace_clone_does_not_stop_the_scan(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (root / "marketplaces" / "m1").mkdir(parents=True)
        (root / "marketplaces" / "m2").mkdir(parents=True)
        real = checkout_mod._checkout_at

        def flaky(path: Path | None, *a: object, **k: object):  # type: ignore[no-untyped-def]
            if path is not None and path.name == "m1":
                raise RuntimeError("synthetic")
            return real(path, *a, **k)  # type: ignore[arg-type]

        monkeypatch.setattr(checkout_mod, "_checkout_at", flaky)
        errors: list[str] = []
        assert analyze_plugin_pins([], root=root, errors=errors) == []
        assert any("m1" in e and "not checked" in e for e in errors)

    def test_plugins_scan_survives_a_crash_in_the_pin_check(
        self,
        root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mcp_audit.cli import app

        _write_root(root)
        monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(root))
        monkeypatch.setattr("mcp_audit.discovery._home", lambda: tmp_path / "home")
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.chdir(tmp_path)

        def boom(*_a: object, **_k: object) -> list[Finding]:
            raise OSError("synthetic")

        monkeypatch.setattr(checkout_mod, "analyze_plugin_pins", boom)
        out = CliRunner().invoke(app, ["plugins", "scan"])
        assert not isinstance(out.exception, OSError), out.output
        assert "plugin pin check failed" in out.output

    def test_nul_in_a_record_through_the_cli_does_not_traceback(
        self, root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.cli import app

        install = _write_root(root)
        record = json.loads((root / "installed_plugins.json").read_text())
        record["plugins"]["n@mkt"] = [
            {"scope": "user", "installPath": str(root / "cache" / "x\x00y")}
        ]
        (root / "installed_plugins.json").write_text(json.dumps(record))
        monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(root))
        monkeypatch.setattr("mcp_audit.discovery._home", lambda: tmp_path / "home")
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.chdir(tmp_path)
        out = CliRunner().invoke(app, ["plugins", "scan", "--format", "json"])
        assert out.exception is None or isinstance(out.exception, SystemExit)
        assert out.exit_code == 1, out.output
        assert any(f["id"] == "PLUGIN-003" for f in json.loads(out.output))
        assert install.exists()

    def test_dotdot_install_path_is_rejected(self, root: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        _git(outside, f"ref: refs/heads/{S}", loose={f"refs/heads/{S}": A})
        (root / "a").mkdir()
        sneaky = root / "a" / ".." / ".." / "outside"
        plugin = _plugin(root, version=S[:12], install_path=sneaky)
        errors: list[str] = []
        assert analyze_plugin_pins([plugin], root=root, errors=errors) == []
        assert any("'..'" in e for e in errors)

    @pytest.mark.skipif(_WINDOWS, reason="needs mkfifo")
    def test_fifo_named_like_a_git_file_does_not_hang(self, root: Path) -> None:
        plugin = _plugin(root, version=S[:12])
        _git(plugin.install_path, S)
        (plugin.install_path / ".git" / "commondir").unlink(missing_ok=True)
        os.mkfifo(plugin.install_path / ".git" / "commondir")
        started = time.monotonic()
        analyze_plugin_pins([plugin], root=root, errors=[])
        assert time.monotonic() - started < 5


# ── Review fixes: nothing from a URL's query, fragment or scp userinfo ───────


class TestSourceHostRedaction:
    @pytest.mark.parametrize(
        ("url", "host", "secret"),
        [
            (
                "https://git.example/p.git?private_token=QUERYTOK99#fragSECRET",
                "git.example",
                "QUERYTOK99",
            ),
            ("https://git.example?private_token=QUERYTOK99", "git.example", "QUERY"),
            ("https://git.example#fragSECRET", "git.example", "fragSECRET"),
            ("git:scppw77@git.example:org/p.git", "git.example", "scppw77"),
            ("git@git.example:org/p.git?x=scppw77", "git.example", "scppw77"),
        ],
    )
    def test_secrets_never_reach_the_location(
        self, url: str, host: str, secret: str
    ) -> None:
        got_host, location = source_host({"source": "url", "url": url})
        assert got_host == host
        assert secret not in location and "fragSECRET" not in location
        assert "?" not in location and "#" not in location

    def test_secrets_never_reach_the_report(self, root: Path) -> None:
        urls = (
            "https://git.example/p.git?private_token=QUERYTOK99#fragSECRET",
            "git:scppw77@git.example:org/p.git",
        )
        plugins = [
            _plugin(root, f"u{i}", source={"source": "url", "url": u, "sha": S})
            for i, u in enumerate(urls)
        ]
        findings = analyze_plugin_pins(plugins, root=root)
        assert len(findings) == 2
        blob = json.dumps([f.model_dump(mode="json") for f in findings])
        for secret in ("QUERYTOK99", "fragSECRET", "scppw77"):
            assert secret not in blob
