"""Read-only git object store reader (STORY-0153): parity with git, hostile input."""

from __future__ import annotations

import shutil
import subprocess
import zlib
from pathlib import Path

import pytest

from mcp_audit._gitobjects import (
    MAX_OBJECT_BYTES,
    BudgetExceededError,
    GitObjectError,
    ObjectStore,
    ReadBudget,
    apply_delta,
    inflate,
    parse_commit,
    tree_entries,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _make_repo(tmp_path: Path, commits: int = 30) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / ".claude").mkdir()
    for i in range(commits):
        # Mostly-shared content makes git store later versions as deltas.
        body = "\n".join(f"line {j} of a long settings file" for j in range(200))
        (repo / ".claude" / "settings.json").write_text(f"{body}\nversion {i}\n")
        (repo / f"f{i}.txt").write_text(str(i))
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", f"c{i}")
    _git(repo, "tag", "-a", "v1", "-m", "tag")
    return repo


def _all_objects(repo: Path) -> list[tuple[str, str]]:
    out = _git(repo, "cat-file", "--batch-all-objects", "--batch-check")
    return [(line.split()[0], line.split()[1]) for line in out.splitlines()]


def _assert_parity(repo: Path) -> int:
    git_dir = repo / ".git"
    store = ObjectStore(git_dir, git_dir, ReadBudget())
    objects = _all_objects(repo)
    with store:
        for oid, kind in objects:
            want = subprocess.run(
                ["git", "-C", str(repo), "cat-file", kind, oid],
                check=True,
                capture_output=True,
            ).stdout
            found = store.read(oid)
            assert found == (kind, want), oid
    return len(objects)


class TestParityWithGit:
    def test_loose_objects(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, commits=5)
        assert _assert_parity(repo) > 10

    def test_packed_objects_with_ofs_deltas(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        _git(repo, "repack", "-adq", "--depth=50", "--window=50")
        assert not any((repo / ".git" / "objects").glob("??/*"))
        assert _assert_parity(repo) > 60

    def test_packed_objects_with_ref_deltas(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        # A thin pack would be needed for cross-pack REF_DELTA; pack-objects
        # writes REF_DELTA when asked not to use offsets.
        objects = "\n".join(oid for oid, _ in _all_objects(repo)) + "\n"
        pack_dir = repo / ".git" / "objects" / "pack"
        pack_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "pack-objects",
                "--no-delta-base-offset",
                "--depth=50",
                "--window=50",
                str(pack_dir / "pack"),
            ],
            input=objects,
            text=True,
            check=True,
            capture_output=True,
        )
        _git(repo, "prune-packed")
        assert _assert_parity(repo) > 60

    def test_ref_tips_include_branches_tags_and_head(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, commits=3)
        _git(repo, "branch", "side", "HEAD~1")
        _git(repo, "pack-refs", "--all")
        git_dir = repo / ".git"
        store = ObjectStore(git_dir, git_dir, ReadBudget())
        tips = set(store.ref_tips())
        assert _git(repo, "rev-parse", "HEAD").strip() in tips
        assert _git(repo, "rev-parse", "side").strip() in tips
        assert _git(repo, "rev-parse", "v1").strip() in tips  # the tag object

    def test_missing_object_reads_as_none(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, commits=1)
        git_dir = repo / ".git"
        store = ObjectStore(git_dir, git_dir, ReadBudget())
        assert store.read("0" * 40) is None
        assert store.missing == 1


class TestHostileInput:
    def test_inflate_stops_at_the_declared_size(self) -> None:
        bomb = zlib.compress(b"\0" * (8 * 1024 * 1024))
        budget = ReadBudget()
        assert inflate(bomb, 100, budget) == b"\0" * 100
        assert budget.used == 100

    def test_stream_shorter_than_declared_raises(self) -> None:
        with pytest.raises(GitObjectError):
            inflate(zlib.compress(b"abc"), 10, ReadBudget())

    def test_oversized_declaration_is_refused(self) -> None:
        with pytest.raises(GitObjectError):
            inflate(b"", MAX_OBJECT_BYTES + 1, ReadBudget())

    def test_budget_runs_out(self) -> None:
        data = zlib.compress(b"x" * 1000)
        budget = ReadBudget(limit=1500)
        inflate(data, 1000, budget)
        with pytest.raises(BudgetExceededError):
            inflate(data, 1000, budget)

    @pytest.mark.parametrize(
        "delta",
        [
            b"\x05\x05\x91\x00\x10",  # copy past the end of the base
            b"\x05\x05\x00",  # reserved opcode
            b"\x05\x09\x04abcd",  # result shorter than declared
            b"\x06\x05",  # wrong base size
            b"\x05",  # truncated header
            b"\x05\x02\x05abcde",  # result longer than declared
        ],
    )
    def test_bad_deltas_raise(self, delta: bytes) -> None:
        with pytest.raises(GitObjectError):
            apply_delta(b"hello", delta)

    def test_good_delta(self) -> None:
        # copy 5 bytes from offset 0, then insert "!"
        assert apply_delta(b"hello", b"\x05\x06\x90\x05\x01!") == b"hello!"

    def test_corrupt_index_is_reported_not_raised(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, commits=3)
        _git(repo, "repack", "-adq")
        idx = next((repo / ".git" / "objects" / "pack").glob("*.idx"))
        idx.write_bytes(b"\xfftOc\x00\x00\x00\x02" + b"\xff" * 40)
        git_dir = repo / ".git"
        store = ObjectStore(git_dir, git_dir, ReadBudget())
        head = _git(repo, "rev-parse", "HEAD").strip()
        assert store.read(head) is None
        assert any("not read" in e for e in store.errors)

    def test_corrupt_pack_raises_git_object_error(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, commits=3)
        _git(repo, "repack", "-adq")
        pack = next((repo / ".git" / "objects" / "pack").glob("*.pack"))
        raw = bytearray(pack.read_bytes())
        raw[12:] = b"\x7f" * (len(raw) - 12)
        pack.write_bytes(bytes(raw))
        git_dir = repo / ".git"
        store = ObjectStore(git_dir, git_dir, ReadBudget())
        head = _git(repo, "rev-parse", "HEAD").strip()
        with pytest.raises(GitObjectError):
            store.read(head)

    def test_malformed_commit_and_tree(self) -> None:
        with pytest.raises(GitObjectError):
            parse_commit(b"tree nothex\n\nmsg")
        with pytest.raises(GitObjectError):
            tree_entries(b"100644 name-without-nul")

    def test_symlinked_ref_file_is_not_followed(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, commits=1)
        outside = tmp_path / "outside"
        outside.write_text("1" * 40 + "\n")
        (repo / ".git" / "refs" / "heads" / "linked").symlink_to(outside)
        git_dir = repo / ".git"
        store = ObjectStore(git_dir, git_dir, ReadBudget())
        assert "1" * 40 not in store.ref_tips()
