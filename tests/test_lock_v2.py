"""lock_version 2 (STORY-0116): compatibility with v1 locks, the v2 shapes.

The first class is the regression the review asked for: locks written by
origin/main's lock_version 1 code (``tests/fixtures/lock_v1_corpus``) must
verify on this code exactly as they verified there, for a corpus of server
shapes (npx pinned/bare/scoped/range/@latest/@*, uvx bare/==/--from/@/>=,
pipx run, yarn dlx, bunx, env and header names, remote URLs, local and docker
commands).
"""

from __future__ import annotations

import copy
import importlib.util
import json
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.advisory.canonical import CanonicalError, canonicalize
from mcp_audit.analyzers.supply_chain import build_deprecated_package_finding
from mcp_audit.cli import app
from mcp_audit.lock import section_digests
from mcp_audit.lock.auto_verify import auto_verify
from mcp_audit.lock.model import (
    LOCK_VERSION,
    OWNED_CHECKSUM_KEYS,
    ResolutionContext,
    compute_checksum,
    unverified_sections,
)
from mcp_audit.lock.resolve import _spec_as_written, resolve_package
from mcp_audit.lock.section_digests import (
    is_digest_string,
    noncanonical_sections,
    section_digest,
)
from mcp_audit.lock.verifier import verify
from mcp_audit.lock.writer import LockWriteError, regenerate, serialize, write_lock
from mcp_audit.models import ServerConfig, Severity
from mcp_audit.output.sarif import format_sarif
from tests.conftest import unwrapped

CORPUS = Path(__file__).parent / "fixtures" / "lock_v1_corpus"
_spec = importlib.util.spec_from_file_location("lock_v1_corpus", CORPUS / "generate.py")
assert _spec is not None and _spec.loader is not None
corpus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(corpus)

EXPECTED = json.loads((CORPUS / "expected.json").read_text(encoding="utf-8"))
runner = CliRunner()

#: A synthetic token in a shape SECRET_PATTERNS knows (never a real key).
_FAKE_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A fresh copy of the corpus project (a git repository root)."""
    return corpus.copy_project(tmp_path)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sc005_neutral(outcome: dict) -> dict:
    """Drop SC-005's prose, which STORY-0116 rewords on purpose."""
    out = copy.deepcopy(outcome)
    for f in out["findings"]:
        if f["id"] == "SC-005":
            f.pop("title")
            f.pop("evidence")
    return out


# ── 1. A lock written by lock_version 1 code verifies exactly as before ─────


class TestV1CorpusVerifiesAsBefore:
    def test_corpus_counts_are_what_the_fixture_says(self, project: Path) -> None:
        servers = corpus.discover(project)
        assert len(servers) == 25
        for name in ("mcp-lock.offline.json", "mcp-lock.resolved.json"):
            doc = _load(CORPUS / name)
            assert doc["lock_version"] == 1
            assert "section_digests" not in doc
            assert len(doc["servers"]) == 25
            assert doc["checksum"] == compute_checksum(doc)
        bare = _load(CORPUS / "mcp-lock.resolved.json")["servers"][
            "claude-code/npx-bare"
        ]["package"]
        assert bare["spec_as_written"] == "latest"  # what v1 wrote

    @pytest.mark.parametrize("lock", ["offline", "resolved"])
    def test_same_outcomes_as_origin_main(self, project: Path, lock: str) -> None:
        got = corpus.run_scenarios(project, f"mcp-lock.{lock}.json")
        want = EXPECTED[lock]
        assert got["verify"] == want["verify"]
        assert got["auto_verify"] == want["auto_verify"]
        for state in ("resolve_locked", "resolve_drifted"):
            assert _sc005_neutral(got[state]) == _sc005_neutral(want[state])
            ids = {f["id"] for f in got[state]["findings"]}
            assert not ids & {"LOCK-010", "LOCK-011", "LOCK-012"}

    def test_untouched_resolved_lock_is_clean_offline_and_resolved(
        self, project: Path
    ) -> None:
        got = corpus.run_scenarios(project, "mcp-lock.resolved.json")
        assert got["verify"]["findings"] == []
        assert got["verify"]["exit_code"] == 0
        # Only SC-005 for the package whose latest is deprecated; no LOCK-004.
        assert [f["id"] for f in got["resolve_locked"]["findings"]] == ["SC-005"]

    def test_v1_lock_with_a_section_digests_key_treats_it_as_foreign(
        self, project: Path
    ) -> None:
        doc = _load(CORPUS / "mcp-lock.resolved.json")
        doc["section_digests"] = {"servers": "sha256:" + "0" * 64}
        (project / "mcp-lock.json").write_bytes(serialize(doc))
        result = verify(project / "mcp-lock.json", corpus.discover(project))
        assert result.findings == []
        assert "section_digests" in result.unverified_sections
        assert result.exit_code == 1  # R56: populated foreign section

    def test_v1_lock_written_non_canonically_gets_no_lock_012(
        self, project: Path
    ) -> None:
        doc = _load(CORPUS / "mcp-lock.resolved.json")
        (project / "mcp-lock.json").write_text(json.dumps(doc, indent=2))
        result = verify(project / "mcp-lock.json", corpus.discover(project))
        assert result.findings == []
        assert result.exit_code == 0


# ── 2. Re-locking a v1 lock writes v2 without churn or false drift ──────────


def _relock(project: Path, lock: str, state: str = "locked") -> dict:
    existing = _load(CORPUS / lock)
    with corpus.patched_registry(state):
        doc = regenerate(
            existing,
            corpus.discover(project),
            project,
            offline=False,
            registry=None,
        )
    write_lock(project / "mcp-lock.json", doc)
    return doc


class TestUpgradeFromV1:
    def test_relock_writes_v2_and_keeps_timestamps(self, project: Path) -> None:
        old = _load(CORPUS / "mcp-lock.resolved.json")
        new = _relock(project, "mcp-lock.resolved.json")
        assert new["lock_version"] == LOCK_VERSION == 2
        for key, entry in old["servers"].items():
            assert new["servers"][key]["first_locked"] == entry["first_locked"]
            assert new["servers"][key]["identity"] == entry["identity"]
            pkg, was = new["servers"][key]["package"], entry["package"]
            if was is None:
                assert pkg is None
                continue
            assert pkg["resolved_version"] == was["resolved_version"]
            assert pkg["integrity"] == was["integrity"]
            assert pkg["resolution"]["resolved_at"] == was["resolution"]["resolved_at"]
            assert "resolution_context" in pkg["resolution"]

    def test_spec_as_written_in_v2(self, project: Path) -> None:
        servers = _relock(project, "mcp-lock.resolved.json")["servers"]

        def spec(key: str) -> str:
            return servers[key]["package"]["spec_as_written"]

        for key in (
            "claude-code/npx-bare",
            "claude-code/npx-scoped-bare",
            "claude-code/npx-trailing-at",
            "claude-code/npx-star",
            "claude-code/uvx-bare",
            "claude-code/uvx-extras",
            "claude-code/pipx-run",
            "cursor/yarn-dlx",
            "vscode/vscode-npx",
        ):
            assert spec(key) == "*", key
        assert spec("claude-code/npx-explicit-latest") == "latest"
        # Specs lock does not parse keep v1's reading: no new resolved version.
        assert spec("claude-code/uvx-eqeq") == "latest"
        assert spec("claude-code/uvx-from") == "latest"
        assert spec("claude-code/uvx-range") == "latest"
        assert spec("claude-code/npx-scoped-range") == "^1.2.0"
        assert spec("claude-code/fs-pinned") == "2025.1.14"
        assert spec("claude-code/uvx-at") == "0.6.2"

    def test_resolution_context_shape(self, project: Path) -> None:
        servers = _relock(project, "mcp-lock.resolved.json")["servers"]
        bare = servers["claude-code/npx-bare"]["package"]["resolution"]
        ctx = bare["resolution_context"]
        ResolutionContext.model_validate(ctx)
        assert ctx == {
            "resolved_at": bare["resolved_at"],
            "latest": "1.4.0",
            "latest_deprecated": None,
            "npm_major": None,
            "node_version": None,
        }
        dep = servers["claude-code/npx-deprecated"]["package"]["resolution"]
        assert dep["resolution_context"]["latest_deprecated"] == (
            "Package no longer supported"
        )
        pinned = servers["claude-code/with-env"]["package"]["resolution"]
        assert pinned["method"] == "exact-pin"
        assert pinned["resolution_context"] is None

    def test_offline_entries_have_null_context(self, project: Path) -> None:
        doc = regenerate(
            _load(CORPUS / "mcp-lock.offline.json"),
            corpus.discover(project),
            project,
            offline=True,
            registry=None,
        )
        pkg = doc["servers"]["claude-code/npx-bare"]["package"]
        assert pkg["resolution"] == {
            "method": "unresolved",
            "resolved_at": None,
            "resolution_context": None,
        }
        assert pkg["spec_as_written"] == "*"

    def test_v2_lock_verifies_clean_and_noop_relock_does_not_churn(
        self, project: Path
    ) -> None:
        first = _relock(project, "mcp-lock.resolved.json")
        result = verify(project / "mcp-lock.json", corpus.discover(project))
        assert result.findings == []
        assert result.exit_code == 0
        assert result.unverified_sections == ["trees"]
        with corpus.patched_registry("locked"):
            second = regenerate(
                first, corpus.discover(project), project, offline=False, registry=None
            )
        assert second["servers"] == first["servers"]
        assert second["checksum"] == first["checksum"]
        assert second["section_digests"] == first["section_digests"]

    def test_resolve_against_unchanged_registry_has_no_drift(
        self, project: Path
    ) -> None:
        _relock(project, "mcp-lock.resolved.json")
        with corpus.patched_registry("locked"):
            result = verify(
                project / "mcp-lock.json", corpus.discover(project), resolve=True
            )
        assert [f.id for f in result.findings] == ["SC-005"]

    def test_resolve_against_drifted_registry(self, project: Path) -> None:
        _relock(project, "mcp-lock.resolved.json")
        with corpus.patched_registry("drifted"):
            result = verify(
                project / "mcp-lock.json", corpus.discover(project), resolve=True
            )
        got = sorted((f.id, f.server) for f in result.findings)
        assert got == [
            ("LOCK-004", "npx-bare"),
            ("LOCK-004", "uvx-bare"),
            ("LOCK-004", "with-env"),
            ("LOCK-010", "npx-bare"),
            ("LOCK-010", "uvx-bare"),
            ("SC-005", "npx-deprecated"),
        ]
        ctx = next(f for f in result.findings if f.id == "LOCK-010")
        assert ctx.severity == Severity.INFO
        assert "latest: locked='1.4.0' now='1.5.0'" in ctx.evidence
        assert result.exit_code == 1  # from LOCK-004, not LOCK-010

    def test_secrets_never_reach_a_v2_lock(self, project: Path) -> None:
        _relock(project, "mcp-lock.resolved.json")
        text = (project / "mcp-lock.json").read_text(encoding="utf-8")
        assert "eu-west-1" not in text  # env value
        assert "session=abc" not in text  # URL query
        assert "${MCP_TOKEN}" not in text  # header value
        assert str(project) not in text


# ── 3. Bare specs ───────────────────────────────────────────────────────────


def _srv(command: str, args: list[str], name: str = "s") -> ServerConfig:
    return ServerConfig(
        name=name,
        client="c",
        config_path=Path("/x/.mcp.json"),
        command=command,
        args=args,
    )


@pytest.mark.parametrize(
    ("command", "args", "spec"),
    [
        ("npx", ["-y", "foo"], "*"),
        ("npx", ["-y", "@s/foo"], "*"),
        ("npx", ["-y", "foo@"], "*"),
        ("npx", ["foo@*"], "*"),
        ("npx", ["-y", "foo@latest"], "latest"),
        ("npx", ["-y", "foo@1.2.3"], "1.2.3"),
        ("npx", ["-y", "@s/foo@^1.2"], "^1.2"),
        ("uvx", ["pkg"], "*"),
        ("uvx", ["pkg[extra]"], "*"),
        ("uvx", ["--from", "pkg", "cmd"], "*"),
        ("pipx", ["run", "pkg"], "*"),
        ("yarn", ["dlx", "foo"], "*"),
        ("uvx", ["pkg==1.2.3"], "latest"),
        ("uvx", ["pkg>=1.0"], "latest"),
        ("uvx", ["pkg~=1.0"], "latest"),
        ("pipx", ["run", "pkg==1.0"], "latest"),
        ("uvx", ["pkg@1.2.3"], "1.2.3"),
    ],
)
def test_spec_as_written(command: str, args: list[str], spec: str) -> None:
    assert _spec_as_written(_srv(command, args)) == spec


def test_bare_spec_resolves_through_latest_like_v1() -> None:
    calls: list[str] = []

    def latest(_eco: object, name: str) -> tuple[str, None]:
        calls.append(name)
        return "3.1.0", None

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("mcp_audit.lock.resolve.resolve_latest_version_info", latest)
        mp.setattr(
            "mcp_audit.lock.resolve.compute_hash_from_url",
            lambda url: "sha256:" + "a" * 64,
        )
        pkg = resolve_package(_srv("npx", ["-y", "foo"]), offline=False, registry=None)
    assert calls == ["foo"]
    assert pkg is not None
    assert pkg["resolved_version"] == "3.1.0"
    assert pkg["resolution"]["method"] == "dist-tag:latest"
    assert pkg["range_spec"] is True


# ── 4. section_digests ──────────────────────────────────────────────────────


def _v2_lock(tmp_path: Path, doc_edit=None) -> Path:  # noqa: ANN001
    (tmp_path / ".cursor").mkdir(exist_ok=True)
    server = ServerConfig(
        name="github",
        client="cursor",
        config_path=tmp_path / ".cursor" / "mcp.json",
        command="npx",
        args=["-y", "foo@1.0.0"],
    )
    doc = regenerate(None, [server], tmp_path, offline=True, registry=None)
    if doc_edit is not None:
        doc_edit(doc)
    path = tmp_path / "mcp-lock.json"
    path.write_bytes(serialize(doc))
    return path


def _server_for(tmp_path: Path) -> list[ServerConfig]:
    return [
        ServerConfig(
            name="github",
            client="cursor",
            config_path=tmp_path / ".cursor" / "mcp.json",
            command="npx",
            args=["-y", "foo@1.0.0"],
        )
    ]


_TREES = {"_producer": "tree-gen", "servers": {"github": {"deps": ["a", "b"]}}}


class TestSectionDigests:
    def test_written_for_owned_sections_only(self, tmp_path: Path) -> None:
        doc = _load(_v2_lock(tmp_path))
        assert set(doc["section_digests"]) == {"servers"}
        assert doc["section_digests"]["servers"] == section_digest(doc["servers"])
        assert is_digest_string(doc["section_digests"]["servers"])
        assert "section_digests" not in OWNED_CHECKSUM_KEYS

    def test_owned_tools_section_gets_a_digest(self, tmp_path: Path) -> None:
        servers = _server_for(tmp_path)
        (tmp_path / ".cursor").mkdir()
        doc = regenerate(
            None,
            servers,
            tmp_path,
            offline=True,
            registry=None,
            tool_records={"cursor/github": {"tools": {}}},
        )
        assert doc["section_digests"]["tools"] == section_digest(doc["tools"])

    def test_other_producers_entries_are_kept_verbatim(self, tmp_path: Path) -> None:
        stale = "sha256:" + "1" * 64

        def add_trees(doc: dict) -> None:
            doc["trees"] = _TREES
            doc["section_digests"]["trees"] = stale
            doc["section_digests"]["zzz"] = "not-a-digest"
            doc["section_digests"]["generated_at"] = "sha256:" + "2" * 64

        path = _v2_lock(tmp_path, add_trees)
        again = regenerate(
            _load(path), _server_for(tmp_path), tmp_path, offline=True, registry=None
        )
        assert again["section_digests"]["trees"] == stale
        assert again["section_digests"]["zzz"] == "not-a-digest"
        assert "generated_at" not in again["section_digests"]  # envelope: dropped
        assert again["trees"] == _TREES

    def test_non_object_map_refuses_to_write(self, tmp_path: Path) -> None:
        path = _v2_lock(tmp_path, lambda d: d.update(section_digests=["x"]))
        with pytest.raises(LockWriteError, match="section_digests"):
            regenerate(
                _load(path),
                _server_for(tmp_path),
                tmp_path,
                offline=True,
                registry=None,
            )

    def test_matching_foreign_digest_is_quiet(self, tmp_path: Path) -> None:
        def add_trees(doc: dict) -> None:
            doc["trees"] = _TREES
            doc["section_digests"]["trees"] = section_digest(_TREES)

        path = _v2_lock(tmp_path, add_trees)
        result = verify(path, _server_for(tmp_path))
        assert result.findings == []
        # A populated foreign section is still unverified (R56).
        assert [i.name for i in result.unverified] == ["trees"]
        assert "section_digests" not in result.unverified_sections

    def test_foreign_section_changed_without_its_digest(self, tmp_path: Path) -> None:
        def add_trees(doc: dict) -> None:
            doc["trees"] = copy.deepcopy(_TREES)
            doc["section_digests"]["trees"] = section_digest(_TREES)
            doc["trees"]["servers"]["github"]["deps"].append("evil")

        path = _v2_lock(tmp_path, add_trees)
        result = verify(path, _server_for(tmp_path), allow_unverified=True)
        assert [f.id for f in result.findings] == ["LOCK-011"]
        finding = result.findings[0]
        assert finding.severity == Severity.HIGH
        assert "'trees'" in finding.title
        assert result.exit_code == 1  # not waivable

    @pytest.mark.parametrize(
        ("edit", "needle"),
        [
            (lambda d: d.pop("section_digests"), "is missing"),
            (lambda d: d.update(section_digests="x"), "not an object"),
            (lambda d: d["section_digests"].pop("servers"), "no digest recorded"),
            (
                lambda d: d["section_digests"].update(servers="sha256:" + "0" * 64),
                "does not match",
            ),
            (lambda d: d["section_digests"].update(servers="md5:abc"), "not sha256"),
            (
                lambda d: d["section_digests"].update(trees2="sha256:" + "0" * 64),
                "section that is gone",
            ),
            (
                lambda d: d["section_digests"].update(checksum="sha256:" + "0" * 64),
                "envelope",
            ),
        ],
    )
    def test_problems_are_lock_011(self, tmp_path: Path, edit, needle: str) -> None:  # noqa: ANN001
        path = _v2_lock(tmp_path, edit)
        result = verify(path, _server_for(tmp_path))
        assert [f.id for f in result.findings] == ["LOCK-011"]
        assert needle in result.findings[0].evidence
        assert result.exit_code == 1

    def test_lock_011_fails_scan_auto_verify(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        _v2_lock(tmp_path, lambda d: d["section_digests"].pop("servers"))
        findings, status = auto_verify(_server_for(tmp_path))
        assert [f.id for f in findings] == ["LOCK-011"]
        assert status.verified is False

    def test_too_large_section_is_unverified_not_passed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def add_trees(doc: dict) -> None:
            doc["trees"] = _TREES
            doc["section_digests"]["trees"] = section_digest(_TREES)

        path = _v2_lock(tmp_path, add_trees)
        real = section_digests.section_digest

        def bounded(value: object) -> str:
            if value == _TREES:
                raise CanonicalError("too big")
            return real(value)

        monkeypatch.setattr(section_digests, "section_digest", bounded)
        result = verify(path, _server_for(tmp_path), allow_unverified=True)
        assert result.findings == []
        assert any(
            i.name == "trees" and "too large" in i.reason for i in result.unverified
        )
        assert result.waived is True

    def test_digest_check_is_linear_on_hostile_values(self) -> None:
        start = time.monotonic()
        assert not is_digest_string("sha256:" + "a" * 5_000_000)
        assert not is_digest_string("sha256:" + "g" * 64)
        assert time.monotonic() - start < 2


# ── 5. Canonical bytes (LOCK-012) ───────────────────────────────────────────


class TestCanonicalForm:
    def test_pretty_printed_v2_lock_is_lock_012_low_and_passes(
        self, tmp_path: Path
    ) -> None:
        path = _v2_lock(tmp_path)
        path.write_text(json.dumps(_load(path), indent=2, sort_keys=True))
        result = verify(path, _server_for(tmp_path))
        assert [f.id for f in result.findings] == ["LOCK-012"]
        assert result.findings[0].severity == Severity.LOW
        assert result.exit_code == 0

    def test_trailing_newline_is_layout(self, tmp_path: Path) -> None:
        path = _v2_lock(tmp_path)
        path.write_bytes(path.read_bytes() + b"\n")
        result = verify(path, _server_for(tmp_path))
        assert [f.evidence for f in result.findings] == ["not canonical: <layout>"]

    def test_names_the_reformatted_section(self) -> None:
        doc = {"a": {"x": 1}, "b": [1, 2]}
        raw = b'{"a":{"x": 1},"b":[1,2]}'
        assert noncanonical_sections(raw, doc) == ["a"]
        assert noncanonical_sections(canonicalize(doc), doc) == []

    def test_unreadable_file_skips_only_the_byte_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _v2_lock(tmp_path)
        real = Path.read_bytes

        def denied(self: Path) -> bytes:
            if self == path:
                raise PermissionError("denied")
            return real(self)

        monkeypatch.setattr(Path, "read_bytes", denied)
        result = verify(path, _server_for(tmp_path))
        assert result.findings == []
        assert result.exit_code == 0


# ── 6. lock_version handling ────────────────────────────────────────────────


class TestLockVersion:
    def test_newer_version_is_refused(self, tmp_path: Path) -> None:
        path = _v2_lock(tmp_path, lambda d: d.update(lock_version=3))
        result = verify(path, _server_for(tmp_path))
        assert result.unsupported_version == 3
        assert result.exit_code == 2
        assert result.findings == []

    def test_newer_version_is_not_overwritten(self, tmp_path: Path) -> None:
        path = _v2_lock(tmp_path, lambda d: d.update(lock_version=3))
        with pytest.raises(LockWriteError, match="lock_version 3"):
            regenerate(
                _load(path),
                _server_for(tmp_path),
                tmp_path,
                offline=True,
                registry=None,
            )

    def test_newer_version_in_scan_is_not_verified(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        _v2_lock(tmp_path, lambda d: d.update(lock_version=7))
        findings, status = auto_verify(_server_for(tmp_path))
        assert findings == []
        assert status.verified is False
        assert any("lock_version 7" in s for s in status.unverified_sections)

    @pytest.mark.parametrize("odd", ["2", True, None])
    def test_odd_version_values_are_read_as_v1(
        self, tmp_path: Path, odd: object
    ) -> None:
        def set_version(doc: dict) -> None:
            doc["lock_version"] = odd
            doc["checksum"] = compute_checksum(doc)

        path = _v2_lock(tmp_path, set_version)
        result = verify(path, _server_for(tmp_path))
        assert result.unsupported_version is None
        assert not any(f.id in ("LOCK-011", "LOCK-012") for f in result.findings)
        assert "section_digests" in unverified_sections(_load(path))

    def test_cli_names_the_newer_version(self, tmp_path: Path) -> None:
        _v2_lock(tmp_path, lambda d: d.update(lock_version=3))
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify"])
        assert result.exit_code == 2
        assert "lock_version 3" in unwrapped(result.output)
        result = runner.invoke(
            app, ["lock", str(tmp_path), "--verify", "--format", "json"]
        )
        assert json.loads(result.stdout)["unsupported_version"] == 3

    def test_v2_lock_keeps_the_v1_checksum_scope(self, tmp_path: Path) -> None:
        """An older mcp-audit recomputes the same checksum, so no false LOCK-005."""
        doc = _load(_v2_lock(tmp_path))
        assert {"lock_version", "generated_by", "servers"} == OWNED_CHECKSUM_KEYS
        assert all(isinstance(v, dict) for v in doc["servers"].values())


# ── 7. SC-005 wording, LOCK-010 text, redaction in every output ─────────────


def _package(spec: str, notice: str) -> dict:
    return {
        "name": "pkg",
        "resolved_version": "2.0.0",
        "spec_as_written": spec,
        "deprecated": notice,
    }


class TestSc005Wording:
    def test_bare_spec_mentions_npm_fast_path(self) -> None:
        f = build_deprecated_package_finding(
            client="c", server="s", config_path="p", package=_package("*", "old")
        )
        assert f is not None
        assert f.title == "`latest` is deprecated on npm: pkg (2.0.0)"
        assert "npm 10.8.2 and later" in f.description
        assert f.severity == Severity.MEDIUM

    def test_explicit_latest_says_npm_installs_it(self) -> None:
        f = build_deprecated_package_finding(
            client="c", server="s", config_path="p", package=_package("latest", "x")
        )
        assert f is not None
        assert "asks for `@latest` explicitly" in f.description
        assert "10.8.2" not in f.description

    def test_notice_is_redacted_and_capped(self) -> None:
        notice = f"moved, token {_FAKE_TOKEN} see https://u:pw@host/x " + "z" * 1000
        f = build_deprecated_package_finding(
            client="c", server="s", config_path="p", package=_package("*", notice)
        )
        assert f is not None
        for text in (f.description, f.evidence, f.title):
            assert _FAKE_TOKEN not in text
            assert "u:pw" not in text
        assert len(f.evidence) < 500

    def test_hostile_notice_is_fast(self) -> None:
        start = time.monotonic()
        build_deprecated_package_finding(
            client="c",
            server="s",
            config_path="p",
            package=_package("*", "://" * 200_000 + "@" * 200_000),
        )
        assert time.monotonic() - start < 5


def _cli_project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"dep": {"command": "npx", "args": ["-y", "dep-mcp"]}}}
        )
    )
    return root


class TestRedactionInOutputs:
    def _lock_then_change(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN202
        root = _cli_project(tmp_path)
        state = {"latest": "1.0.0", "notice": None}

        def latest(_eco: object, _name: str) -> tuple[str, str | None]:
            return state["latest"], state["notice"]

        monkeypatch.setattr(
            "mcp_audit.lock.resolve.resolve_latest_version_info", latest
        )
        monkeypatch.setattr(
            "mcp_audit.lock.resolve.compute_hash_from_url",
            lambda url: "sha256:" + "b" * 64,
        )
        assert runner.invoke(app, ["lock", str(root)]).exit_code == 0
        state["notice"] = f"use other-mcp; {_FAKE_TOKEN}"
        return root

    @pytest.mark.parametrize("fmt", ["terminal", "json", "sarif"])
    def test_context_and_sc005_never_print_the_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
    ) -> None:
        root = self._lock_then_change(tmp_path, monkeypatch)
        result = runner.invoke(
            app, ["lock", str(root), "--verify", "--resolve", "--format", fmt]
        )
        out = result.output
        assert "LOCK-010" in out
        assert "SC-005" in out
        assert _FAKE_TOKEN not in out
        assert "[REDACTED]" in out

    def test_sarif_formatter_directly(self, tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
        from mcp_audit.models import ScanResult

        root = self._lock_then_change(tmp_path, monkeypatch)
        result = verify(
            root / "mcp-lock.json",
            corpus.discover(root),
            resolve=True,
        )
        sarif = format_sarif(ScanResult(servers=[], findings=result.findings))
        assert _FAKE_TOKEN not in sarif


def test_fixture_project_is_unchanged_by_tests() -> None:
    """The corpus configs are inputs; a test must never rewrite them."""
    assert not (CORPUS / "project" / "mcp-lock.json").exists()
