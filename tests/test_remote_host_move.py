"""STORY-0135: a remote server's host (or port) move is named, never leaks creds."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_audit.analyzers.rug_pull import RugPullAnalyzer
from mcp_audit.diff.comparator import compare
from mcp_audit.diff.render import render_json, render_pr_comment
from mcp_audit.lock.identity import describe_remote_move, remote_host
from mcp_audit.lock.verifier import verify
from mcp_audit.lock.writer import regenerate, write_lock
from mcp_audit.models import ServerConfig, TransportType

BASE = "https://a.example/mcp"
SECRET = "s3cr3t-token-value"  # noqa: S105


def _srv(root: Path, url: str) -> ServerConfig:
    return ServerConfig(
        name="remote",
        client="cursor",
        config_path=root / ".cursor" / "mcp.json",
        transport=TransportType.SSE,
        url=url,
        raw={"url": url},
    )


def _lock_findings(tmp_path: Path, old: str, new: str) -> list:
    write_lock(
        tmp_path / "mcp-lock.json",
        regenerate(None, [_srv(tmp_path, old)], tmp_path, offline=True, registry=None),
    )
    result = verify(
        tmp_path / "mcp-lock.json", [_srv(tmp_path, new)], resolve=False, registry=None
    )
    return [f for f in result.findings if f.id == "LOCK-001"]


class TestDescribe:
    def test_host(self) -> None:
        assert (
            describe_remote_move(BASE, "https://b.example/mcp")
            == "remote host changed from a.example to b.example"
        )

    def test_port(self) -> None:
        msg = describe_remote_move(BASE, "https://a.example:8443/mcp")
        assert msg == "remote port changed from 443 to 8443 on host a.example"

    @pytest.mark.parametrize(
        "new",
        [
            "https://a.example/other",
            "https://a.example:443/mcp",
            "https://A.EXAMPLE/mcp",
            f"https://user:{SECRET}@a.example/mcp",
            f"https://a.example/mcp?token={SECRET}",
        ],
    )
    def test_not_a_move(self, new: str) -> None:
        assert describe_remote_move(BASE, new) is None

    def test_garbage_and_empty(self) -> None:
        assert describe_remote_move(None, BASE) is None
        assert describe_remote_move("not a url", BASE) is None
        assert remote_host("https://h.example:99999/x") is None

    def test_credentials_never_quoted(self) -> None:
        msg = describe_remote_move(
            f"https://u:{SECRET}@a.example/m?k={SECRET}",
            f"https://u:{SECRET}@b.example/m?k={SECRET}",
        )
        assert msg is not None and SECRET not in msg


class TestLockVerify:
    def test_host_change_named(self, tmp_path: Path) -> None:
        (f,) = _lock_findings(tmp_path, BASE, "https://b.example/mcp")
        assert f.severity == "HIGH"
        assert "remote host changed from a.example to b.example" in f.evidence
        assert "remote endpoint moved" in f.description

    def test_port_change_named(self, tmp_path: Path) -> None:
        (f,) = _lock_findings(tmp_path, BASE, "https://a.example:8443/mcp")
        assert "remote port changed from 443 to 8443" in f.evidence

    def test_path_change_is_drift_but_not_a_move(self, tmp_path: Path) -> None:
        (f,) = _lock_findings(tmp_path, BASE, "https://a.example/v2")
        assert "remote host" not in f.evidence
        assert "remote port" not in f.evidence

    def test_userinfo_and_query_only_do_not_drift(self, tmp_path: Path) -> None:
        new = f"https://u:{SECRET}@a.example/mcp?token={SECRET}"
        assert _lock_findings(tmp_path, BASE, new) == []

    def test_no_credentials_in_finding_or_lock(self, tmp_path: Path) -> None:
        old = f"https://u:{SECRET}@a.example/mcp?token={SECRET}"
        new = f"https://u:{SECRET}@b.example/mcp?token={SECRET}"
        (f,) = _lock_findings(tmp_path, old, new)
        assert SECRET not in f.model_dump_json()
        assert SECRET not in (tmp_path / "mcp-lock.json").read_text()
        assert "remote host changed from a.example to b.example" in f.evidence


class TestDiff:
    def test_host_move_noted(self) -> None:
        a, b = _srv(Path("/x"), BASE), _srv(Path("/x"), "https://b.example/mcp")
        server = [c for c in compare([a], [b]) if c.entity_type == "server"][0]
        assert server.note == "remote host changed from a.example to b.example"
        records = json.loads(render_json(compare([a], [b])))
        assert any(r.get("note") == server.note for r in records)
        assert server.note in render_pr_comment(compare([a], [b]), "base", "head")

    def test_path_only_has_no_note(self) -> None:
        a, b = _srv(Path("/x"), BASE), _srv(Path("/x"), "https://a.example/v2")
        notes = [c.note for c in compare([a], [b])]
        assert notes and all(n is None for n in notes)
        assert "note" not in json.loads(render_json(compare([a], [b])))[0]

    def test_secret_not_in_note(self) -> None:
        a = _srv(Path("/x"), f"https://u:{SECRET}@a.example/m?t={SECRET}")
        b = _srv(Path("/x"), f"https://u:{SECRET}@b.example/m?t={SECRET}")
        notes = [c.note for c in compare([a], [b]) if c.note]
        assert notes and all(SECRET not in n for n in notes)


class TestRugPull:
    def test_host_move_named(self, tmp_path: Path) -> None:
        an = RugPullAnalyzer(state_path=tmp_path / "s.json")
        an.analyze_all([_srv(tmp_path, BASE)])
        (f,) = an.analyze_all([_srv(tmp_path, "https://b.example/mcp")])
        assert f.id == "RUGPULL-001"
        assert "remote host changed from a.example to b.example" in f.evidence

    def test_state_without_remote_host_still_fires(self, tmp_path: Path) -> None:
        state = tmp_path / "s.json"
        an = RugPullAnalyzer(state_path=state)
        an.analyze_all([_srv(tmp_path, BASE)])
        doc = json.loads(state.read_text())
        for entry in doc["servers"].values():
            entry.pop("remote_host", None)
        state.write_text(json.dumps(doc))
        (f,) = an.analyze_all([_srv(tmp_path, "https://b.example/mcp")])
        assert f.id == "RUGPULL-001"
        assert "remote host" not in f.evidence

    def test_state_stores_only_hostname(self, tmp_path: Path) -> None:
        state = tmp_path / "s.json"
        an = RugPullAnalyzer(state_path=state)
        an.analyze_all([_srv(tmp_path, f"https://u:{SECRET}@a.example/m?t={SECRET}")])
        assert SECRET not in state.read_text()
        assert "a.example" in state.read_text()


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (BASE, "http://a.example/mcp", "remote scheme changed from https to http"),
        (BASE, "wss://a.example/mcp", "remote scheme changed from https to wss"),
        ("https://a.example./mcp", BASE, None),
        ("https://BÜCHER.example/m", "https://xn--bcher-kva.example/m", None),
        ("https://${HOST}/mcp", BASE, None),
    ],
)
def test_scheme_and_equivalent_hosts(old: str, new: str, expected: str | None) -> None:
    got = describe_remote_move(old, new)
    if expected is None:
        assert got is None
    else:
        assert got is not None and got.startswith(expected)
        assert "None" not in got


def test_pr_comment_note_is_code_span() -> None:
    a = _srv(Path("/x"), BASE)
    b = _srv(Path("/x"), "https://b<img src=x>.example/mcp")
    out = render_pr_comment(compare([a], [b]), "base", "head")
    note_lines = [ln for ln in out.splitlines() if "remote host changed" in ln]
    assert note_lines and all(ln.startswith("> `") for ln in note_lines)
