"""STORY-0131: ``affected --transitive`` and ``affected --fleet``."""

from __future__ import annotations

import json
import os
import urllib.error
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcp_audit.affected import fleet as fleet_mod
from mcp_audit.affected import transitive as tr
from mcp_audit.cli import app
from mcp_audit.vulnerability import depsdev
from mcp_audit.vulnerability.models import Ecosystem, ResolvedPackage

runner = CliRunner()
QUERY = "leftpad@<2.0"


def _run(*args: str) -> Any:
    return runner.invoke(app, ["affected", *args])


def _cfg(tmp_path: Path, servers: dict[str, Any], name: str = "mcp.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


def _wrapper(spec: str = "wrapper@1.0.0") -> dict[str, Any]:
    return {"command": "npx", "args": ["-y", spec]}


def _graph(
    *deps: tuple[str, str, str],
    error: str | None = None,
    incomplete: str | None = None,
    top: str = "wrapper",
) -> depsdev.DependencyGraph:
    pkgs = [
        ResolvedPackage(
            ecosystem=Ecosystem.NPM,
            name=top,
            version="1.0.0",
            direct=True,
            source_server="",
            relation="self",
        )
    ]
    for name, version, relation in deps:
        pkgs.append(
            ResolvedPackage(
                ecosystem=Ecosystem.NPM,
                name=name,
                version=version,
                direct=relation == "direct",
                source_server="",
                relation=relation,
            )
        )
    return depsdev.DependencyGraph(packages=pkgs, error=error, incomplete=incomplete)


class _Calls(list):
    state: dict[str, Any]


@pytest.fixture
def graphs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Patch the deps.dev client; returns the list of lookups made."""
    calls = _Calls()
    state: dict[str, Any] = {"graph": _graph()}

    def fake(eco: Any, name: str, version: str, **_: Any) -> Any:
        calls.append((name, version))
        g = state["graph"]
        if isinstance(g, Exception):
            raise g
        return g

    monkeypatch.setattr(depsdev, "fetch_dependency_graph", fake)
    calls.state = state
    return calls


def _set(graphs: Any, g: Any) -> None:
    graphs.state["graph"] = g


def _json(result: Any) -> dict:
    return json.loads(result.output)


class TestTransitive:
    def test_direct_dependency_hit(self, tmp_path: Path, graphs: Any) -> None:
        _set(graphs, _graph(("leftpad", "1.3.0", "direct")))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        assert r.exit_code == 1
        row = _json(r)["results"][0]
        assert row["status"] == "AFFECTED"
        assert row["dependency"]["relation"] == "DIRECT"
        assert row["dependency"]["path"] == "wrapper@1.0.0 -> leftpad@1.3.0 (DIRECT)"
        assert row["package"] == "npm:wrapper"
        assert _json(r)["transitive"] is True

    def test_indirect_dependency_hit(self, tmp_path: Path, graphs: Any) -> None:
        _set(
            graphs,
            _graph(("other", "9.0.0", "direct"), ("leftpad", "1.0.0", "indirect")),
        )
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        row = _json(r)["results"][0]
        assert row["status"] == "AFFECTED" and row["reason"] == "dependency"
        assert "(INDIRECT)" in row["dependency"]["path"]
        assert graphs == [("wrapper", "1.0.0")]

    def test_dependency_at_fixed_version_is_clear(
        self, tmp_path: Path, graphs: Any
    ) -> None:
        _set(graphs, _graph(("leftpad", "2.1.0", "indirect")))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        row = _json(r)["results"][0]
        assert r.exit_code == 0 and row["status"] == "NOT AFFECTED"
        assert "dependencies" in row["evidence"]

    def test_incomplete_graph_is_couldnt_check(
        self, tmp_path: Path, graphs: Any
    ) -> None:
        _set(graphs, _graph(("other", "1.0.0", "direct"), incomplete="node errors"))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        row = _json(r)["results"][0]
        assert row["status"] == "COULDN'T CHECK"
        assert row["reason"] == "dependencies-unchecked"
        assert "node errors" in row["evidence"]

    def test_incomplete_graph_with_a_hit_is_still_affected(
        self, tmp_path: Path, graphs: Any
    ) -> None:
        _set(graphs, _graph(("leftpad", "1.0.0", "direct"), incomplete="x"))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        assert _json(r)["results"][0]["status"] == "AFFECTED"

    def test_graph_404_is_couldnt_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*a: Any, **k: Any) -> None:
            raise urllib.error.HTTPError("u", 404, "nf", {}, None)  # type: ignore[arg-type]

        monkeypatch.setattr(depsdev.urllib.request, "urlopen", boom)
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        row = _json(r)["results"][0]
        assert r.exit_code == 0
        assert row["status"] == "COULDN'T CHECK" and "404" in row["evidence"]

    def test_lookup_that_raises_is_couldnt_check(
        self, tmp_path: Path, graphs: Any
    ) -> None:
        _set(graphs, RuntimeError("boom"))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        assert _json(r)["results"][0]["status"] == "COULDN'T CHECK"

    def test_no_exact_version_is_couldnt_check(
        self, tmp_path: Path, graphs: Any
    ) -> None:
        cfg = _cfg(tmp_path, {"w": _wrapper("wrapper")})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        row = _json(r)["results"][0]
        assert row["status"] == "COULDN'T CHECK"
        assert row["reason"] == "dependencies-unchecked"
        assert graphs == []  # nothing to look up

    def test_remote_server_is_left_alone(self, tmp_path: Path, graphs: Any) -> None:
        cfg = _cfg(tmp_path, {"r": {"url": "https://example.com/mcp"}})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "--all", "-f", "json")
        assert _json(r)["results"][0]["reason"] == "no-package"
        assert graphs == []

    def test_without_flag_no_lookup(self, tmp_path: Path, graphs: Any) -> None:
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "-f", "json")
        assert graphs == [] and _json(r)["transitive"] is False

    def test_requires_live(self, tmp_path: Path, graphs: Any) -> None:
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--transitive")
        assert r.exit_code == 2 and "--live" in r.output
        assert graphs == []

    def test_offline_live_still_refused(self, tmp_path: Path, graphs: Any) -> None:
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--offline", "--live", "--transitive")
        assert r.exit_code == 2 and graphs == []

    def test_same_package_fetched_once_and_budget(
        self, tmp_path: Path, graphs: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        servers = {f"s{i}": _wrapper() for i in range(3)}
        cfg = _cfg(tmp_path, servers)
        _run(QUERY, "-p", str(cfg), "--live", "--transitive")
        assert len(graphs) == 1
        monkeypatch.setattr(tr, "MAX_GRAPH_FETCHES", 1)
        graphs.clear()
        servers = {"a": _wrapper("wrapper@1.0.0"), "b": _wrapper("wrapper@1.0.1")}
        cfg = _cfg(tmp_path, servers, "two.json")
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        rows = _json(r)["results"]
        assert len(graphs) == 1
        assert [x["status"] for x in rows].count("COULDN'T CHECK") == 1

    def test_hostile_dependency_name_is_sanitised(
        self, tmp_path: Path, graphs: Any
    ) -> None:
        _set(graphs, _graph(("leftpad\x1b[31m\n", "1.0.0", "direct")))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive")
        # The rule only matches the clean name, so a name with control
        # characters is never reported as a hit and never reaches the screen.
        assert "\x1b" not in r.output
        graphs.state["graph"] = _graph(("x" * 5000, "1.0.0", "direct"))
        r = _run("x@<2", "-p", str(cfg), "--live", "--transitive", "-f", "json")
        assert len(_json(r)["results"][0]["evidence"]) < 1000

    def test_terminal_and_sarif_carry_the_path(
        self, tmp_path: Path, graphs: Any
    ) -> None:
        _set(graphs, _graph(("leftpad", "1.3.0", "indirect")))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive")
        assert "wrapper@1.0.0 -> leftpad@1.3.0 (INDIRECT)" in r.output
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "sarif")
        res = _json(r)["runs"][0]["results"][0]
        assert res["properties"]["dependency"]["relation"] == "INDIRECT"
        assert "leftpad@1.3.0" in res["message"]["text"]

    def test_json_paths_are_redacted(self, tmp_path: Path, graphs: Any) -> None:
        _set(graphs, _graph(("leftpad", "1.0.0", "direct")))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "-f", "json")
        from mcp_audit._redact import redact_finding_path  # noqa: PLC0415

        expected = redact_finding_path(str(cfg), str(cfg)).replace("\\", "/")
        assert _json(r)["results"][0]["config_path"] == expected

    def test_fix_does_not_pin_the_wrapper(self, tmp_path: Path, graphs: Any) -> None:
        _set(graphs, _graph(("leftpad", "1.0.0", "direct")))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        before = cfg.read_text()
        r = _run(QUERY, "-p", str(cfg), "--live", "--transitive", "--fix", "--apply")
        assert "dependency of this server" in r.output
        assert cfg.read_text() == before

    def test_openvex_names_the_dependency(self, tmp_path: Path, graphs: Any) -> None:
        _set(graphs, _graph(("leftpad", "1.0.0", "direct")))
        from mcp_audit.affected import vex  # noqa: PLC0415
        from mcp_audit.affected.match import Dependency, Row, Status  # noqa: PLC0415

        row = Row(
            "c/w",
            Status.AFFECTED,
            "x",
            package="npm:wrapper",
            version="1.0.0",
            reason="dependency",
            dependency=Dependency("npm", "leftpad", "1.0.0", "direct", "p"),
        )
        doc = vex.build([("CVE-1", row)])
        assert doc["statements"][0]["products"][0]["@id"] == "pkg:npm/leftpad@1.0.0"

    def test_graph_source_never_raises_on_budget(self) -> None:
        src = tr.GraphSource(lambda *a, **k: _graph())
        for i in range(tr.MAX_GRAPH_FETCHES):
            src.graph("npm", f"p{i}", "1.0.0")
        assert src.graph("npm", "extra", "1.0.0").error


# ── Fleet ──────────────────────────────────────────────────────────────────────


def _scan(
    servers: list[dict[str, Any]], host: str = "host-a", **extra: Any
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "version": "0.0.0",
        "timestamp": "2026-10-29T00:00:00+00:00",
        "machine_info": {
            "hostname": host,
            "username": "u",
            "os": "Linux",
            "os_version": "1",
            "scan_id": "x",
        },
        "servers": servers,
        "findings": [],
    }
    out.update(extra)
    return out


def _srv(name: str, spec: str, cfg: str = "/home/u/.cursor/mcp.json") -> dict:
    return {
        "name": name,
        "client": "cursor",
        "config_path": cfg,
        "command": "npx",
        "args": ["-y", spec],
    }


def _write(tmp_path: Path, name: str, doc: Any) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class TestFleet:
    def test_two_machines_one_affected(self, tmp_path: Path) -> None:
        a = _write(tmp_path, "a.json", _scan([_srv("lp", "leftpad@1.0.0")], "host-a"))
        b = _write(tmp_path, "b.json", _scan([_srv("lp", "leftpad@2.5.0")], "host-b"))
        r = _run(QUERY, "--fleet", str(a), "--fleet", str(b), "-f", "json")
        assert r.exit_code == 1
        doc = _json(r)
        by = {x["machine"]: x["status"] for x in doc["results"]}
        assert by == {"host-a": "AFFECTED", "host-b": "NOT AFFECTED"}
        assert doc["summary"]["checked"] == 2
        assert str(tmp_path) not in r.output or "a.json" in json.dumps(doc["fleet"])

    def test_terminal_names_the_machine(self, tmp_path: Path) -> None:
        a = _write(tmp_path, "a.json", _scan([_srv("lp", "leftpad@1.0.0")], "host-a"))
        r = _run(QUERY, "--fleet", str(a))
        assert "host-a: cursor/lp" in r.output

    def test_asset_id_wins_and_duplicates_are_kept_apart(self, tmp_path: Path) -> None:
        doc = _scan([_srv("lp", "leftpad@1.0.0")], "same")
        doc["machine_info"]["asset_id"] = "corp-1"
        a = _write(tmp_path, "a.json", doc)
        b = _write(tmp_path, "b.json", _scan([_srv("lp", "leftpad@1.0.0")], "corp-1"))
        r = _run(QUERY, "--fleet", str(a), "--fleet", str(b), "-f", "json")
        machines = [x["machine"] for x in _json(r)["results"]]
        assert machines == ["corp-1", "corp-1 (b.json)"]

    def test_hostile_files_are_reported_not_raised(self, tmp_path: Path) -> None:
        good = _write(tmp_path, "g.json", _scan([_srv("lp", "leftpad@1.0.0")]))
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        arr = _write(tmp_path, "arr.json", [1, 2])
        deep = tmp_path / "deep.json"
        deep.write_text("[" * 100000 + "]" * 100000)
        nul = tmp_path / "nul.json"
        nul.write_bytes(b"\xff\xfe\x00")
        weird = _write(
            tmp_path,
            "weird.json",
            _scan([5, None, {"name": 3}, {"x": 1}, _srv("ok", "leftpad@3.0.0")]),
        )
        noservers = _write(tmp_path, "ns.json", {"findings": []})
        args: list[str] = []
        for p in (good, bad, arr, deep, nul, weird, noservers):
            args += ["--fleet", str(p)]
        r = _run(QUERY, *args, "-f", "json")
        assert r.exception is None or isinstance(r.exception, SystemExit)
        assert r.exit_code == 1
        doc = _json(r)
        statuses = [x["status"] for x in doc["results"]]
        assert statuses.count("AFFECTED") == 1
        assert statuses.count("COULDN'T CHECK") >= 6
        assert any("bad.json" in e for e in doc["errors"])

    def test_oversized_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(fleet_mod, "MAX_SCAN_BYTES", 50)
        big = _write(tmp_path, "big.json", _scan([_srv("lp", "leftpad@1.0.0")]))
        r = _run(QUERY, "--fleet", str(big), "-f", "json")
        doc = _json(r)
        assert r.exit_code == 0
        assert doc["results"][0]["status"] == "COULDN'T CHECK"
        assert "not read" in doc["results"][0]["evidence"]

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
    def test_fifo_does_not_hang(self, tmp_path: Path) -> None:
        fifo = tmp_path / "pipe.json"
        os.mkfifo(fifo)
        r = _run(QUERY, "--fleet", str(fifo), "-f", "json")
        assert _json(r)["results"][0]["status"] == "COULDN'T CHECK"

    def test_missing_file_and_directory_exit_2(self, tmp_path: Path) -> None:
        assert _run(QUERY, "--fleet", str(tmp_path / "none.json")).exit_code == 2
        assert _run(QUERY, "--fleet", str(tmp_path)).exit_code == 2

    def test_merge_output_is_recognised(self, tmp_path: Path) -> None:
        m = _write(
            tmp_path,
            "merged.json",
            {"machines": [], "deduplicated_findings": [], "stats": {}},
        )
        r = _run(QUERY, "--fleet", str(m), "-f", "json")
        assert "merge" in _json(r)["results"][0]["evidence"]

    def test_incompatible_flags(self, tmp_path: Path) -> None:
        a = _write(tmp_path, "a.json", _scan([_srv("lp", "leftpad@1.0.0")]))
        cfg = _cfg(tmp_path, {"w": _wrapper()})
        for extra in (
            ["-p", str(cfg)],
            ["--fix"],
            ["--policy-out", str(tmp_path / "p.json")],
        ):
            assert _run(QUERY, "--fleet", str(a), *extra).exit_code == 2

    def test_foreign_config_path_is_never_used_to_find_a_lock(
        self, tmp_path: Path
    ) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text("{}")
        lock = {
            "lock_version": 2,
            "servers": {
                "cursor/lp": {
                    "package": {"name": "leftpad", "resolved_version": "1.0.0"}
                }
            },
        }
        (tmp_path / "mcp-lock.json").write_text(json.dumps(lock))
        a = _write(tmp_path, "a.json", _scan([_srv("lp", "leftpad", str(cfg))]))
        r = _run(QUERY, "--fleet", str(a), "-f", "json")
        assert _json(r)["results"][0]["status"] == "COULDN'T CHECK"

    def test_fleet_with_transitive(self, tmp_path: Path, graphs: Any) -> None:
        _set(graphs, _graph(("leftpad", "1.0.0", "indirect")))
        a = _write(tmp_path, "a.json", _scan([_srv("w", "wrapper@1.0.0")], "h1"))
        b = _write(tmp_path, "b.json", _scan([_srv("w", "wrapper@1.0.0")], "h2"))
        r = _run(
            QUERY, "--fleet", str(a), "--fleet", str(b), "--live", "--transitive",
            "-f", "json",
        )  # fmt: skip
        rows = _json(r)["results"]
        assert [x["machine"] for x in rows] == ["h1", "h2"]
        assert all(x["status"] == "AFFECTED" for x in rows)
        assert len(graphs) == 1

    def test_real_scan_json_round_trips(self, tmp_path: Path) -> None:
        """A server serialised by ServerConfig itself is read back."""
        from mcp_audit.models import ServerConfig  # noqa: PLC0415

        s = ServerConfig(
            name="lp",
            client="cursor",
            config_path=Path("/home/u/mcp.json"),
            command="npx",
            args=["-y", "leftpad@1.0.0", "--api-key", "sk-abcdefghijklmnopqrstuvwxyz"],
        )
        data = _scan([json.loads(s.model_dump_json())])
        a = _write(tmp_path, "a.json", data)
        r = _run(QUERY, "--fleet", str(a), "-f", "json")
        row = _json(r)["results"][0]
        assert row["status"] == "AFFECTED" and row["version"] == "1.0.0"
