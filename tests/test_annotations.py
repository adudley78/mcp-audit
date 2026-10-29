"""Tests for ``analyzers/annotations.py`` (ANNOT-001, STORY-0136).

Every definition here is written for this file; none is copied from a corpus.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from mcp_audit.advisory.classify import is_advisable
from mcp_audit.analyzers import annotations as a
from mcp_audit.lock import tool_text
from mcp_audit.models import (
    ServerConfig,
    ServerEnumeration,
    Severity,
    ToolInfo,
    TransportType,
)
from mcp_audit.scanner import run_scan, run_scan_async

RO = {"readOnlyHint": True}
NOT_DESTRUCTIVE = {"destructiveHint": False}


def _schema(**props: dict) -> dict:
    return {"type": "object", "properties": dict(props)}


def _srv(name: str = "srv", client: str = "cursor") -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path=Path(f"cfg/{client}/mcp.json"),
        transport=TransportType.STDIO,
        command=name,
    )


def _hits(annotations: object, schema: object) -> list[a.Contradiction]:
    return a.find_contradictions(annotations, schema)


class TestFires:
    def test_read_only_with_command_parameter(self) -> None:
        h = _hits(RO, _schema(command={"type": "string"}))
        assert [c.param for c in h] == ["command"]
        assert h[0].claim == "readOnlyHint=true"

    def test_camel_case_and_script(self) -> None:
        assert _hits(RO, _schema(shellScript={"type": "string"}))

    def test_description_says_it_runs_a_command(self) -> None:
        schema = _schema(
            input={"type": "string", "description": "Shell command to run"}
        )
        assert _hits(RO, schema)

    def test_sql_with_write_verbs(self) -> None:
        schema = _schema(
            sql={"type": "string", "description": "Statement: INSERT, UPDATE or DELETE"}
        )
        assert _hits(RO, schema)

    def test_overwrite_switch(self) -> None:
        assert _hits(RO, _schema(overwrite={"type": "boolean"}))

    def test_content_to_write_beside_path(self) -> None:
        schema = _schema(
            path={"type": "string"},
            content={"type": "string", "description": "Content to write to the file"},
        )
        assert [c.param for c in _hits(RO, schema)] == ["content"]

    def test_destructive_false_with_delete_switch(self) -> None:
        h = _hits(NOT_DESTRUCTIVE, _schema(delete_existing={"type": "boolean"}))
        assert h and h[0].claim == "destructiveHint=false"

    def test_destructive_false_with_exec(self) -> None:
        assert _hits(NOT_DESTRUCTIVE, _schema(cmd={"type": "string"}))

    def test_nested_parameter(self) -> None:
        schema = _schema(options=_schema(command={"type": "string"}))
        assert _hits(RO, schema)

    def test_any_of_branch(self) -> None:
        schema = {"anyOf": [_schema(command={"type": "string"})]}
        assert _hits(RO, schema)


class TestSilent:
    def test_path_alone(self) -> None:
        assert not _hits(RO, _schema(path={"type": "string"}))

    def test_url_alone(self) -> None:
        assert not _hits(RO, _schema(url={"type": "string"}))

    def test_no_annotations(self) -> None:
        assert not _hits(None, _schema(command={"type": "string"}))
        assert not _hits({}, _schema(command={"type": "string"}))

    def test_read_only_false(self) -> None:
        assert not _hits({"readOnlyHint": False}, _schema(command={"type": "string"}))

    def test_destructive_true(self) -> None:
        assert not _hits({"destructiveHint": True}, _schema(command={"type": "string"}))

    def test_script_path_is_a_reference(self) -> None:
        assert not _hits(RO, _schema(script_path={"type": "string"}))

    def test_boolean_command_flag(self) -> None:
        assert not _hits(RO, _schema(command={"type": "boolean"}))

    def test_sql_description_forbidding_writes(self) -> None:
        schema = _schema(
            query={
                "type": "string",
                "description": "Read-only query. No INSERT or DELETE.",
            }
        )
        assert not _hits(RO, schema)

    def test_content_without_path(self) -> None:
        schema = _schema(content={"type": "string", "description": "Content to write"})
        assert not _hits(RO, schema)

    def test_additive_write_does_not_contradict_destructive_false(self) -> None:
        schema = _schema(
            path={"type": "string"},
            content={"type": "string", "description": "Content to write"},
            append={"type": "boolean"},
        )
        assert not _hits(NOT_DESTRUCTIVE, schema)

    def test_remove_is_not_a_delete_switch(self) -> None:
        # Measured false positives: removeBase64Images, remove_background.
        schema = _schema(removeBase64Images={"type": "boolean"})
        assert not _hits(RO, schema)
        assert not _hits(NOT_DESTRUCTIVE, schema)

    def test_ordinary_read_tool(self) -> None:
        schema = _schema(
            query={"type": "string", "description": "Search text"},
            limit={"type": "integer"},
        )
        assert not _hits(RO, schema)


class TestMalformed:
    def test_non_bool_annotations(self) -> None:
        for bad in ("true", 1, [True], {"readOnlyHint": "true"}, {"readOnlyHint": 1}):
            assert not _hits(bad, _schema(command={"type": "string"}))

    def test_odd_schemas(self) -> None:
        for bad in (None, 5, "x", [], {"properties": 5}, {"properties": {1: 2}}):
            assert _hits(RO, bad) == []
        assert _hits(RO, {"properties": {"command": 7}}) != []

    def test_deep_nesting(self) -> None:
        node: dict = _schema(command={"type": "string"})
        for _ in range(5000):
            node = _schema(inner=node)
        assert isinstance(_hits(RO, node), list)

    def test_deep_any_of_chain(self) -> None:
        node: dict = {}
        for _ in range(5000):
            node = {"anyOf": [node]}
        assert _hits(RO, node) == []

    def test_huge_schema(self) -> None:
        props = {
            f"p{i}": {"type": "string", "description": "x " * 500} for i in range(5000)
        }
        assert _hits(RO, {"properties": props}) == []

    def test_huge_description(self) -> None:
        schema = _schema(x={"type": "string", "description": "a " * 2_000_000})
        assert _hits(RO, schema) == []

    def test_analyze_definition_never_raises(self) -> None:
        for name in (None, 5, "ok"):
            assert (
                a.analyze_definition(
                    client="c",
                    server="s",
                    finding_path="p",
                    name=name,
                    annotations={"readOnlyHint": True},
                    input_schema=object(),
                )
                is None
            )


class TestFinding:
    def _finding(self, **kw: object):  # type: ignore[no-untyped-def]
        args = {
            "client": "cursor",
            "server": "srv",
            "finding_path": "cfg",
            "name": "run_it",
            "annotations": RO,
            "input_schema": _schema(command={"type": "string"}),
        }
        args.update(kw)
        return a.analyze_definition(**args)  # type: ignore[arg-type]

    def test_shape(self) -> None:
        f = self._finding()
        assert f is not None
        assert f.id == "ANNOT-001"
        assert f.analyzer == "annotations"
        assert f.severity == a.SHIPPED_SEVERITY == Severity.LOW
        assert f.owasp_mcp_top_10 == ["MCP03", "MCP06"]
        assert f.tool == "run_it"
        assert "readOnlyHint=true" in f.evidence

    def test_evidence_is_redacted(self) -> None:
        secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        f = self._finding(
            input_schema=_schema(**{f"command_{secret}": {"type": "string"}})
        )
        assert f is not None
        assert secret not in f.evidence and secret not in f.description

    def test_control_characters_are_stripped(self) -> None:
        f = self._finding(name="bad\x1b[31m\nname")
        assert f is not None
        assert "\x1b" not in f.tool and "\n" not in f.evidence

    def test_not_an_advisory(self) -> None:
        assert not is_advisable("ANNOT-001")

    def test_many_parameters_are_summarised(self) -> None:
        schema = _schema(**{f"command{i}": {"type": "string"} for i in range(9)})
        f = self._finding(input_schema=schema)
        assert f is not None and "more" in f.evidence


class TestConnectPairs:
    def test_one_finding_per_tool_and_dedupes_clients(self) -> None:
        enum = ServerEnumeration(
            tools=[
                ToolInfo(
                    name="sh",
                    input_schema=_schema(command={"type": "string"}),
                    annotations=RO,
                ),
                ToolInfo(name="plain", input_schema=_schema(path={"type": "string"})),
            ]
        )
        pairs = [(_srv("x", "cursor"), enum), (_srv("x", "cursor"), enum)]
        found = a.detect_annotation_contradictions(pairs)
        assert [f.tool for f in found] == ["sh"]

    def test_failed_enumeration_skipped(self) -> None:
        enum = ServerEnumeration(error="boom")
        assert a.detect_annotation_contradictions([(_srv(), enum)]) == []

    async def test_run_scan_async_wiring(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text('{"mcpServers": {"fs": {"command": "fs-cmd"}}}')
        enum = ServerEnumeration(
            tools=[
                ToolInfo(
                    name="sh",
                    input_schema=_schema(command={"type": "string"}),
                    annotations=RO,
                )
            ]
        )

        async def fake(server: ServerConfig, auth_token: str | None = None):  # noqa: ANN202, ARG001
            return enum

        with (
            patch("mcp_audit.discovery._get_client_specs", return_value=[]),
            patch("mcp_audit.mcp_client.connect_and_enumerate", side_effect=fake),
        ):
            result = await run_scan_async(
                extra_paths=[cfg], connect=True, skip_rug_pull=True
            )
        assert [f.id for f in result.findings if f.analyzer == "annotations"] == [
            "ANNOT-001"
        ]

    async def test_crash_is_contained(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text('{"mcpServers": {"fs": {"command": "fs-cmd"}}}')
        enum = ServerEnumeration(tools=[ToolInfo(name="t")])

        async def fake(server: ServerConfig, auth_token: str | None = None):  # noqa: ANN202, ARG001
            return enum

        with (
            patch("mcp_audit.discovery._get_client_specs", return_value=[]),
            patch("mcp_audit.mcp_client.connect_and_enumerate", side_effect=fake),
            patch.object(
                a, "detect_annotation_contradictions", side_effect=RuntimeError("x")
            ),
        ):
            result = await run_scan_async(
                extra_paths=[cfg], connect=True, skip_rug_pull=True
            )
        assert any("annotations error" in e for e in result.errors)


class TestSavedToolText:
    def _doc(self) -> dict:
        tools = [
            ToolInfo(
                name="sh",
                input_schema=_schema(command={"type": "string"}),
                annotations=RO,
            ),
            ToolInfo(name="ok", input_schema=_schema(path={"type": "string"})),
        ]
        return tool_text.build({"cursor/srv": tool_text.server_text(tools)})

    def test_findings_from_document(self, tmp_path: Path) -> None:
        found = a.findings_from_tool_text(self._doc(), tmp_path / "t.json")
        assert [(f.client, f.server, f.tool) for f in found] == [
            ("cursor", "srv", "sh")
        ]

    def test_garbage_documents(self, tmp_path: Path) -> None:
        for doc in (
            None,
            5,
            [],
            {"servers": 5},
            {"servers": {"a/b": 5}},
            {"servers": {"a/b": {"tools": {"t": [5, None]}}}},
            {"servers": {"a/b": {"tools": {"t": {"annotations": 5}}}}},
        ):
            assert a.findings_from_tool_text(doc, tmp_path / "t.json") == []

    def test_default_scan_reads_cwd_file(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        (tmp_path / tool_text.TOOL_TEXT_FILENAME).write_text(json.dumps(self._doc()))
        monkeypatch.chdir(tmp_path)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = run_scan(skip_rug_pull=True)
        assert [f.id for f in result.findings if f.analyzer == "annotations"] == [
            "ANNOT-001"
        ]

    def test_default_scan_reports_unreadable_file(
        self, tmp_path: Path, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        (tmp_path / tool_text.TOOL_TEXT_FILENAME).write_text("{not json")
        monkeypatch.chdir(tmp_path)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = run_scan(skip_rug_pull=True)
        assert any(e.startswith("annotations:") for e in result.errors)
        assert not [f for f in result.findings if f.analyzer == "annotations"]


def test_module_has_no_network_or_process_imports() -> None:
    src = Path(a.__file__).read_text()
    for banned in ("subprocess", "urllib", "socket", "requests", "os.system"):
        assert banned not in src
    assert os.name  # keep os import used
