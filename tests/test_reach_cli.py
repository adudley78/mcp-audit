"""``mcp-audit reach`` command, JSON schema, PDF and fleet roll-up (STORY-0145)."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.output.reach_pdf import ReachPdfFormatter
from mcp_audit.reach import build_machine_reach
from mcp_audit.reach.fleet import MAX_FILE_BYTES, load_fleet
from mcp_audit.scanner import run_scan
from tests.conftest import split_runner
from tests.test_reach import FETCH, FILESYSTEM, GOOD_SETTINGS, Box

DOCS = Path(__file__).resolve().parents[1] / "docs"
RUNNER = CliRunner()


@pytest.fixture()
def box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Box:
    return Box(tmp_path, monkeypatch)


def _schema(name: str) -> Draft202012Validator:
    doc = json.loads((DOCS / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(doc)
    return Draft202012Validator(doc)


def _unsafe(box: Box) -> None:
    box.settings({"permissions": {"defaultMode": "bypassPermissions"}})
    box.ssh_key()
    box.servers({"fetch": FETCH})


def _ready(box: Box) -> None:
    box.settings(GOOD_SETTINGS)
    box.ssh_key()


# ── Terminal / JSON ───────────────────────────────────────────────────────────


def test_terminal_shows_one_panel_per_agent_and_exits_1(box: Box) -> None:
    _unsafe(box)
    box.write(".codex/config.toml", 'sandbox_mode = "workspace-write"\n')
    result = RUNNER.invoke(app, ["reach"])
    out = " ".join(result.output.split())
    assert result.exit_code == 1, result.output
    assert "Claude Code NOT SAFE TO ALLOW" in out
    assert "Codex COULDN'T CHECK" in out
    assert "2 agents: 1 not safe to allow, 1 couldn't check" in out
    assert "HARNESS-001" in out and "REACH-001" in out


def test_ready_machine_exits_0(box: Box) -> None:
    _ready(box)
    result = RUNNER.invoke(app, ["reach"])
    assert result.exit_code == 0, result.output
    assert "READY" in result.output


def test_couldnt_check_only_exits_0(box: Box) -> None:
    shutil.rmtree(box.home / ".claude")
    box.write(".codex/config.toml", 'sandbox_mode = "read-only"\n')
    result = RUNNER.invoke(app, ["reach"])
    assert result.exit_code == 0, result.output


def test_no_agents_prints_a_message_and_exits_0(box: Box) -> None:
    shutil.rmtree(box.home / ".claude")
    result = RUNNER.invoke(app, ["reach"])
    assert result.exit_code == 0
    assert "No agents found on this machine" in result.output


def test_json_on_stdout_validates_against_the_schema(box: Box) -> None:
    _unsafe(box)
    box.write(".codex/config.toml", 'sandbox_mode = "workspace-write"\n')
    box.write(".cursor/mcp.json", {"mcpServers": {"fs": FILESYSTEM}})
    result = split_runner().invoke(app, ["reach", "--format", "json"])
    assert result.exit_code == 1
    doc = json.loads(result.stdout)
    errors = list(_schema("reach.schema.json").iter_errors(doc))
    assert errors == [], [e.message for e in errors]
    assert doc["schema_version"] == "1.0"
    assert [a["id"] for a in doc["agents"]] == ["claude-code", "codex", "cursor"]
    assert doc["summary"]["worst_verdict"] == "not_safe_to_allow"
    assert "zebrauser" not in result.stdout


def test_empty_machine_json_validates(box: Box) -> None:
    shutil.rmtree(box.home / ".claude")
    result = split_runner().invoke(app, ["reach", "-f", "json"])
    assert result.exit_code == 0
    doc = json.loads(result.stdout)
    assert list(_schema("reach.schema.json").iter_errors(doc)) == []
    assert doc["agents"] == []


def test_json_to_a_file(box: Box, tmp_path: Path) -> None:
    _ready(box)
    out = tmp_path / "out" / "reach.json"
    result = RUNNER.invoke(app, ["reach", "-f", "json", "-o", str(out)])
    assert result.exit_code == 0
    assert (
        json.loads(out.read_text(encoding="utf-8"))["agents"][0]["verdict"] == "ready"
    )


def test_schema_rejects_a_changed_document(box: Box) -> None:
    _ready(box)
    doc = build_machine_reach(
        run_scan(skip_rug_pull=True, offline=True), env=box.env
    ).to_dict()
    validator = _schema("reach.schema.json")
    assert list(validator.iter_errors(doc)) == []
    bad = json.loads(json.dumps(doc))
    bad["agents"][0]["verdict"] = "fine"
    assert list(validator.iter_errors(bad))
    bad = json.loads(json.dumps(doc))
    bad["agents"][0]["extra"] = 1
    assert list(validator.iter_errors(bad))
    bad = json.loads(json.dumps(doc))
    del bad["agents"][0]["questions"]["logging"]
    assert list(validator.iter_errors(bad))


def test_path_is_not_accepted(box: Box) -> None:
    result = RUNNER.invoke(app, ["reach", "--path", str(box.home)])
    assert result.exit_code == 2
    assert "No such option" in result.output


def test_unknown_report_format_is_an_error(box: Box) -> None:
    result = RUNNER.invoke(app, ["reach", "--report", "docx"])
    assert result.exit_code == 2


def test_reach_scans_without_writing_state_or_network(
    box: Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcp_audit.cli.reach as cli_reach

    seen: dict = {}
    real = cli_reach.run_scan

    def spy(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(cli_reach, "run_scan", spy)
    _ready(box)
    RUNNER.invoke(app, ["reach"])
    assert seen["skip_rug_pull"] is True
    assert seen["offline"] is True
    assert not seen.get("connect")
    assert not seen.get("extra_paths")


def test_scan_failure_is_exit_2_not_a_traceback(
    box: Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcp_audit.cli.reach as cli_reach

    def boom(*_a, **_k):
        raise RuntimeError("secret ghp_" + "x" * 36)

    monkeypatch.setattr(cli_reach, "run_scan", boom)
    result = RUNNER.invoke(app, ["reach"])
    assert result.exit_code == 2
    assert "ghp_" not in result.output
    assert "Traceback" not in result.output


def test_markup_in_a_server_name_is_not_interpreted(box: Box) -> None:
    box.settings(GOOD_SETTINGS)
    box.servers({"[red]boom[/red] [": {"command": "./x"}})
    result = RUNNER.invoke(app, ["reach"])
    assert result.exit_code in (0, 1)
    assert "[red]boom[/red]" in result.output


# ── PDF ───────────────────────────────────────────────────────────────────────


def _pdf_text(pdf: bytes) -> str:
    """Text drawn on the pages: every content stream, ASCII85 and Flate undone."""
    import base64
    import zlib

    parts: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        data = match.group(1).strip()
        try:
            raw = base64.a85decode(data, adobe=data.startswith(b"<~"))
        except ValueError:
            try:
                raw = base64.a85decode(data.removesuffix(b"~>"))
            except ValueError:
                continue
        with contextlib.suppress(zlib.error):
            raw = zlib.decompress(raw)
        if raw.startswith(b"\xff\xd8"):
            continue  # the header image
        parts.append(raw.decode("latin-1"))
    return "\n".join(parts)


def _story_text(flowables: list) -> str:
    """Plain text of every Paragraph in *flowables* (tables walked)."""
    from reportlab.platypus import Paragraph, Table

    out: list[str] = []

    def walk(items: list) -> None:
        for item in items:
            if isinstance(item, Paragraph):
                out.append(item.getPlainText())
            elif isinstance(item, Table):
                for row in item._cellvalues:
                    walk(row)
            elif isinstance(item, list):
                walk(item)

    walk(flowables)
    return " ".join(out)


def _pages(pdf: bytes) -> int:
    return len(re.findall(rb"/Type /Page(?![s\w])", pdf))


def test_pdf_command_writes_one_page(box: Box, tmp_path: Path) -> None:
    _unsafe(box)
    out = tmp_path / "reach.pdf"
    result = RUNNER.invoke(app, ["reach", "--report", "pdf", "-o", str(out)])
    assert result.exit_code == 1, result.output
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    assert "PDF report written" in result.output


def test_pdf_is_one_page_per_machine_however_many_agents(box: Box) -> None:
    _unsafe(box)
    box.write(".codex/config.toml", 'sandbox_mode = "danger-full-access"\n')
    for name in ("cursor", "vscode", "windsurf", "zed", "augment", "amazon-q"):
        box.write(
            f".{name}/mcp.json",
            {"mcpServers": {f"s{i}": FETCH for i in range(3)}},
        )
    report = build_machine_reach(
        run_scan(skip_rug_pull=True, offline=True), env=box.env
    )
    assert len(report.agents) >= 3
    pdf = ReachPdfFormatter(report, org_name="Acme <b>Corp</b>").generate(
        compress=False
    )
    assert pdf.startswith(b"%PDF")
    assert _pages(pdf) == 1
    drawn = _pdf_text(pdf)
    assert "(NOT SAFE TO ALLOW)" in drawn
    # Markup in an organisation name is text, not markup.
    assert "Acme <b>Corp</b>" in _story_text(
        ReachPdfFormatter(report, "Acme <b>Corp</b>")._story(400)
    )


def test_pdf_with_many_synthetic_agents_still_one_page(box: Box) -> None:
    from mcp_audit.reach.models import (
        AgentReach,
        MachineReach,
        Question,
        Reason,
        Status,
        Verdict,
    )

    questions = [
        Question(qid, Status.FAIL, "x " * 120)
        for qid in ("where_it_runs", "credentials", "network", "policy", "logging")
    ]
    agents = [
        AgentReach(
            id=f"a{i}",
            name=f"Agent {i}",
            kind="client",
            verdict=Verdict.NEEDS_WORK,
            reasons=[Reason("needs_work", "y " * 150, ["REACH-001"])] * 9,
            questions=questions,
        )
        for i in range(14)
    ]
    report = MachineReach(
        version="0",
        generated_at="2026-01-01T00:00:00+00:00",
        hostname="h",
        os="Linux",
        os_version="1",
        asset_id=None,
        agents=agents,
    )
    pdf = ReachPdfFormatter(report).generate(compress=False)
    assert _pages(pdf) == 1


def test_pdf_with_no_agents(box: Box) -> None:
    shutil.rmtree(box.home / ".claude")
    report = build_machine_reach(
        run_scan(skip_rug_pull=True, offline=True), env=box.env
    )
    pdf = ReachPdfFormatter(report).generate(compress=False)
    assert pdf.startswith(b"%PDF")
    assert _pages(pdf) == 1
    assert "No agents found on this machine." in _pdf_text(pdf)


# ── Fleet ─────────────────────────────────────────────────────────────────────


def _machine_json(box: Box, name: str, hostname: str) -> dict:
    doc = build_machine_reach(
        run_scan(skip_rug_pull=True, offline=True), env=box.env
    ).to_dict()
    doc["machine"]["hostname"] = hostname
    return doc


def _fleet_dir(tmp_path: Path, docs: dict[str, object]) -> Path:
    d = tmp_path / "fleet"
    d.mkdir()
    for name, doc in docs.items():
        (d / name).write_text(
            doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8"
        )
    return d


def test_fleet_counts_per_verdict_and_reports_the_malformed_file(
    box: Box, tmp_path: Path
) -> None:
    _unsafe(box)
    unsafe = _machine_json(box, "a", "laptop-a")
    _ready(box)
    shutil.rmtree(box.home / ".ssh")
    ready = _machine_json(box, "b", "laptop-b")
    fleet = _fleet_dir(
        tmp_path,
        {"a.json": unsafe, "b.json": ready, "c.json": "{ not json at all"},
    )
    result = split_runner().invoke(app, ["reach", "--fleet", str(fleet)])
    out = " ".join(result.stdout.split())
    assert result.exit_code == 1
    assert "2 machine(s)" in out
    assert "laptop-a: Claude Code" in out
    assert "laptop-b" not in out.split("Not safe to allow:")[1].split("Skipped")[0]
    assert "Skipped 1 file(s)" in out
    assert "c.json is not valid JSON" in out


def test_fleet_json_validates_and_lists_the_skipped_file(
    box: Box, tmp_path: Path
) -> None:
    _unsafe(box)
    unsafe = _machine_json(box, "a", "laptop-a")
    fleet = _fleet_dir(
        tmp_path, {"a.json": unsafe, "b.json": unsafe, "bad.json": "[1, 2]"}
    )
    result = split_runner().invoke(
        app, ["reach", "--fleet", str(fleet), "--format", "json"]
    )
    doc = json.loads(result.stdout)
    assert list(_schema("reach-fleet.schema.json").iter_errors(doc)) == []
    assert doc["machines"] == 2
    assert doc["per_agent"]["Claude Code"]["not_safe_to_allow"] == 2
    assert [m["machine"] for m in doc["not_safe_to_allow"]] == [
        "laptop-a",
        "laptop-a (b.json)",
    ]
    assert doc["skipped"] == [
        {"file": "bad.json", "reason": "is not a reach report (expected a JSON object)"}
    ]


def test_fleet_with_only_ready_and_couldnt_check_exits_0(
    box: Box, tmp_path: Path
) -> None:
    _ready(box)
    box.write(".codex/config.toml", 'sandbox_mode = "read-only"\n')
    doc = _machine_json(box, "a", "m1")
    assert {a["verdict"] for a in doc["agents"]} == {"ready", "couldnt_check"}
    fleet = _fleet_dir(tmp_path, {"m1.json": doc})
    result = RUNNER.invoke(app, ["reach", "--fleet", str(fleet)])
    assert result.exit_code == 0, result.output
    assert "No machine has an agent that is not safe to allow" in result.output


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "null",
        '{"schema_version": "2.0", "agents": []}',
        '{"schema_version": "1.0"}',
        '{"schema_version": "1.0", "agents": {}}',
        '{"schema_version": "1.0", "agents": [1]}',
        '{"schema_version": "1.0", "agents": [{"name": "x", "verdict": "fine"}]}',
        '{"schema_version": "1.0", "agents": [{"verdict": "ready"}]}',
        "[" * 50000,
        "\xff\xfe",
    ],
)
def test_fleet_skips_hostile_files(tmp_path: Path, payload: str) -> None:
    d = _fleet_dir(tmp_path, {"x.json": payload})
    report = load_fleet(d)
    assert report.machines == []
    assert len(report.skipped) == 1


def test_fleet_hostile_names_and_values_are_cleaned(tmp_path: Path) -> None:
    doc = {
        "schema_version": "1.0",
        "machine": {"hostname": "ho\x1b[31mst\n"},
        "agents": [{"name": "Ag\x00ent", "verdict": "ready"}],
    }
    report = load_fleet(_fleet_dir(tmp_path, {"m.json": doc}))
    assert report.machines[0].machine == "ho?[31mst"
    assert report.machines[0].agents[0][0] == "Ag?ent"


def test_fleet_ignores_non_json_names_and_reads_bounded(tmp_path: Path) -> None:
    d = _fleet_dir(tmp_path, {"notes.txt": "x"})
    (d / "big.json").write_bytes(b" " * (MAX_FILE_BYTES + 1))
    (d / "sub.json").mkdir()
    report = load_fleet(d)
    reasons = dict(report.skipped)
    assert "over" in reasons["big.json"]
    assert "not a regular file" in reasons["sub.json"]
    assert "notes.txt" not in reasons


@pytest.mark.skipif(sys.platform.startswith("win"), reason="needs FIFOs and symlinks")
def test_fleet_does_not_block_on_a_fifo_or_follow_a_device(tmp_path: Path) -> None:
    d = _fleet_dir(tmp_path, {})
    os.mkfifo(d / "pipe.json")
    os.symlink("/dev/zero", d / "zero.json")
    report = load_fleet(d)
    assert {f for f, _ in report.skipped} == {"pipe.json", "zero.json"}


def test_fleet_file_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit.reach.fleet as fleet_mod

    monkeypatch.setattr(fleet_mod, "MAX_FILES", 2)
    doc = {"schema_version": "1.0", "agents": [{"name": "A", "verdict": "ready"}]}
    d = _fleet_dir(tmp_path, {f"{i}.json": doc for i in range(5)})
    report = load_fleet(d)
    assert len(report.machines) == 2 and report.truncated


def test_fleet_argument_errors(box: Box, tmp_path: Path) -> None:
    missing = RUNNER.invoke(app, ["reach", "--fleet", str(tmp_path / "nope")])
    assert missing.exit_code == 2
    file_ = tmp_path / "f.json"
    file_.write_text("{}")
    assert RUNNER.invoke(app, ["reach", "--fleet", str(file_)]).exit_code == 2
    d = _fleet_dir(tmp_path, {})
    both = RUNNER.invoke(app, ["reach", "--fleet", str(d), "--report", "pdf"])
    assert both.exit_code == 2


def test_empty_fleet_directory(tmp_path: Path) -> None:
    d = tmp_path / "empty"
    d.mkdir()
    result = RUNNER.invoke(app, ["reach", "--fleet", str(d)])
    assert result.exit_code == 0
    assert "0 machine(s)" in result.output


# ── Review fixes: fleet input is untrusted ─────────────────────────────────────


def _one_agent_doc() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "machine": {"hostname": "m"},
        "agents": [{"name": "Claude Code", "verdict": "ready"}],
    }


def test_n3_a_file_with_too_many_agents_is_skipped_not_truncated(
    tmp_path: Path,
) -> None:
    from mcp_audit.reach.fleet import MAX_AGENTS_PER_FILE

    doc = _one_agent_doc()
    doc["agents"] = [
        {"name": f"Agent {i}", "verdict": "not_safe_to_allow"}
        for i in range(MAX_AGENTS_PER_FILE + 1)
    ]
    d = _fleet_dir(tmp_path, {"big.json": doc, "ok.json": _one_agent_doc()})
    report = load_fleet(d)
    assert [m.source for m in report.machines] == ["ok.json"]
    assert "more than" in dict(report.skipped)["big.json"]
    assert report.exit_code == 0


@pytest.mark.skipif(sys.platform.startswith("win"), reason="needs symlinks")
def test_n4_a_symlink_in_the_fleet_directory_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps(_one_agent_doc()))
    d = _fleet_dir(tmp_path, {})
    (d / "link.json").symlink_to(outside)
    report = load_fleet(d)
    assert report.machines == []
    assert "symbolic link" in dict(report.skipped)["link.json"]


@pytest.mark.skipif(sys.platform.startswith("win"), reason="needs symlinks")
def test_n4_affected_fleet_does_not_follow_a_symlink_either(tmp_path: Path) -> None:
    from mcp_audit.affected import fleet as affected_fleet

    outside = tmp_path / "scan.json"
    outside.write_text(json.dumps({"servers": []}))
    link = tmp_path / "link.json"
    link.symlink_to(outside)
    doc, why = affected_fleet._read(link)
    assert doc is None and "symbolic link" in (why or "")
