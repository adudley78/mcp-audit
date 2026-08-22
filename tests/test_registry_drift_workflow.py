"""Structural checks for .github/workflows/registry-drift.yml."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "registry-drift.yml"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _on(workflow: dict) -> dict:
    value = workflow.get("on", workflow.get(True))
    assert isinstance(value, dict), "workflow is missing an `on:` block"
    return value


def test_weekly_schedule_and_dispatch() -> None:
    on = _on(_load())
    assert on["schedule"] == [{"cron": "0 14 * * 1"}]
    assert "workflow_dispatch" in on


def test_read_only_permissions() -> None:
    wf = _load()
    assert wf["permissions"] == {"contents": "read"}


def test_never_invokes_stamp_or_opens_a_pr() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "python scripts/audit_registry.py --stamp" not in text
    assert "gh pr" not in text
    assert "git commit" not in text
    assert "git push" not in text


def test_hashes_registry_before_and_after() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "registry.before" in text
    assert "registry.after" in text
    assert "cmp -s" in text
    assert "byte-identical" in text


def test_april_batch_reason_is_in_the_workflow() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "2026-04" in text
    assert "85" in text
    assert "--stamp stays a human act" in text or "human act" in text


def test_pins_and_uploads_report() -> None:
    steps = _load()["jobs"]["audit"]["steps"]
    uses = [s.get("uses", "") for s in steps]
    assert any(u.startswith(CHECKOUT) for u in uses)
    assert any(u.startswith(SETUP_PYTHON) for u in uses)
    assert any(u.startswith(UPLOAD) for u in uses)
    upload = next(s for s in steps if str(s.get("uses", "")).startswith(UPLOAD))
    assert upload["with"]["name"] == "registry-drift-report"
    assert "registry-drift-report.json" in str(upload["with"]["path"])
    assert "always()" in str(upload.get("if", ""))


def test_runs_audit_script_report_only() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "python scripts/audit_registry.py --refresh" in text
    assert "python scripts/check_registry_drift.py" in text
    assert "persist-credentials: false" in text
