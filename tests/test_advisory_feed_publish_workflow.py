"""Structural checks for .github/workflows/advisory-feed-publish.yml.

R30 split the single `publish` job into `build` (read-only) and `publish`
(write, gated on a real content change) so the destination that Amendment 7
gates signing on actually exists. These tests pin the shape of that split so
a future edit cannot silently recombine the two capabilities or re-widen a
permission.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "advisory-feed-publish.yml"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _on(workflow: dict) -> dict:
    value = workflow.get("on", workflow.get(True))
    assert isinstance(value, dict), "workflow is missing an `on:` block"
    return value


def _steps(job: dict) -> list[dict]:
    return job["steps"]


def _uses(steps: list[dict]) -> list[str]:
    return [s.get("uses", "") for s in steps]


def _run_text(steps: list[dict]) -> str:
    return "\n".join(str(s.get("run", "")) for s in steps)


def test_schedule_and_ttl_are_unchanged() -> None:
    """R30 must not touch the cadence or the freshness design."""
    on = _on(_load())
    assert on["schedule"] == [{"cron": "0 14 * * 0"}]
    assert "workflow_dispatch" in on


def test_top_level_permissions_are_read_only() -> None:
    wf = _load()
    assert wf["permissions"] == {"contents": "read"}


def test_exactly_two_jobs_named_build_and_publish() -> None:
    jobs = _load()["jobs"]
    assert set(jobs) == {"build", "publish"}


def test_build_job_is_read_only() -> None:
    build = _load()["jobs"]["build"]
    assert build["permissions"] == {"contents": "read"}


def test_publish_job_has_write_and_nothing_else() -> None:
    publish = _load()["jobs"]["publish"]
    assert publish["permissions"] == {"contents": "write"}


def test_publish_depends_on_build_and_is_gated_on_a_real_change() -> None:
    publish = _load()["jobs"]["publish"]
    assert publish["needs"] == "build"
    assert publish["if"] == "needs.build.outputs.changed == 'true'"


def test_build_never_checks_out_or_writes_the_feed_branch() -> None:
    build = _load()["jobs"]["build"]
    uses = _uses(_steps(build))
    checkout_steps = [
        s for s in _steps(build) if str(s.get("uses", "")).startswith(CHECKOUT)
    ]
    assert checkout_steps, "build must check out the repo to run mcp-audit advise"
    for step in checkout_steps:
        assert step.get("with", {}).get("ref") in (None, "main", "${{ github.ref }}")
    run_text = _run_text(_steps(build))
    assert "git push" not in run_text
    assert "git commit" not in run_text
    assert any(u.startswith(SETUP_PYTHON) for u in uses)
    assert any(u.startswith(UPLOAD) for u in uses)


def test_build_reads_the_live_feed_branch_not_a_local_file() -> None:
    run_text = _run_text(_steps(_load()["jobs"]["build"]))
    assert "git fetch --depth 1 origin feed" in run_text
    assert "git archive FETCH_HEAD" in run_text
    assert "--previous-index previous_feed/index.json" in run_text


def test_build_diffs_with_feed_diff_script() -> None:
    run_text = _run_text(_steps(_load()["jobs"]["build"]))
    assert "scripts/feed_diff.py" in run_text
    assert "--github-output" in run_text
    assert '"$GITHUB_OUTPUT"' in run_text


def test_build_declares_the_outputs_publish_consumes() -> None:
    build = _load()["jobs"]["build"]
    outputs = build["outputs"]
    assert outputs["changed"] == "${{ steps.diff.outputs.changed }}"
    assert outputs["snapshot_version"] == "${{ steps.diff.outputs.snapshot_version }}"
    assert outputs["count"] == "${{ steps.diff.outputs.count }}"


def test_publish_checks_out_the_feed_branch_and_downloads_the_artifact() -> None:
    publish = _load()["jobs"]["publish"]
    steps = _steps(publish)
    checkout = next(s for s in steps if str(s.get("uses", "")).startswith(CHECKOUT))
    assert checkout["with"]["ref"] == "feed"
    assert any(str(s.get("uses", "")).startswith(DOWNLOAD) for s in steps)


def test_publish_commit_message_names_version_and_count() -> None:
    run_text = _run_text(_steps(_load()["jobs"]["publish"]))
    assert "snapshot_version ${SNAPSHOT_VERSION}" in run_text
    assert "${COUNT} advisories" in run_text
    assert "git push origin feed" in run_text


def test_publish_has_a_belt_and_suspenders_empty_diff_guard() -> None:
    """Even though `if:` already gates on build's verdict, the commit step
    itself must refuse to commit an empty diff."""
    run_text = _run_text(_steps(_load()["jobs"]["publish"]))
    assert "git diff --cached --quiet" in run_text


def test_never_signs_or_touches_key_material() -> None:
    """Only the advise invocation's own --no-sign may mention "sign"; no bare
    --sign flag, no key material, no secret, anywhere in the workflow."""
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "MCP_AUDIT_SIGNING_KEY" not in text
    assert "secrets." not in text
    assert "--keyless" not in text
    run_text = _run_text(_steps(_load()["jobs"]["build"])) + _run_text(
        _steps(_load()["jobs"]["publish"])
    )
    for line in run_text.splitlines():
        code = line.split("#", 1)[0]
        assert "--sign" not in code.replace("--no-sign", "")


def test_amendment_7_gate_comment_still_present() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "Amendment 7" in text
    assert "key custody" in text


def test_documents_the_public_feed_url() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert (
        "https://raw.githubusercontent.com/adudley78/mcp-audit/feed/index.json" in text
    )
