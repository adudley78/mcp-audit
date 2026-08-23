"""Structural checks for .github/workflows/advisory-feed-publish.yml.

R30 split the single `publish` job into `build` (read-only) and `publish`
(write) so the destination that Amendment 7 gates signing on actually
exists. R31 removed the R30 gate that skipped `publish` when advisory
content was unchanged — that gate froze `expires` on a feed with a TTL,
which is worse than a noisy commit log. `publish` now always runs; the
diff only shapes the commit message. These tests pin the shape of that
split, and of the unconditional publish, so a future edit cannot silently
recombine the two capabilities, re-widen a permission, or reintroduce a
publish gate.
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


def test_publish_depends_on_build_and_is_unconditional() -> None:
    """R31: publish must run on every scheduled run, changed or not — a
    TTL-backed feed cannot skip refreshing its expiry just because the
    advisory content happens to be identical this week."""
    publish = _load()["jobs"]["publish"]
    assert publish["needs"] == "build"
    assert "if" not in publish


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
    assert outputs["changed_count"] == "${{ steps.diff.outputs.changed_count }}"
    assert outputs["snapshot_version"] == "${{ steps.diff.outputs.snapshot_version }}"
    assert outputs["count"] == "${{ steps.diff.outputs.count }}"
    assert outputs["commit_message"] == "${{ steps.diff.outputs.commit_message }}"


def test_publish_checks_out_the_feed_branch_and_downloads_the_artifact() -> None:
    publish = _load()["jobs"]["publish"]
    steps = _steps(publish)
    checkout = next(s for s in steps if str(s.get("uses", "")).startswith(CHECKOUT))
    assert checkout["with"]["ref"] == "feed"
    assert any(str(s.get("uses", "")).startswith(DOWNLOAD) for s in steps)


def test_publish_commit_message_comes_from_build_diff_classification() -> None:
    """R31: the commit message is built entirely by scripts/feed_diff.py
    (unit-tested separately) and passed through, not reconstructed with
    ad hoc bash string interpolation in the workflow."""
    publish = _load()["jobs"]["publish"]
    commit_step = next(
        s for s in _steps(publish) if "COMMIT_MESSAGE" in str(s.get("env", {}))
    )
    assert commit_step["env"]["COMMIT_MESSAGE"] == (
        "${{ needs.build.outputs.commit_message }}"
    )
    run_text = commit_step["run"]
    assert 'git commit -m "${COMMIT_MESSAGE}"' in run_text
    assert "git push origin feed" in run_text


def test_publish_has_a_belt_and_suspenders_empty_diff_guard() -> None:
    """R31: publish is unconditional, so this is the only remaining guard
    against an empty commit — defence-in-depth, expected to never fire
    since snapshot_version/expires change every run."""
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
