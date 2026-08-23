"""Structural checks for .github/workflows/advisory-feed-freshness-canary.yml.

R31 STEP 4: this canary must be able to detect "advisory-feed-publish.yml
stopped running" even when advisory-feed-publish.yml itself is the thing
that broke, which means it must be genuinely independent of it — its own
schedule, no write permission, no dependency on that workflow's steps.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "advisory-feed-freshness-canary.yml"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "advisory-feed-publish.yml"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _on(workflow: dict) -> dict:
    value = workflow.get("on", workflow.get(True))
    assert isinstance(value, dict), "workflow is missing an `on:` block"
    return value


def _steps(job: dict) -> list[dict]:
    return job["steps"]


def test_has_its_own_schedule_independent_of_the_publish_workflow() -> None:
    on = _on(_load())
    assert "workflow_dispatch" in on
    canary_crons = {entry["cron"] for entry in on["schedule"]}

    publish_on = yaml.safe_load(PUBLISH_WORKFLOW.read_text(encoding="utf-8"))
    publish_crons = {entry["cron"] for entry in _on(publish_on)["schedule"]}
    assert canary_crons, "canary must be scheduled, not only workflow_dispatch"
    assert canary_crons.isdisjoint(publish_crons), (
        "canary must not share a cron with advisory-feed-publish.yml — a "
        "canary that only checks when the publisher also happens to run "
        "cannot detect the publisher failing to run"
    )


def test_top_level_permissions_are_read_only() -> None:
    wf = _load()
    assert wf["permissions"] == {"contents": "read"}


def test_single_job_is_also_read_only() -> None:
    jobs = _load()["jobs"]
    assert len(jobs) == 1
    (job,) = jobs.values()
    assert job["permissions"] == {"contents": "read"}


def test_never_writes_anything() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "git commit" not in text
    assert "git push" not in text
    assert "secrets." not in text
    assert "upload-artifact" not in text


def test_runs_the_freshness_check_script() -> None:
    (job,) = _load()["jobs"].values()
    run_text = "\n".join(str(s.get("run", "")) for s in _steps(job))
    assert "python scripts/check_feed_freshness.py" in run_text


def test_has_a_short_timeout_because_it_is_cheap() -> None:
    (job,) = _load()["jobs"].values()
    assert job["timeout-minutes"] <= 10


def test_pins_checkout_and_setup_python() -> None:
    (job,) = _load()["jobs"].values()
    uses = [s.get("uses", "") for s in _steps(job)]
    assert any(u.startswith(CHECKOUT) for u in uses)
    assert any(u.startswith(SETUP_PYTHON) for u in uses)
