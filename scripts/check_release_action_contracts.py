#!/usr/bin/env python3
"""Assert release.yml's ``with:`` blocks still match each pinned action's own
declared input contract, fetched at the exact SHA release.yml pins.

Why this exists
----------------
A SHA-pinned action (Dependabot's own recommended form, and what every
action in release.yml already uses) buys supply-chain integrity — the bytes
that run cannot change under you — but buys nothing on the *input contract*.
An action can rename or drop an input, or add a newly-required one with no
default, between the old pinned SHA and the new one, and a version-bump PR
that only ever diffs a 40-hex-char string will not show it. Every action
release.yml touches (``upload-artifact``, ``download-artifact``,
``action-gh-release``, ``gh-action-pypi-publish``, ``setup-uv``) sits on the
tag-push-only path — the one path CI's own PR-triggered jobs do not execute
(see docs/release-ci-blind-spot.md) — so a broken contract is invisible until
the next real tag, at release time, with no rollback but a new tag.

This script closes that specific gap, generalizing the precedent already
established in ci.yml's ``wheel-check`` job (which fetches
``pypa/gh-action-pypi-publish``'s pinned-SHA ``requirements/runtime.txt`` to
resolve the matching Twine version rather than keeping a second copy of it).
Same shape: parse the SHA out of release.yml itself, fetch the pinned
commit's own metadata from GitHub, never keep an independent copy of what
"correct" looks like.

Scope
-----
Only external, SHA-pinned marketplace actions (``owner/repo@<40-hex-sha>``)
used in release.yml are checked. Local composite actions
(``uses: ./.github/actions/build-binary``) are out of scope: their
``action.yml`` lives in this repo, is reviewed like any other source change,
and is never bumped by Dependabot — the failure mode this script targets
(silent contract drift riding in on a version-bump PR) does not apply to it.

Two directions are checked for every usage:

1. Every key under the workflow step's ``with:`` block must be a declared
   input of the action at that exact pinned SHA (catches a renamed/removed
   input — the workflow would otherwise pass a value silently ignored, or in
   some runners, rejected outright).
2. Every input the action declares ``required: true`` with no ``default``
   must be present under the workflow step's ``with:`` block (catches a
   newly-required input introduced by the bump — the step would otherwise
   fail at release time with "Input required and not supplied").

Usage::

    python scripts/check_release_action_contracts.py
    python scripts/check_release_action_contracts.py --workflow /tmp/scratch.yml
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, NamedTuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"

# owner/repo@<40-hex-char-sha> — the exact form every action in release.yml
# already uses. Deliberately does not match local composite refs
# (``./path``) or floating tag/branch refs (``@v1``, ``@main``) — see
# "Scope" in the module docstring for why composites are excluded; floating
# refs have no fixed contract to diff against in the first place.
_ACTION_USES_RE = re.compile(
    r"^(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(?P<sha>[0-9a-f]{40})$"
)

_RAW_URL_TEMPLATE = "https://raw.githubusercontent.com/{repo}/{sha}/{filename}"
_ACTION_YAML_CANDIDATES = ("action.yml", "action.yaml")


class ActionUsage(NamedTuple):
    """One ``uses:`` step in the workflow that resolves to a pinned SHA."""

    repo: str  # "owner/name"
    sha: str
    job: str
    step_name: str
    with_keys: frozenset[str]


def find_action_usages(workflow_path: Path) -> list[ActionUsage]:
    """Parse *workflow_path* and return every pinned-SHA external action usage.

    Local composite actions (``uses: ./...``) and unpinned refs (a branch or
    tag rather than a 40-hex-char SHA) are skipped; see the module docstring.
    """
    doc = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    usages: list[ActionUsage] = []
    for job_name, job in (doc.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            uses = step.get("uses")
            if not uses:
                continue
            match = _ACTION_USES_RE.match(uses)
            if not match:
                continue
            with_block = step.get("with") or {}
            usages.append(
                ActionUsage(
                    repo=match.group("repo"),
                    sha=match.group("sha"),
                    job=job_name,
                    step_name=step.get("name") or uses,
                    with_keys=frozenset(with_block.keys()),
                )
            )
    return usages


def _http_get(url: str) -> str:
    # S310: url is always built from this script's own hardcoded
    # https://raw.githubusercontent.com/ template plus an owner/repo@sha
    # parsed out of release.yml — never user-controlled scheme or host.
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
        return resp.read().decode("utf-8")


def fetch_action_yaml(
    repo: str,
    sha: str,
    *,
    fetcher: Any = None,
) -> dict[str, Any]:
    """Fetch and parse an action's ``action.yml``/``action.yaml`` at an exact SHA.

    *fetcher*, if given, replaces the network call with ``fetcher(url) -> str``
    — the seam tests use to stay fully offline.

    Raises ``FileNotFoundError`` if neither candidate filename exists at
    that SHA.
    """
    fetch = fetcher or _http_get
    last_error: Exception | None = None
    for filename in _ACTION_YAML_CANDIDATES:
        url = _RAW_URL_TEMPLATE.format(repo=repo, sha=sha, filename=filename)
        try:
            raw = fetch(url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                last_error = exc
                continue
            raise
        parsed = yaml.safe_load(raw)
        if not isinstance(parsed, dict):
            raise ValueError(f"{repo}@{sha}: {filename} did not parse to a mapping")
        return parsed
    raise FileNotFoundError(
        f"Neither action.yml nor action.yaml found for {repo}@{sha}"
    ) from last_error


def _truthy(value: Any) -> bool:
    """Parse a YAML-sourced boolean-ish value defensively.

    Real ``action.yml`` files always use a real YAML boolean, but this
    treats a stray ``"false"``/``"true"`` string the same way rather than
    letting Python's normal string-truthiness turn ``"false"`` into
    ``True``.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1"}
    return bool(value)


def declared_inputs(action_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the ``inputs:`` mapping of a parsed action.yml (``{}`` if none)."""
    inputs = action_doc.get("inputs") or {}
    return inputs if isinstance(inputs, dict) else {}


def is_required_without_default(spec: dict[str, Any]) -> bool:
    """True if an input is ``required: true`` and carries no ``default``.

    A required input *with* a default is satisfied by that default when the
    caller omits it — only the no-default case can fail a run.
    """
    has_default = "default" in spec and spec.get("default") is not None
    return _truthy(spec.get("required", False)) and not has_default


def check_usage(usage: ActionUsage, action_doc: dict[str, Any]) -> list[str]:
    """Return human-readable violation strings for one ``uses:`` occurrence."""
    violations: list[str] = []
    inputs = declared_inputs(action_doc)
    declared_names = set(inputs.keys())
    location = f"{usage.repo}@{usage.sha} (job '{usage.job}', step '{usage.step_name}')"

    unknown = usage.with_keys - declared_names
    for name in sorted(unknown):
        violations.append(
            f"{location}: `with: {name}` is not a declared input of this "
            f"action at this SHA (renamed or removed upstream)."
        )

    missing_required = {
        name for name, spec in inputs.items() if is_required_without_default(spec)
    } - usage.with_keys
    for name in sorted(missing_required):
        violations.append(
            f"{location}: required input `{name}` (no default) is not "
            f"passed under `with:` — this step will fail with "
            f"'Input required and not supplied' at release time."
        )
    return violations


def check_workflow(
    workflow_path: Path,
    *,
    fetcher: Any = None,
) -> tuple[list[ActionUsage], list[str], list[str]]:
    """Run the full check over *workflow_path*.

    Returns ``(usages, violations, fetch_errors)``. Fetching is cached per
    unique ``(repo, sha)`` pair so an action used in several steps or jobs
    is only fetched once.
    """
    usages = find_action_usages(workflow_path)
    cache: dict[tuple[str, str], dict[str, Any] | None] = {}
    violations: list[str] = []
    fetch_errors: list[str] = []

    for usage in usages:
        key = (usage.repo, usage.sha)
        if key not in cache:
            try:
                cache[key] = fetch_action_yaml(usage.repo, usage.sha, fetcher=fetcher)
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                fetch_errors.append(
                    f"{usage.repo}@{usage.sha}: could not fetch action.yml ({exc})"
                )
                cache[key] = None
        action_doc = cache[key]
        if action_doc is None:
            continue
        violations.extend(check_usage(usage, action_doc))

    return usages, violations, fetch_errors


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Exit 0 clean, 1 on a contract violation, 2 on a fetch error."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--workflow",
        type=Path,
        default=DEFAULT_WORKFLOW,
        help="Workflow file to check (default: .github/workflows/release.yml)",
    )
    args = parser.parse_args(argv)

    if not args.workflow.exists():
        print(f"ERROR: workflow file not found: {args.workflow}", file=sys.stderr)
        return 2

    usages, violations, fetch_errors = check_workflow(args.workflow)
    unique_actions = {(u.repo, u.sha) for u in usages}

    if fetch_errors:
        print("ERROR: could not verify the following pinned actions:", file=sys.stderr)
        for err in fetch_errors:
            print(f"  - {err}", file=sys.stderr)
        print(file=sys.stderr)

    if violations:
        print(
            f"ERROR: {args.workflow} `with:` inputs do not match the pinned "
            "action's own declared contract:",
            file=sys.stderr,
        )
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)

    if fetch_errors:
        # Could not complete verification at all — distinct from a positive
        # finding, same as any other "scan could not run" condition (exit 2).
        return 2
    if violations:
        return 1

    print(
        f"OK: {len(usages)} pinned-action usages ({len(unique_actions)} unique "
        f"action@sha pairs) in {args.workflow} match their declared input contracts."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
