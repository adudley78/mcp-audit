#!/usr/bin/env python3
"""Credenzo Team: verify ``mcp-lock.json`` in CI and send drift alerts.

This file is the whole Team action. It uses the Python standard library only
and runs the ``credenzo`` command that is on PATH. It adds nothing to the
check itself: ``credenzo lock --verify`` decides, and its exit code is the
exit code of this step.

What Team adds is the alert. When the check fails on the default branch, on a
schedule or on a manual run, the action

- opens one GitHub issue (and updates or closes it on later runs), and
- sends one message to a webhook, when a webhook URL is given.

Who gets alerts
---------------
- A repository of a personal account: always.
- A public repository: always.
- A private repository of an organization: when the organization has a Team
  subscription. Without one the check runs the same and no alert is sent.

Subscriptions are read from a public list on the ``team-licenses`` branch.
The list holds SHA-256 digests of owner names, not the names. While the list
is not published, or says that subscriptions are not open, every repository
gets alerts (preview).

What leaves the runner
----------------------
One GET of the public list. Alerts go to the repository's own issues and to
the webhook that the workflow gives. An alert holds finding IDs, severities,
server names, tool names and the link to the run. It holds no evidence text,
no path and no config content. Nothing is sent to the Credenzo project.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INDEX_URL = (
    "https://raw.githubusercontent.com/adudley78/credenzo/team-licenses/index.json"
)
INFO_URL = "https://github.com/adudley78/credenzo/blob/main/docs/team.md"
DIGEST_PREFIX = "credenzo-team:"
ISSUE_MARKER = "<!-- credenzo-team-drift"
ISSUE_LABEL = "credenzo-lock-drift"
ISSUE_TITLE = "MCP lock drift"
MAX_INDEX_BYTES = 1024 * 1024
MAX_ROWS = 50
HTTP_TIMEOUT_SECONDS = 15

#: Events on which a failed check is already in front of its author.
NO_ALERT_EVENTS = ("pull_request", "pull_request_target", "merge_group")

#: One fixed sentence for each finding ID. Alerts never carry the finding's
#: own text: a pull request can write a server name, and evidence can hold a
#: path.
MEANINGS = {
    "LOCK-001": "config entry changed after it was locked",
    "LOCK-002": "server is not in the lock",
    "LOCK-003": "locked server is not in the config",
    "LOCK-004": "resolved package version or hash changed",
    "LOCK-005": "lock file was edited by hand or is damaged",
    "LOCK-006": "tool added",
    "LOCK-007": "tool schema or annotations changed",
    "LOCK-008": "tool description or title changed",
    "LOCK-009": "tool removed",
    "LOCK-010": "registry answer changed",
    "LOCK-011": "section digest is missing or wrong",
    "LOCK-012": "lock file was reformatted",
    "LOCK-013": "a credential in the launch line cannot be compared",
    "LOCK-014": "guardrail file allows more than its record",
}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

Fetch = Callable[[urllib.request.Request], tuple[int, bytes]]


def _fetch(request: urllib.request.Request) -> tuple[int, bytes]:
    """Send *request* and return ``(status, body)``. HTTPS only."""
    if not request.full_url.startswith("https://"):
        raise ValueError("only https URLs are used")
    try:
        with urllib.request.urlopen(  # noqa: S310 - scheme checked above
            request, timeout=HTTP_TIMEOUT_SECONDS
        ) as response:
            return response.status, response.read(MAX_INDEX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def owner_digest(owner: str) -> str:
    """Return the digest under which *owner* is listed in the licence list."""
    return hashlib.sha256((DIGEST_PREFIX + owner.strip().lower()).encode()).hexdigest()


def clean_name(value: object) -> str:
    """Return *value* as a short name that is safe inside a code span.

    A server or tool name comes from a config file that a pull request can
    write. Only characters that cannot end a code span, start a mention or
    form a link are kept.
    """
    text = value if isinstance(value, str) else ""
    return re.sub(r"[^A-Za-z0-9._/@:+-]", "?", text)[:80] or "?"


@dataclass(frozen=True)
class Row:
    """One finding as an alert shows it."""

    finding_id: str
    severity: str
    server: str
    tool: str

    def text(self) -> str:
        meaning = MEANINGS.get(self.finding_id, "see the run log")
        subject = f"`{self.server}`"
        if self.tool:
            subject += f" tool `{self.tool}`"
        return f"{self.finding_id} ({self.severity}) {subject}: {meaning}"


def rows_of(payload: dict[str, Any] | None) -> list[Row]:
    """Return the alert rows for a ``lock --verify --format json`` document."""
    findings = (payload or {}).get("findings")
    rows: set[Row] = set()
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, dict):
            continue
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not re.fullmatch(
            r"[A-Z]{2,12}-[0-9A-Za-z]{1,12}", finding_id
        ):
            finding_id = "LOCK-?"
        severity = str(finding.get("severity", "")).upper()
        tool = finding.get("tool")
        rows.add(
            Row(
                finding_id=finding_id,
                severity=severity if severity in SEVERITIES else "UNRATED",
                server=clean_name(finding.get("server")),
                tool=clean_name(tool) if tool else "",
            )
        )
    return sorted(rows, key=lambda r: (r.finding_id, r.server, r.tool, r.severity))


def fingerprint(rows: list[Row], exit_code: int) -> str:
    """Return a short digest that changes when the set of findings changes."""
    material = json.dumps([exit_code, [r.text() for r in rows]], sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def message(rows: list[Row], exit_code: int, repository: str, run_url: str) -> str:
    """Return the alert text. It is the same text for the issue and the webhook."""
    if exit_code == 1:
        head = f"MCP lock drift in `{clean_name(repository)}`."
    else:
        head = (
            f"The MCP lock check could not finish in `{clean_name(repository)}`"
            f" (exit code {exit_code})."
        )
    lines = [head, ""]
    lines += [f"- {row.text()}" for row in rows[:MAX_ROWS]]
    if len(rows) > MAX_ROWS:
        lines.append(f"- and {len(rows) - MAX_ROWS} more")
    if not rows:
        lines.append("- No finding was listed. Read the run log.")
    lines += [
        "",
        f"Run: {run_url}",
        "",
        "Review the change. If it is correct, run `credenzo lock --accept`"
        " and commit `mcp-lock.json`.",
    ]
    return "\n".join(lines)


# --- who gets alerts -------------------------------------------------------


@dataclass(frozen=True)
class Offer:
    """What the published licence list says about the paid offer."""

    live: bool = False
    checkout_url: str = ""
    owners: frozenset[str] = frozenset()


def read_offer(fetch: Fetch = _fetch, url: str = INDEX_URL) -> Offer | None:
    """Return the published offer, or ``None`` when it cannot be read."""
    try:
        status, body = fetch(urllib.request.Request(url))  # noqa: S310
        if status != 200 or len(body) > MAX_INDEX_BYTES:
            return None
        data = json.loads(body.decode("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        return None
    owners = data.get("owners")
    offer = data.get("offer") if isinstance(data.get("offer"), dict) else {}
    checkout = offer.get("checkout_url")
    return Offer(
        live=offer.get("live") is True,
        checkout_url=checkout
        if isinstance(checkout, str) and checkout.startswith("https://")
        else "",
        owners=frozenset(o for o in owners if isinstance(o, str))
        if isinstance(owners, list)
        else frozenset(),
    )


@dataclass(frozen=True)
class Entitlement:
    """Whether this repository gets alerts, and why."""

    alerts: bool
    kind: str
    note: str = ""


def decide(
    owner: str,
    owner_type: str | None,
    private: bool | None,
    offer_reader: Callable[[], Offer | None],
) -> Entitlement:
    """Return who this repository is to Credenzo Team.

    The licence list is read only for a repository that is not known to be
    personal or public.
    """
    if owner_type == "User":
        return Entitlement(True, "personal")
    if private is False:
        return Entitlement(True, "public")
    offer = offer_reader()
    if offer is None:
        return Entitlement(
            True, "unchecked", "The licence list could not be read. Alerts stay on."
        )
    if not offer.live:
        return Entitlement(
            True,
            "preview",
            "Credenzo Team subscriptions are not open yet. Alerts are on.",
        )
    if owner_digest(owner) in offer.owners:
        return Entitlement(True, "licensed")
    where = offer.checkout_url or INFO_URL
    return Entitlement(
        False,
        "unlicensed",
        "Drift alerts for private repositories of an organization are part of"
        " Credenzo Team ($99 a month for up to 10 seats). This run checked the"
        f" lock and sent no alert. Subscribe: {where}",
    )


# --- GitHub ----------------------------------------------------------------


class GitHub:
    """The few REST calls the action makes, on the repository it runs in."""

    def __init__(
        self, api_url: str, repository: str, token: str, fetch: Fetch = _fetch
    ) -> None:
        self._base = f"{api_url.rstrip('/')}/repos/{repository}"
        self._token = token
        self._fetch = fetch

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        """Return the decoded answer, or ``None`` when the call did not succeed."""
        request = urllib.request.Request(  # noqa: S310 - https checked in _fetch
            self._base + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            status, raw = self._fetch(request)
            if not 200 <= status < 300 or not raw:
                return None
            return json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            return None

    def repository(self) -> tuple[str | None, bool | None]:
        """Return ``(owner type, private)`` of the repository."""
        data = self.call("GET", "")
        if not isinstance(data, dict):
            return None, None
        owner = data.get("owner") if isinstance(data.get("owner"), dict) else {}
        private = data.get("private")
        return owner.get("type"), private if isinstance(private, bool) else None

    def open_drift_issue(self) -> dict[str, Any] | None:
        """Return the open issue that this action wrote, when there is one."""
        issues = self.call("GET", "/issues?state=open&per_page=100")
        for issue in issues if isinstance(issues, list) else []:
            if (
                isinstance(issue, dict)
                and "pull_request" not in issue
                and ISSUE_MARKER in str(issue.get("body") or "")
            ):
                return issue
        return None


def sync_issue(github: GitHub, text: str, mark: str, drift: bool) -> str:
    """Open, update or close the drift issue. Return what was done.

    Returns one of ``opened``, ``updated``, ``same``, ``closed``, ``none``
    and ``failed``.
    """
    issue = github.open_drift_issue()
    body = f"{text}\n\n{ISSUE_MARKER}:{mark} -->"
    if not drift:
        if issue is None:
            return "none"
        number = issue.get("number")
        github.call(
            "POST",
            f"/issues/{number}/comments",
            {"body": "The lock check passes again."},
        )
        done = github.call("PATCH", f"/issues/{number}", {"state": "closed"})
        return "closed" if done is not None else "failed"
    if issue is None:
        new = {"title": ISSUE_TITLE, "body": body}
        made = github.call("POST", "/issues", {**new, "labels": [ISSUE_LABEL]})
        if made is None:  # A token that cannot make the label can make the issue.
            made = github.call("POST", "/issues", new)
        return "opened" if made is not None else "failed"
    if f"{ISSUE_MARKER}:{mark} -->" in str(issue.get("body") or ""):
        return "same"
    number = issue.get("number")
    done = github.call("PATCH", f"/issues/{number}", {"body": body})
    github.call(
        "POST",
        f"/issues/{number}/comments",
        {"body": "The findings changed.\n\n" + text},
    )
    return "updated" if done is not None else "failed"


def send_webhook(url: str, text: str, fetch: Fetch = _fetch) -> bool:
    """POST ``{"text": ...}`` to *url*. Return whether the receiver accepted it."""
    request = urllib.request.Request(  # noqa: S310 - https checked in _fetch
        url,
        method="POST",
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        status, _ = fetch(request)
    except (OSError, ValueError):
        return False
    return 200 <= status < 300


# --- the check -------------------------------------------------------------


def run_verify(
    command: str, root: str, connect: bool, resolve: bool
) -> tuple[int, dict[str, Any] | None]:
    """Run ``credenzo lock --verify`` and return ``(exit code, JSON document)``.

    The document is ``None`` when there is no lock file (exit code 0) or when
    the command stopped before it wrote one (exit code 2).
    """
    args = [command, "lock", root, "--verify", "--if-present", "--format", "json"]
    if connect:
        args.append("--connect")
    if resolve:
        args.append("--resolve")
    done = subprocess.run(args, capture_output=True, text=True, check=False)  # noqa: S603
    sys.stderr.write(done.stderr)
    try:
        payload = json.loads(done.stdout) if done.stdout.strip() else None
    except ValueError:
        payload = None
    return done.returncode, payload if isinstance(payload, dict) else None


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def _append(path: str | None, text: str) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)


def _event(path: str | None) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8")) if path else {}
    except (OSError, ValueError):
        data = {}
    return data if isinstance(data, dict) else {}


def main(env: dict[str, str] | None = None, fetch: Fetch = _fetch) -> int:
    """Run the action. Return the exit code of the step."""
    env = dict(os.environ if env is None else env)
    command = shutil.which(env.get("INPUT_COMMAND") or "credenzo")
    if command is None:
        print(
            "::error title=Credenzo Team::The `credenzo` command is not on PATH."
            " Add the `adudley78/credenzo/setup-action` step before this one."
        )
        return 2

    exit_code, payload = run_verify(
        command,
        env.get("INPUT_PATH") or ".",
        _truthy(env.get("INPUT_CONNECT")),
        _truthy(env.get("INPUT_RESOLVE")),
    )
    rows = rows_of(payload)
    drift = exit_code != 0
    repository = env.get("GITHUB_REPOSITORY", "")
    run_url = (
        f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/{repository}"
        f"/actions/runs/{env.get('GITHUB_RUN_ID', '')}"
    )
    text = message(rows, exit_code, repository, run_url)

    if payload is None and exit_code == 0:
        summary = "No `mcp-lock.json` here. Run `credenzo lock` and commit the file."
    elif drift:
        summary = text
    else:
        checked = payload.get("checked_servers", 0) if payload else 0
        summary = f"Lock verified: {checked} server(s)."
    _append(env.get("GITHUB_STEP_SUMMARY"), f"### Credenzo lock check\n\n{summary}\n")

    token = env.get("INPUT_GITHUB_TOKEN", "")
    api_url = env.get("GITHUB_API_URL", "https://api.github.com")
    github = GitHub(api_url, repository, token, fetch)
    event = _event(env.get("GITHUB_EVENT_PATH"))
    repo = event.get("repository")
    repo = repo if isinstance(repo, dict) else {}
    owner = repo.get("owner") if isinstance(repo.get("owner"), dict) else {}
    owner_type, private = owner.get("type"), repo.get("private")
    if owner_type is None or not isinstance(private, bool):
        owner_type, private = github.repository() if token else (None, None)

    entitlement = decide(
        env.get("GITHUB_REPOSITORY_OWNER") or repository.split("/")[0],
        owner_type,
        private,
        lambda: read_offer(fetch, env.get("CREDENZO_TEAM_INDEX_URL") or INDEX_URL),
    )
    if entitlement.note:
        print(f"::notice title=Credenzo Team::{entitlement.note}")

    alerted = "off"
    if env.get("GITHUB_EVENT_NAME", "") in NO_ALERT_EVENTS:
        alerted = "not on this event"
    elif entitlement.alerts:
        mark = fingerprint(rows, exit_code)
        changed = drift
        if _truthy(env.get("INPUT_ALERT_ISSUE", "true")) and token:
            alerted = sync_issue(github, text, mark, drift)
            changed = alerted in ("opened", "updated", "failed")
            if alerted == "failed":
                print(
                    "::warning title=Credenzo Team::The drift issue could not be"
                    " written. Give the job `issues: write`."
                )
        webhook = (env.get("INPUT_ALERT_WEBHOOK") or "").strip()
        if webhook and drift and changed:
            sent = webhook.startswith("https://") and send_webhook(webhook, text, fetch)
            if not sent:
                print(
                    "::warning title=Credenzo Team::The alert webhook did not"
                    " accept the message."
                )
            alerted = f"{alerted}, webhook {'sent' if sent else 'failed'}"

    _append(
        env.get("GITHUB_OUTPUT"),
        f"drift={'true' if drift else 'false'}\n"
        f"plan={entitlement.kind}\nalert={alerted}\n",
    )
    if exit_code == 1 and not _truthy(env.get("INPUT_FAIL_ON_DRIFT", "true")):
        return 0
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
