"""The Credenzo Team action (`team/`): who gets alerts and what an alert holds.

The end-to-end tests write a real lock with the real `credenzo lock`, change
the config and run the action's `main()` on it. Only the network is replaced.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import urllib.request
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TEAM = ROOT / "team"

_spec = importlib.util.spec_from_file_location(
    "credenzo_team", TEAM / "credenzo_team.py"
)
team = importlib.util.module_from_spec(_spec)
sys.modules["credenzo_team"] = team
_spec.loader.exec_module(team)


def _console_script() -> Path:
    """The `credenzo` script of the Python that runs the tests."""
    name = "credenzo.exe" if sys.platform == "win32" else "credenzo"
    home = Path(sys.executable).parent
    for candidate in (home / name, home / "Scripts" / name):
        if candidate.exists():
            return candidate
    found = shutil.which("credenzo")
    return Path(found) if found else home / name


CREDENZO = _console_script()
needs_cli = pytest.mark.skipif(
    not CREDENZO.exists(), reason="the credenzo console script is not installed"
)


class Net:
    """A fake network: the licence list, the GitHub API and a webhook."""

    def __init__(
        self,
        index: dict | None = None,
        issues: list[dict] | None = None,
        repo: dict | None = None,
        login: str | None = None,
    ) -> None:
        self.index = index
        self.issues = issues or []
        self.repo = repo
        self.login = login
        self.calls: list[tuple[str, str, dict | None]] = []

    def __call__(self, request: urllib.request.Request) -> tuple[int, bytes]:
        url, method = request.full_url, request.get_method()
        body = json.loads(request.data) if request.data else None
        self.calls.append((method, url, body))
        if url.startswith("https://raw.githubusercontent.com/"):
            if self.index is None:
                return 404, b""
            return 200, json.dumps(self.index).encode()
        if url.startswith("https://hooks.example/"):
            return 200, b"ok"
        if url.endswith("/repos/acme/app"):
            return (200, json.dumps(self.repo).encode()) if self.repo else (404, b"")
        if url.endswith("/user"):
            if self.login is None:  # the workflow token cannot read /user
                return 403, b""
            return 200, json.dumps({"login": self.login}).encode()
        if "/issues?" in url:
            return 200, json.dumps(self.issues).encode()
        return 201, b"{}"

    def sent(self, method: str, part: str) -> list[dict | None]:
        return [b for m, u, b in self.calls if m == method and part in u]


BOT = {"login": "github-actions[bot]", "type": "Bot"}


def _scope(root: Path, connect: bool = False) -> str:
    """The scope key of the check that `_run` makes on *root*."""
    return team.Scope("MCP lock", "lock", str(root), connect, False).key()


def _issue(root: Path, mark: str = "0" * 16, number: int = 7, **fields: object) -> dict:
    body = f"old\n\n{team.ISSUE_MARKER}:{_scope(root)}:{mark} -->"
    return {"number": number, "body": body, "user": BOT, **fields}


def _index(*owners: str, live: bool = True) -> dict:
    return {
        "schema_version": 1,
        "offer": {"live": live, "checkout_url": "https://buy.stripe.example/x"},
        "owners": sorted(team.owner_digest(o) for o in owners),
    }


# --- who gets alerts -------------------------------------------------------


def _decide(owner_type: str | None, private: bool | None, offer: object) -> object:
    return team.decide("Acme", owner_type, private, lambda: offer)


def test_a_personal_account_gets_alerts_and_the_list_is_not_read() -> None:
    def never() -> None:
        raise AssertionError("the licence list was read")

    assert team.decide("me", "User", True, never).kind == "personal"
    assert team.decide("acme", "Organization", False, never).kind == "public"


def test_an_organization_with_a_subscription_gets_alerts() -> None:
    offer = team.Offer(live=True, owners=frozenset({team.owner_digest("acme")}))
    got = _decide("Organization", True, offer)
    assert (got.alerts, got.kind) == (True, "licensed")


def test_the_owner_name_is_matched_without_case() -> None:
    assert team.owner_digest("Acme") == team.owner_digest(" acme ")


def test_an_organization_with_no_subscription_gets_the_check_and_no_alert() -> None:
    offer = team.Offer(live=True, checkout_url="https://buy.stripe.example/x")
    got = _decide("Organization", True, offer)
    assert (got.alerts, got.kind) == (False, "unlicensed")
    assert "https://buy.stripe.example/x" in got.note
    assert "$99" in got.note


def test_alerts_stay_on_before_subscriptions_open() -> None:
    assert _decide("Organization", True, team.Offer(live=False)).kind == "preview"


def test_alerts_stay_on_when_the_list_cannot_be_read() -> None:
    got = _decide("Organization", True, None)
    assert (got.alerts, got.kind) == (True, "unchecked")


def test_an_unknown_repository_is_checked_against_the_list() -> None:
    assert _decide(None, None, team.Offer(live=True)).kind == "unlicensed"


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"[]",
        b"{",
        b'{"schema_version": 2, "owners": []}',
        b"x" * (1024 * 1024 + 1),
    ],
)
def test_a_list_that_is_not_the_expected_document_is_not_read(body: bytes) -> None:
    assert team.read_offer(lambda _request: (200, body)) is None


def test_a_checkout_link_that_is_not_https_is_dropped() -> None:
    doc = {"schema_version": 1, "offer": {"live": True, "checkout_url": "javascript:x"}}
    offer = team.read_offer(lambda _request: (200, json.dumps(doc).encode()))
    assert offer == team.Offer(live=True)


# --- what an alert holds ---------------------------------------------------


def test_a_name_cannot_leave_its_code_span() -> None:
    assert team.clean_name("evil`x @all <!here> [a](b)") == "evil?x?@all???here???a??b?"
    assert team.clean_name(None) == "?"
    assert len(team.clean_name("a" * 500)) == 80


def test_rows_hold_ids_and_names_and_never_the_finding_text() -> None:
    payload = {
        "findings": [
            {
                "id": "LOCK-006",
                "severity": "high",
                "server": "files",
                "tool": "read",
                "title": "SECRET-TITLE",
                "evidence": "/home/someone/secret",
            },
            {"id": "not an id <x>", "severity": "weird", "server": 7},
            "junk",
        ]
    }
    rows = team.rows_of(payload)
    text = team.message(
        rows, 1, "acme/app", "https://github.com/acme/app/actions/runs/1"
    )
    assert "LOCK-006 (HIGH) `files` tool `read`: tool added" in text
    assert "LOCK-? (UNRATED) `?`: see the run log" in text
    assert "SECRET-TITLE" not in text and "/home/someone" not in text


def test_every_lock_finding_id_has_a_sentence() -> None:
    """A LOCK ID that `lock --verify` can report is in the table."""
    import re

    source = "".join(
        p.read_text(encoding="utf-8")
        for p in (ROOT / "src" / "mcp_audit" / "lock").glob("*.py")
    )
    reported = set(re.findall(r'"(LOCK-\d{3})"', source))
    assert reported, "no LOCK IDs found in the lock package"
    assert sorted(reported - set(team.MEANINGS)) == []


def test_the_fingerprint_follows_the_findings() -> None:
    one = [team.Row("LOCK-001", "HIGH", "a", "")]
    two = [*one, team.Row("LOCK-002", "HIGH", "b", "")]
    assert team.fingerprint(one, 1) == team.fingerprint(list(one), 1)
    assert team.fingerprint(one, 1) != team.fingerprint(two, 1)
    assert team.fingerprint(one, 1) != team.fingerprint(one, 2)


def test_a_long_list_is_cut() -> None:
    rows = [team.Row("LOCK-002", "HIGH", f"s{i:03}", "") for i in range(70)]
    text = team.message(rows, 1, "acme/app", "u")
    assert text.count("\n- LOCK-002") == team.MAX_ROWS
    assert "- and 20 more" in text


# --- the action on a real lock ---------------------------------------------


@pytest.fixture
def project(tmp_path: Path) -> Path:
    import subprocess

    root = tmp_path / "app"
    root.mkdir()
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "files": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(  # noqa: S603
        [str(CREDENZO), "lock", str(root), "--offline"],
        check=True,
        capture_output=True,
    )
    return root


def _drift(root: Path) -> None:
    config = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))
    config["mcpServers"]["evil`x @all <!here>"] = {"command": "node", "args": ["x.js"]}
    (root / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")


def _run(
    root: Path,
    tmp_path: Path,
    net: Net,
    event_name: str = "schedule",
    owner_type: str = "Organization",
    private: bool = True,
    ref: str = "refs/heads/main",
    **inputs: str,
) -> tuple[int, dict[str, str]]:
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "repository": {
                    "private": private,
                    "owner": {"type": owner_type},
                    "default_branch": "main",
                }
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "output.txt"
    output.write_text("", encoding="utf-8")
    env = {
        "INPUT_COMMAND": str(CREDENZO),
        "INPUT_PATH": str(root),
        "INPUT_GITHUB_TOKEN": "t",
        "GITHUB_REPOSITORY": "acme/app",
        "GITHUB_REPOSITORY_OWNER": "acme",
        "GITHUB_EVENT_NAME": event_name,
        "GITHUB_REF": ref,
        "GITHUB_WORKFLOW": "MCP lock",
        "GITHUB_JOB": "lock",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_RUN_ID": "42",
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        **inputs,
    }
    code = team.main(env, net)
    lines = output.read_text(encoding="utf-8").splitlines()
    return code, dict(line.split("=", 1) for line in lines)


@needs_cli
def test_a_clean_lock_passes_and_sends_nothing(project: Path, tmp_path: Path) -> None:
    net = Net(index=_index("acme"))
    code, out = _run(
        project, tmp_path, net, INPUT_ALERT_WEBHOOK="https://hooks.example/a"
    )
    assert (code, out["drift"], out["plan"], out["alert"]) == (
        0,
        "false",
        "licensed",
        "none",
    )
    assert net.sent("POST", "") == []


@needs_cli
def test_drift_opens_an_issue_and_sends_the_webhook(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _drift(project)
    net = Net(index=_index("acme"))
    code, out = _run(
        project, tmp_path, net, INPUT_ALERT_WEBHOOK="https://hooks.example/a"
    )
    assert code == 1
    assert out == {"drift": "true", "plan": "licensed", "alert": "opened, webhook sent"}
    (issue,) = net.sent("POST", "/repos/acme/app/issues")
    assert issue["title"] == "MCP lock drift"
    assert (
        "LOCK-002 (HIGH) `evil?x?@all???here?`: server is not in the lock"
        in issue["body"]
    )
    assert "https://github.com/acme/app/actions/runs/42" in issue["body"]
    (hook,) = net.sent("POST", "hooks.example")
    assert set(hook) == {"text"} and "LOCK-002" in hook["text"]
    assert "`" not in hook["text"].replace("`evil?x?@all???here?`", "").replace(
        "`acme/app`", ""
    ).replace("`credenzo lock --accept`", "").replace("`mcp-lock.json`", "").replace(
        "`MCP?lock`", ""
    ).replace("`lock`", "")
    assert "MCP lock drift" in (tmp_path / "summary.md").read_text(encoding="utf-8")


@needs_cli
def test_the_same_drift_is_reported_once(project: Path, tmp_path: Path) -> None:
    _drift(project)
    first = Net(index=_index("acme"))
    _run(project, tmp_path, first, INPUT_ALERT_WEBHOOK="https://hooks.example/a")
    (issue,) = first.sent("POST", "/repos/acme/app/issues")
    again = Net(
        index=_index("acme"), issues=[{"number": 7, "body": issue["body"], "user": BOT}]
    )
    code, out = _run(
        project, tmp_path, again, INPUT_ALERT_WEBHOOK="https://hooks.example/a"
    )
    assert (code, out["alert"]) == (1, "same")
    assert again.sent("POST", "") == [] and again.sent("PATCH", "") == []


@needs_cli
def test_new_findings_update_the_issue_and_send_again(
    project: Path, tmp_path: Path
) -> None:
    _drift(project)
    net = Net(index=_index("acme"), issues=[_issue(project)])
    _, out = _run(project, tmp_path, net, INPUT_ALERT_WEBHOOK="https://hooks.example/a")
    assert out["alert"] == "updated, webhook sent"
    assert len(net.sent("PATCH", "/issues/7")) == 1
    assert len(net.sent("POST", "/issues/7/comments")) == 1


@needs_cli
def test_a_passing_check_closes_the_issue(project: Path, tmp_path: Path) -> None:
    old = _issue(project)
    pull = {**old, "number": 8, "pull_request": {}}
    net = Net(index=_index("acme"), issues=[pull, old])
    code, out = _run(project, tmp_path, net)
    assert (code, out["alert"]) == (0, "closed")
    assert net.sent("PATCH", "/issues/7") == [{"state": "closed"}]
    assert net.sent("PATCH", "/issues/8") == []


@needs_cli
def test_no_subscription_keeps_the_check_and_sends_no_alert(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _drift(project)
    net = Net(index=_index("someone-else"))
    code, out = _run(
        project, tmp_path, net, INPUT_ALERT_WEBHOOK="https://hooks.example/a"
    )
    assert code == 1
    assert out == {"drift": "true", "plan": "unlicensed", "alert": "off"}
    assert [m for m, _, _ in net.calls] == ["GET"]
    assert capsys.readouterr().out.count("::notice title=Credenzo Team::") == 1


@needs_cli
def test_a_notice_is_printed_only_when_an_alert_was_held_back(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No notice on a passing run, on a pull request, or before the offer is live."""
    _run(project, tmp_path, Net(index=_index("someone-else")))
    _run(project, tmp_path, Net(index=_index(live=False)))
    _run(project, tmp_path, Net(index=None))
    _drift(project)
    _run(
        project, tmp_path, Net(index=_index("someone-else")), event_name="pull_request"
    )
    _run(project, tmp_path, Net(index=_index("someone-else")), ref="refs/heads/topic")
    _run(project, tmp_path, Net(index=_index(live=False)))
    assert "::notice" not in capsys.readouterr().out


# --- whose issue it is -----------------------------------------------------


@needs_cli
def test_an_issue_that_a_stranger_planted_is_not_read(
    project: Path, tmp_path: Path
) -> None:
    """The exact marker of the coming drift, in an issue from another account."""
    _drift(project)
    first = Net(index=_index("acme"))
    _run(project, tmp_path, first)
    (ours,) = first.sent("POST", "/repos/acme/app/issues")
    planted = {
        "number": 5,
        "body": ours["body"],
        "user": {"login": "mallory", "type": "User"},
    }
    net = Net(index=_index("acme"), issues=[planted])
    code, out = _run(
        project, tmp_path, net, INPUT_ALERT_WEBHOOK="https://hooks.example/a"
    )
    assert (code, out["alert"]) == (1, "opened, webhook sent")
    assert net.sent("PATCH", "/issues/5") == []
    assert net.sent("POST", "/issues/5/comments") == []


@needs_cli
def test_a_stranger_cannot_get_the_issue_closed_or_use_the_label(
    project: Path, tmp_path: Path
) -> None:
    planted = _issue(
        project,
        number=5,
        user={"login": "mallory", "type": "User"},
        labels=[{"name": team.ISSUE_LABEL}],
    )
    net = Net(index=_index("acme"), issues=[planted])
    code, out = _run(project, tmp_path, net)
    assert (code, out["alert"]) == (0, "none")
    assert net.sent("PATCH", "") == []


@needs_cli
def test_an_issue_of_another_bot_counts_only_with_the_label(
    project: Path, tmp_path: Path
) -> None:
    """A token of a GitHub App writes as that app, and cannot read /user."""
    app = {"login": "acme-ci[bot]", "type": "Bot"}
    bare = Net(index=_index("acme"), issues=[_issue(project, user=app)])
    assert _run(project, tmp_path, bare)[1]["alert"] == "none"
    labelled = _issue(project, user=app, labels=[{"name": team.ISSUE_LABEL}])
    net = Net(index=_index("acme"), issues=[labelled])
    assert _run(project, tmp_path, net)[1]["alert"] == "closed"


@needs_cli
def test_a_user_token_reads_its_own_issues(project: Path, tmp_path: Path) -> None:
    alice = {"login": "alice", "type": "User"}
    net = Net(index=_index("acme"), issues=[_issue(project, user=alice)], login="alice")
    assert _run(project, tmp_path, net)[1]["alert"] == "closed"
    assert any("creator=alice" in u for _, u, _ in net.calls)
    other = Net(index=_index("acme"), issues=[_issue(project, user=BOT)], login="alice")
    assert _run(project, tmp_path, other)[1]["alert"] == "none"


@needs_cli
def test_the_issue_list_is_asked_for_this_account_only(
    project: Path, tmp_path: Path
) -> None:
    net = Net(index=_index("acme"))
    _run(project, tmp_path, net)
    queries = [u.split("?", 1)[1] for _, u, _ in net.calls if "/issues?" in u]
    assert queries == [
        "state=open&per_page=100&creator=github-actions%5Bbot%5D",
        "state=open&per_page=100&labels=credenzo-lock-drift",
    ]


# --- one issue for each check ----------------------------------------------


@needs_cli
def test_a_passing_check_does_not_close_the_issue_of_another_check(
    project: Path, tmp_path: Path
) -> None:
    """The scheduled check with `connect` found drift; the push check passes."""
    other = team.Scope("MCP lock", "lock", str(project), True, False).key()
    body = f"old\n\n{team.ISSUE_MARKER}:{other}:{'0' * 16} -->"
    net = Net(index=_index("acme"), issues=[{"number": 7, "body": body, "user": BOT}])
    code, out = _run(project, tmp_path, net)
    assert (code, out["alert"]) == (0, "none")
    assert net.sent("PATCH", "") == []


@needs_cli
def test_a_run_on_another_branch_sends_and_closes_nothing(
    project: Path, tmp_path: Path
) -> None:
    net = Net(index=_index("acme"), issues=[_issue(project)])
    code, out = _run(project, tmp_path, net, ref="refs/heads/topic")
    assert (code, out["alert"]) == (0, "not on this branch")
    _drift(project)
    code, out = _run(
        project,
        tmp_path,
        net,
        ref="refs/heads/topic",
        event_name="push",
        INPUT_ALERT_WEBHOOK="https://hooks.example/a",
    )
    assert (code, out["alert"]) == (1, "not on this branch")
    assert net.sent("PATCH", "") == [] and net.sent("POST", "") == []


@needs_cli
def test_the_alert_names_its_check(project: Path, tmp_path: Path) -> None:
    _drift(project)
    net = Net(index=_index("acme"))
    _run(project, tmp_path, net)
    (issue,) = net.sent("POST", "/repos/acme/app/issues")
    assert "Check: workflow `MCP?lock`, job `lock`." in issue["body"]


# --- an alert never changes the result -------------------------------------


class Broken(Net):
    """A network that fails in a way that is not an OSError."""

    def __init__(self, error: BaseException, part: str, **kw: object) -> None:
        super().__init__(**kw)
        self.error, self.part = error, part

    def __call__(self, request: urllib.request.Request) -> tuple[int, bytes]:
        if self.part in request.full_url:
            raise self.error
        return super().__call__(request)


@needs_cli
@pytest.mark.parametrize("part", ["raw.githubusercontent", "/issues", "hooks.example"])
@pytest.mark.parametrize("drift", [False, True])
def test_a_broken_network_does_not_change_the_exit_code(
    project: Path, tmp_path: Path, part: str, drift: bool
) -> None:
    import http.client

    if drift:
        _drift(project)
    for error in (http.client.IncompleteRead(b""), RecursionError(), KeyError("x")):
        net = Broken(error, part, index=_index("acme"))
        code, _ = _run(
            project, tmp_path, net, INPUT_ALERT_WEBHOOK="https://hooks.example/a"
        )
        assert code == (1 if drift else 0), (part, error)


@needs_cli
def test_a_fault_in_the_alert_step_is_a_warning(
    project: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _drift(project)

    def boom(*_a: object, **_k: object) -> str:
        raise RuntimeError("boom")

    monkeypatch.setattr(team, "sync_issue", boom)
    code, _ = _run(project, tmp_path, Net(index=_index("acme")))
    out = capsys.readouterr().out
    assert code == 1
    assert "::warning title=Credenzo Team::The alert step stopped (RuntimeError)" in out


def test_a_list_nested_too_deep_is_unchecked() -> None:
    deep = Net()
    deep.__class__ = type(
        "Deep", (Net,), {"__call__": lambda self, request: (200, b"[" * 200_000)}
    )
    assert team.read_offer(deep) is None


def test_a_redirect_is_refused() -> None:
    handler = team._NoRedirect()
    request = urllib.request.Request("https://api.github.com/x")  # noqa: S310
    assert (
        handler.redirect_request(
            request, None, 302, "Found", {}, "https://evil.example/"
        )
        is None
    )
    redirectors = [
        h
        for h in team._OPENER.handlers
        if isinstance(h, urllib.request.HTTPRedirectHandler)
    ]
    assert [type(h) for h in redirectors] == [team._NoRedirect]


def test_a_check_that_does_not_end_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import subprocess

    def never(*_a: object, **kw: object) -> None:
        assert kw["timeout"] == team.VERIFY_TIMEOUT_SECONDS
        raise subprocess.TimeoutExpired("credenzo", kw["timeout"])

    monkeypatch.setattr(team.subprocess, "run", never)
    assert team.run_verify("credenzo", ".", True, False) == (2, None)
    assert "did not end" in capsys.readouterr().out


def test_an_item_that_was_not_verified_is_listed_without_its_reason() -> None:
    payload = {
        "findings": [],
        "unverified": [
            {"kind": "entry", "name": "notes`@all", "reason": "stderr: /home/x token"},
            "junk",
        ],
    }
    lines = team.unverified_of(payload)
    assert lines == ["not verified (entry): `notes?@all`"]
    text = team.message([], 1, "acme/app", "https://x/run", lines)
    assert "- not verified (entry): `notes?@all`" in text
    assert "stderr" not in text and "No finding was listed" not in text
    assert team.fingerprint([], 1, lines) != team.fingerprint([], 1)


@needs_cli
@pytest.mark.parametrize(
    ("owner_type", "private", "plan"),
    [("User", True, "personal"), ("Organization", False, "public")],
)
def test_personal_and_public_repositories_get_alerts_with_no_list(
    project: Path, tmp_path: Path, owner_type: str, private: bool, plan: str
) -> None:
    _drift(project)
    net = Net(index=None)
    _, out = _run(project, tmp_path, net, owner_type=owner_type, private=private)
    assert (out["plan"], out["alert"]) == (plan, "opened")
    assert not [u for _, u, _ in net.calls if "raw.githubusercontent" in u]


@needs_cli
def test_a_pull_request_gets_the_check_and_no_alert(
    project: Path, tmp_path: Path
) -> None:
    _drift(project)
    net = Net(index=_index("acme"))
    code, out = _run(project, tmp_path, net, event_name="pull_request")
    assert (code, out["alert"]) == (1, "not on this event")
    assert net.sent("POST", "") == []


@needs_cli
def test_fail_on_drift_false_reports_and_passes(project: Path, tmp_path: Path) -> None:
    _drift(project)
    code, out = _run(
        project, tmp_path, Net(index=_index("acme")), INPUT_FAIL_ON_DRIFT="false"
    )
    assert (code, out["drift"], out["alert"]) == (0, "true", "opened")


@needs_cli
def test_a_webhook_that_is_not_https_is_not_called(
    project: Path, tmp_path: Path
) -> None:
    _drift(project)
    net = Net(index=_index("acme"))
    _, out = _run(project, tmp_path, net, INPUT_ALERT_WEBHOOK="http://hooks.example/a")
    assert out["alert"] == "opened, webhook failed"
    assert not [u for _, u, _ in net.calls if "hooks.example" in u]


@needs_cli
def test_no_lock_file_passes(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    code, out = _run(empty, tmp_path, Net(index=_index("acme")))
    assert (code, out["drift"]) == (0, "false")
    assert "No `mcp-lock.json` here" in (tmp_path / "summary.md").read_text(
        encoding="utf-8"
    )


def test_a_missing_command_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert team.main({"INPUT_COMMAND": "no-such-credenzo-command"}, Net()) == 2
    assert "::error title=Credenzo Team::" in capsys.readouterr().out


def test_the_repository_is_read_from_the_api_when_the_event_does_not_say() -> None:
    net = Net(repo={"private": True, "owner": {"type": "Organization"}})
    github = team.GitHub("https://api.github.com", "acme/app", "t", net)
    assert github.repository() == {"private": True, "owner": {"type": "Organization"}}
    assert (
        team.GitHub("https://api.github.com", "acme/app", "t", Net()).repository() == {}
    )


@needs_cli
def test_the_default_branch_is_read_from_the_api_when_the_event_does_not_say(
    project: Path, tmp_path: Path
) -> None:
    repo = {
        "private": True,
        "owner": {"type": "Organization"},
        "default_branch": "trunk",
    }
    net = Net(index=_index("acme"), repo=repo, issues=[_issue(project)])
    event = tmp_path / "bare.json"
    event.write_text("{}", encoding="utf-8")
    code, out = _run(project, tmp_path, net, GITHUB_EVENT_PATH=str(event))
    assert (code, out["plan"], out["alert"]) == (0, "licensed", "not on this branch")
    code, out = _run(
        project, tmp_path, net, ref="refs/heads/trunk", GITHUB_EVENT_PATH=str(event)
    )
    assert out["alert"] == "closed"


def test_only_https_is_fetched() -> None:
    with pytest.raises(ValueError, match="https"):
        team._fetch(urllib.request.Request("http://example.com/"))  # noqa: S310


# --- the files -------------------------------------------------------------


def test_the_script_uses_the_standard_library_only() -> None:
    import ast

    tree = ast.parse((TEAM / "credenzo_team.py").read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    assert names - set(sys.stdlib_module_names) == {"__future__"} - set(
        sys.stdlib_module_names
    )
    assert "mcp_audit" not in names


def test_the_team_code_is_not_in_the_package() -> None:
    """Every command in the package stays free: nothing there reads a licence."""
    for path in (ROOT / "src" / "mcp_audit").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "team-licenses" not in text and "credenzo_team" not in text, path


def test_the_action_file() -> None:
    action = yaml.safe_load((TEAM / "action.yml").read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    for name, spec in action["inputs"].items():
        assert spec.get("description"), name
        assert "required" in spec, name
    assert set(action["outputs"]) == {"drift", "plan", "alert"}
    (step,) = action["runs"]["steps"]
    assert "uses" not in step
    # No input reaches the shell as text: each one is an environment variable.
    assert "${{" not in step["run"]
    wanted = {f"INPUT_{name.upper().replace('-', '_')}" for name in action["inputs"]}
    assert wanted <= set(step["env"])


def test_the_offer_file() -> None:
    offer = json.loads((TEAM / "offer.json").read_text(encoding="utf-8"))
    assert set(offer) == {
        "name",
        "price_usd_per_month",
        "seats",
        "live_since",
        "checkout_url",
        "portal_url",
        "payment_link_id",
    }
    assert (offer["price_usd_per_month"], offer["seats"]) == (99, 10)
    live = offer["live_since"] is not None
    assert (offer["checkout_url"] is not None) == live
    assert (offer["payment_link_id"] is not None) == live
