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
    ) -> None:
        self.index = index
        self.issues = issues or []
        self.repo = repo
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
        if "/issues?" in url:
            return 200, json.dumps(self.issues).encode()
        return 201, b"{}"

    def sent(self, method: str, part: str) -> list[dict | None]:
        return [b for m, u, b in self.calls if m == method and part in u]


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
    **inputs: str,
) -> tuple[int, dict[str, str]]:
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps({"repository": {"private": private, "owner": {"type": owner_type}}}),
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
    ).replace("`credenzo lock --accept`", "").replace("`mcp-lock.json`", "")
    assert "MCP lock drift" in (tmp_path / "summary.md").read_text(encoding="utf-8")


@needs_cli
def test_the_same_drift_is_reported_once(project: Path, tmp_path: Path) -> None:
    _drift(project)
    first = Net(index=_index("acme"))
    _run(project, tmp_path, first, INPUT_ALERT_WEBHOOK="https://hooks.example/a")
    (issue,) = first.sent("POST", "/repos/acme/app/issues")
    again = Net(index=_index("acme"), issues=[{"number": 7, "body": issue["body"]}])
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
    old = {"number": 7, "body": f"old\n\n{team.ISSUE_MARKER}:0000000000000000 -->"}
    net = Net(index=_index("acme"), issues=[old])
    _, out = _run(project, tmp_path, net, INPUT_ALERT_WEBHOOK="https://hooks.example/a")
    assert out["alert"] == "updated, webhook sent"
    assert len(net.sent("PATCH", "/issues/7")) == 1
    assert len(net.sent("POST", "/issues/7/comments")) == 1


@needs_cli
def test_a_passing_check_closes_the_issue(project: Path, tmp_path: Path) -> None:
    old = {"number": 7, "body": f"old\n\n{team.ISSUE_MARKER}:0000000000000000 -->"}
    pull = {"number": 8, "pull_request": {}, "body": old["body"]}
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
    assert "::notice title=Credenzo Team::" in capsys.readouterr().out


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
    assert github.repository() == ("Organization", True)
    assert team.GitHub(
        "https://api.github.com", "acme/app", "t", Net()
    ).repository() == (
        None,
        None,
    )


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
