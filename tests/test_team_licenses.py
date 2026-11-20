"""`scripts/team_licenses.py` and `team-licenses.yml`: Stripe to the licence list."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "team-licenses.yml"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


lic = _load("team_licenses", ROOT / "scripts" / "team_licenses.py")
team = _load("credenzo_team_for_licences", ROOT / "team" / "credenzo_team.py")

SALT = "s" * 32
LIVE = {
    "live_since": "2026-12-01",
    "checkout_url": "https://buy.stripe.example/x",
    "payment_link_id": "plink_1",
    "price_usd_per_month": 99,
    "seats": 10,
}


def _session(subscription: object, typed: object, key: str = "githubowner") -> dict:
    return {
        "id": f"cs_{subscription}",
        "subscription": subscription,
        "custom_fields": [
            {"key": "other", "type": "text", "text": {"value": "nope"}},
            {"key": key, "type": "text", "text": {"value": typed}},
        ],
    }


class Stripe:
    """A fake Stripe that serves two lists, 100 objects to a page."""

    def __init__(self, sessions: list[dict], subscriptions: list[dict]) -> None:
        self.lists = {
            "/v1/checkout/sessions": sessions,
            "/v1/subscriptions": subscriptions,
        }
        self.paths: list[str] = []

    def __call__(self, path: str) -> dict:
        from urllib.parse import parse_qs, urlsplit

        self.paths.append(path)
        parts = urlsplit(path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        items = self.lists[parts.path]
        start = 0
        if "starting_after" in query:
            start = [i["id"] for i in items].index(query["starting_after"]) + 1
        page = items[start : start + int(query["limit"])]
        return {"data": page, "has_more": start + len(page) < len(items)}


# --- owner names -----------------------------------------------------------


@pytest.mark.parametrize(
    ("typed", "names"),
    [
        ("Acme", ["acme"]),
        (" @acme-corp ", ["acme-corp"]),
        ("https://github.com/Acme/app", ["acme"]),
        ("github.com/acme", ["acme"]),
        ("acme, beta  gamma", ["acme", "beta", "gamma"]),
        ("acme,acme", ["acme"]),
    ],
)
def test_owner_names_are_read(typed: str, names: list[str]) -> None:
    assert lic.owner_names(typed) == (names, False)


@pytest.mark.parametrize(
    "typed", ["", "   ", None, 7, "-acme", "acme-", "a--b", "a" * 40, "ac me!", "a_b"]
)
def test_text_that_is_not_an_owner_name_is_reported(typed: object) -> None:
    names, bad = lic.owner_names(typed)
    assert bad is True
    assert all(lic._OWNER.fullmatch(n) for n in names)


def test_a_checkout_names_three_owners_at_most() -> None:
    assert lic.owner_names("a b c d") == (["a", "b", "c"], True)


def test_the_two_digests_are_the_same() -> None:
    assert lic.DIGEST_PREFIX == team.DIGEST_PREFIX
    assert lic.owner_digest("Acme") == team.owner_digest("acme")


# --- subscriptions ---------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "listed"),
    [
        ("active", True),
        ("trialing", True),
        ("past_due", True),
        ("canceled", False),
        ("unpaid", False),
        ("incomplete", False),
        ("incomplete_expired", False),
        ("paused", False),
    ],
)
def test_only_a_subscription_in_force_is_listed(status: str, listed: bool) -> None:
    owners, unusable = lic.subscribed_owners(
        [_session("sub_1", "acme")], [{"id": "sub_1", "status": status}]
    )
    assert (owners == {"acme"}) is listed
    assert unusable is False


def test_a_checkout_with_no_known_subscription_is_not_listed() -> None:
    sessions = [_session("sub_gone", "acme"), _session(None, "beta")]
    assert lic.subscribed_owners(sessions, []) == (set(), False)


def test_an_expanded_subscription_object_is_read() -> None:
    sessions = [_session({"id": "sub_1"}, "acme")]
    owners, _ = lic.subscribed_owners(sessions, [{"id": "sub_1", "status": "active"}])
    assert owners == {"acme"}


def test_unusable_text_is_reported_only_for_a_subscription_in_force() -> None:
    subs = [{"id": "sub_1", "status": "active"}, {"id": "sub_2", "status": "canceled"}]
    assert lic.subscribed_owners([_session("sub_2", "!!")], subs) == (set(), False)
    assert lic.subscribed_owners([_session("sub_1", "!!")], subs) == (set(), True)
    wrong_key = [_session("sub_1", "acme", key="company")]
    assert lic.subscribed_owners(wrong_key, subs) == (set(), True)


# --- the list --------------------------------------------------------------


def test_the_length_of_the_list_does_not_show_the_number_of_subscribers() -> None:
    none = lic.build_index(LIVE, set(), SALT)["owners"]
    some = lic.build_index(LIVE, {f"org{i}" for i in range(40)}, SALT)["owners"]
    assert len(none) == len(some) == 64
    assert (
        len(lic.build_index(LIVE, {f"o{i}" for i in range(65)}, SALT)["owners"]) == 128
    )
    for owners in (none, some):
        assert owners == sorted(set(owners))
        assert all(len(o) == 64 and int(o, 16) >= 0 for o in owners)


def test_fillers_do_not_change_between_runs_and_depend_on_the_secret() -> None:
    assert lic.padded(set(), SALT) == lic.padded(set(), SALT)
    assert not set(lic.padded(set(), SALT)) & set(lic.padded(set(), "t" * 32))
    one = lic.padded({lic.owner_digest("acme")}, SALT)
    assert len(set(one) - set(lic.padded(set(), SALT))) == 1


def test_the_team_action_reads_the_list_that_this_script_writes() -> None:
    index = lic.build_index(LIVE, {"acme"}, SALT)
    offer = team.read_offer(lambda _request: (200, json.dumps(index).encode()))
    assert offer.live is True
    assert offer.checkout_url == "https://buy.stripe.example/x"
    got = team.decide("Acme", "Organization", True, lambda: offer)
    assert got.kind == "licensed"
    assert (
        team.decide("other", "Organization", True, lambda: offer).kind == "unlicensed"
    )


def test_the_list_says_closed_until_the_offer_is_live() -> None:
    closed = {**LIVE, "live_since": None}
    index = lic.build_index(closed, {"acme"}, SALT)
    assert index["offer"] == {
        "live": False,
        "checkout_url": None,
        "price_usd_per_month": 99,
        "seats": 10,
    }
    assert set(index) == {"schema_version", "offer", "owners"}


def test_the_list_holds_no_name_and_no_stripe_id() -> None:
    stripe = Stripe(
        [_session("sub_1", "acme-secret-name")], [{"id": "sub_1", "status": "active"}]
    )
    index, unusable = lic.run(LIVE, stripe, SALT)
    text = json.dumps(index)
    assert "acme-secret-name" not in text and "sub_1" not in text and "cs_" not in text
    assert lic.owner_digest("acme-secret-name") in index["owners"]
    assert unusable is False
    assert (
        "payment_link=plink_1" in stripe.paths[0]
        and "status=complete" in stripe.paths[0]
    )


def test_every_page_of_a_stripe_list_is_read() -> None:
    sessions = [_session(f"sub_{i}", f"org{i}") for i in range(250)]
    subs = [{"id": f"sub_{i}", "status": "active"} for i in range(250)]
    stripe = Stripe(sessions, subs)
    index, _ = lic.run(LIVE, stripe, SALT)
    assert len(stripe.paths) == 6
    assert all(lic.owner_digest(f"org{i}") in index["owners"] for i in range(250))
    assert len(index["owners"]) == 256


def test_stripe_is_not_read_before_there_is_a_payment_link() -> None:
    def never(_path: str) -> dict:
        raise AssertionError("Stripe was read")

    index, _ = lic.run({**LIVE, "payment_link_id": None}, never, SALT)
    assert len(index["owners"]) == 64


@pytest.mark.parametrize(
    "page", [None, [], {"data": "x"}, {"data": [1]}, {"data": [{}], "has_more": True}]
)
def test_a_stripe_answer_that_is_not_a_list_stops_the_run(page: object) -> None:
    with pytest.raises(lic.StripeError):
        lic.stripe_list(lambda _path: page, "/v1/subscriptions", {})


def test_a_failed_request_writes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offer = tmp_path / "offer.json"
    offer.write_text(json.dumps(LIVE), encoding="utf-8")
    monkeypatch.setattr(lic, "OFFER_PATH", offer)
    monkeypatch.setenv("TEAM_INDEX_SALT", SALT)
    monkeypatch.setenv("STRIPE_API_KEY", "rk_test_SECRETKEY")

    def fail(_key: str) -> Any:
        def get(_path: str) -> dict:
            raise lic.StripeError("Stripe answered 401 for /v1/checkout/sessions")

        return get

    monkeypatch.setattr(lic, "stripe_get", fail)
    assert lic.main(["--out", str(tmp_path / "out")]) == 1
    assert not (tmp_path / "out").exists()
    assert "rk_test_SECRETKEY" not in capsys.readouterr().out


def test_main_prints_no_subscriber_and_no_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offer = tmp_path / "offer.json"
    offer.write_text(json.dumps(LIVE), encoding="utf-8")
    monkeypatch.setattr(lic, "OFFER_PATH", offer)
    monkeypatch.setenv("TEAM_INDEX_SALT", SALT)
    monkeypatch.setenv("STRIPE_API_KEY", "rk_test_x")
    stripe = Stripe(
        [_session("sub_1", "acme"), _session("sub_2", "beta"), _session("sub_3", "!!")],
        [{"id": f"sub_{i}", "status": "active"} for i in (1, 2, 3)],
    )
    monkeypatch.setattr(lic, "stripe_get", lambda _key: stripe)
    assert lic.main(["--out", str(tmp_path / "out")]) == 0
    printed = capsys.readouterr().out
    assert "acme" not in printed and "beta" not in printed
    assert "Licence list written: 64 entries." in printed
    assert "::warning title=Team licence list::" in printed
    written = json.loads((tmp_path / "out" / "index.json").read_text(encoding="utf-8"))
    assert lic.owner_digest("beta") in written["owners"]


@pytest.mark.parametrize(
    ("salt", "key", "code"), [("short", "rk", 2), (SALT, "", 2), ("", "rk", 2)]
)
def test_a_missing_secret_stops_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, salt: str, key: str, code: int
) -> None:
    offer = tmp_path / "offer.json"
    offer.write_text(json.dumps(LIVE), encoding="utf-8")
    monkeypatch.setattr(lic, "OFFER_PATH", offer)
    monkeypatch.setenv("TEAM_INDEX_SALT", salt)
    monkeypatch.setenv("STRIPE_API_KEY", key)
    assert lic.main(["--out", str(tmp_path / "out")]) == code
    assert not (tmp_path / "out").exists()


def test_the_script_uses_the_standard_library_only() -> None:
    """The build job installs nothing, so the job that holds the key runs no package."""
    import ast

    tree = ast.parse(
        (ROOT / "scripts" / "team_licenses.py").read_text(encoding="utf-8")
    )
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    assert names <= set(sys.stdlib_module_names) | {"__future__"}


# --- the workflow ----------------------------------------------------------


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def test_the_schedule_waits_for_the_repository_variable() -> None:
    assert "vars.TEAM_LICENSES_LIVE == 'true'" in _jobs()["build"]["if"]


def test_the_job_with_the_secrets_cannot_write_and_installs_nothing() -> None:
    build = _jobs()["build"]
    assert build["permissions"] == {"contents": "read"}
    assert build["environment"] == "team-licenses"
    runs = [s["run"] for s in build["steps"] if "run" in s]
    assert runs == ["python3 -I scripts/team_licenses.py --out out"]


def test_the_job_that_writes_holds_no_secret_and_runs_no_repository_code() -> None:
    publish = _jobs()["publish"]
    assert publish["permissions"] == {"contents": "write"}
    assert "environment" not in publish
    text = json.dumps(publish)
    assert "secrets." not in text
    assert "scripts/" not in text and "team/" not in text


def test_the_publish_job_checks_the_list_that_the_script_writes(tmp_path: Path) -> None:
    """Run the inline check of the publish job on a real list and on bad ones."""
    import subprocess

    (step,) = [s for s in _jobs()["publish"]["steps"] if "Check" in s.get("name", "")]
    code = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]

    def check(document: object) -> int:
        work = tmp_path / f"w{len(list(tmp_path.iterdir()))}"
        (work / "incoming").mkdir(parents=True)
        (work / "incoming" / "index.json").write_text(
            json.dumps(document), encoding="utf-8"
        )
        return subprocess.run(  # noqa: S603
            [sys.executable, "-I", "-c", code], cwd=work, capture_output=True
        ).returncode

    good = lic.build_index(LIVE, {"acme"}, SALT)
    assert check(good) == 0
    assert check({**good, "owners": good["owners"][:-1]}) != 0
    assert check({**good, "owners": [*good["owners"][:-1], "acme"]}) != 0
    assert check({**good, "extra": 1}) != 0
    assert check({**good, "owners": []}) != 0
    assert check([]) != 0
