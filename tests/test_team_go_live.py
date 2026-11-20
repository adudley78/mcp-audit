"""`scripts/team_go_live.py`: the one command that opens subscriptions."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "team_go_live", ROOT / "scripts" / "team_go_live.py"
)
live = importlib.util.module_from_spec(_spec)
sys.modules["team_go_live"] = live
_spec.loader.exec_module(live)

GOOD = [
    "--checkout-url",
    "https://buy.stripe.com/aBc123",
    "--payment-link-id",
    "plink_1AbC",
    "--portal-url",
    "https://billing.stripe.com/p/login/xYz",
    "--live-since",
    "2026-12-01",
]


@pytest.fixture
def copies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    offer, doc = tmp_path / "offer.json", tmp_path / "team.md"
    offer.write_bytes(live.OFFER_PATH.read_bytes())
    doc.write_bytes(live.DOC_PATH.read_bytes())
    monkeypatch.setattr(live, "OFFER_PATH", offer)
    monkeypatch.setattr(live, "DOC_PATH", doc)
    return offer, doc


def test_the_page_and_the_offer_file_agree_in_the_repository() -> None:
    assert live.main(["--check"]) == 0


def test_going_live_writes_the_offer_and_the_page(copies: tuple[Path, Path]) -> None:
    offer, doc = copies
    before = doc.read_text(encoding="utf-8")
    assert live.main(GOOD) == 0
    written = json.loads(offer.read_text(encoding="utf-8"))
    assert written["live_since"] == "2026-12-01"
    assert written["checkout_url"] == "https://buy.stripe.com/aBc123"
    assert written["payment_link_id"] == "plink_1AbC"
    assert (written["price_usd_per_month"], written["seats"]) == (99, 10)
    after = doc.read_text(encoding="utf-8")
    assert "[Subscribe to Credenzo Team](https://buy.stripe.com/aBc123)" in after
    assert "$99 a month for up to 10 seats" in after
    assert "https://billing.stripe.com/p/login/xYz" in after
    assert "Subscriptions are not open yet" not in after
    # Only the block between the two markers changed.
    assert before.split(live.START)[0] == after.split(live.START)[0]
    assert before.split(live.END)[1] == after.split(live.END)[1]
    assert live.main(["--check"]) == 0


def test_check_fails_when_the_two_files_do_not_agree(copies: tuple[Path, Path]) -> None:
    offer, _ = copies
    data = json.loads(offer.read_text(encoding="utf-8"))
    data.update(live_since="2026-12-01", checkout_url="https://buy.stripe.com/x")
    offer.write_text(json.dumps(data), encoding="utf-8")
    assert live.main(["--check"]) == 1


@pytest.mark.parametrize(
    ("index", "value"),
    [
        (1, "https://example.com/pay"),
        (1, "http://buy.stripe.com/abc"),
        (1, "https://buy.stripe.com/test_abc"),
        (3, "price_123"),
        (5, "https://example.com/portal"),
        (7, "next week"),
    ],
)
def test_a_wrong_argument_changes_nothing(
    copies: tuple[Path, Path], index: int, value: str
) -> None:
    offer, doc = copies
    before = (offer.read_bytes(), doc.read_bytes())
    args = list(GOOD)
    args[index] = value
    assert live.main(args) == 2
    assert (offer.read_bytes(), doc.read_bytes()) == before


def test_a_page_with_no_block_is_an_error() -> None:
    with pytest.raises(ValueError, match="team-checkout"):
        live.with_block("no markers here", {})
