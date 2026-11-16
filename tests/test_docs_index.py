"""docs/README.md lists every document in docs/ and links to nothing missing."""

import re
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"


def _linked() -> set[str]:
    text = (DOCS / "README.md").read_text(encoding="utf-8")
    return set(re.findall(r"\]\(([^)#]+)\)", text))


def test_every_doc_is_in_the_index() -> None:
    files = {p.name for p in DOCS.glob("*.md")} - {"README.md"}
    assert sorted(files - _linked()) == []


def test_every_index_link_exists() -> None:
    missing = [t for t in _linked() if "://" not in t and not (DOCS / t).exists()]
    assert sorted(missing) == []
