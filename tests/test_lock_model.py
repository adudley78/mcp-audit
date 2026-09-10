"""Tests for mcp_audit.lock.model — ownership boundary and checksum scoping."""

from __future__ import annotations

from mcp_audit.lock.model import (
    LOCK_VERSION,
    compute_checksum,
    owned_subdocument,
    unverified_sections,
)


def _doc(**overrides: object) -> dict:
    base = {
        "lock_version": LOCK_VERSION,
        "generated_by": "mcp-audit/0.17.0",
        "generated_at": "2026-09-10T00:00:00Z",
        "servers": {"cursor/github": {"name": "github"}},
        "trees": {"_producer": "mcp-lock-tree-gen", "_schema_version": 1},
        "tools": None,
        "checksum": "sha256:placeholder",
    }
    base.update(overrides)
    return base


class TestOwnedSubdocument:
    def test_includes_only_owned_keys(self) -> None:
        doc = _doc()
        body = owned_subdocument(doc)
        assert set(body) == {"lock_version", "generated_by", "servers"}

    def test_excludes_generated_at_and_checksum(self) -> None:
        body = owned_subdocument(_doc())
        assert "generated_at" not in body
        assert "checksum" not in body

    def test_excludes_foreign_sections(self) -> None:
        body = owned_subdocument(_doc())
        assert "trees" not in body
        assert "tools" not in body

    def test_missing_owned_key_is_simply_absent(self) -> None:
        doc = {"generated_by": "x"}
        assert owned_subdocument(doc) == {"generated_by": "x"}


class TestComputeChecksum:
    def test_deterministic_for_same_owned_content(self) -> None:
        doc_a = _doc(generated_at="2026-09-10T00:00:00Z")
        doc_b = _doc(generated_at="2026-09-11T12:34:56Z")  # different timestamp only
        assert compute_checksum(doc_a) == compute_checksum(doc_b)

    def test_changes_when_servers_change(self) -> None:
        doc_a = _doc()
        doc_b = _doc(servers={"cursor/github": {"name": "github-renamed"}})
        assert compute_checksum(doc_a) != compute_checksum(doc_b)

    def test_unaffected_by_foreign_section_edits(self) -> None:
        """The checkpoint-review fix: regenerating `trees` never trips LOCK-005."""
        doc_a = _doc(trees={"_producer": "mcp-lock-tree-gen", "_schema_version": 1})
        doc_b = _doc(
            trees={
                "_producer": "mcp-lock-tree-gen",
                "_schema_version": 2,
                "servers": {"github": {"deps": ["a", "b", "c"]}},
            }
        )
        assert compute_checksum(doc_a) == compute_checksum(doc_b)

    def test_returns_sha256_prefixed_hex(self) -> None:
        checksum = compute_checksum(_doc())
        assert checksum.startswith("sha256:")
        assert len(checksum) == len("sha256:") + 64


class TestUnverifiedSections:
    def test_names_trees(self) -> None:
        assert unverified_sections(_doc()) == ["tools", "trees"]

    def test_generic_over_any_foreign_key(self) -> None:
        """Not `trees`-specific — a future foreign section is caught too."""
        doc = _doc()
        doc["resolutions"] = {"_producer": "some-other-tool"}
        assert "resolutions" in unverified_sections(doc)
        assert "trees" in unverified_sections(doc)

    def test_empty_when_only_owned_and_structural_keys_present(self) -> None:
        doc = {
            "lock_version": LOCK_VERSION,
            "generated_by": "mcp-audit/0.17.0",
            "generated_at": "2026-09-10T00:00:00Z",
            "servers": {},
            "checksum": "sha256:x",
        }
        assert unverified_sections(doc) == []
