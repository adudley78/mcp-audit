"""STORY-0122: research records (registry/research-records.json)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_audit.registry.research import (
    MAX_ENTRIES,
    load_research_records,
    research_id,
)

REPO = Path(__file__).resolve().parent.parent
SHIPPED = REPO / "src" / "mcp_audit" / "data" / "research-records.json"
PLUGIN4SHELL = "x_MCPRS-4ad8c07d80d7"


def _write(tmp_path: Path, entries: list[object]) -> Path:
    p = tmp_path / "r.json"
    p.write_text(
        json.dumps({"schema_version": 1, "entries": entries}), encoding="utf-8"
    )
    return p


def _entry(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "x_MCPRS-000000000001",
        "summary": "s",
        "details": "d",
        "credits": [{"name": "A (B)", "type": "FINDER"}],
        "references": [{"type": "ARTICLE", "url": "https://example.test/a"}],
        "database_specific": {
            "mcp_audit": {
                "kind": "research",
                "products": [
                    {
                        "product": "P",
                        "vendor": "V",
                        "status": "fixed",
                        "fixed_in": "1.2",
                    }
                ],
                "checks": ["X-001"],
            }
        },
    }
    base.update(over)
    return base


class TestShippedFile:
    def test_loads_with_records_and_no_error(self) -> None:
        index = load_research_records()
        assert index.load_error is None
        assert index.skipped == []
        assert len(index) >= 1

    def test_plugin4shell_is_credited_to_air_researchers_by_name(self) -> None:
        rec = load_research_records().lookup(PLUGIN4SHELL)
        assert rec is not None
        assert [c.name for c in rec.credits] == [
            "Or Nevo (AIR Security)",
            "Dor Granat (AIR Security)",
            "Niv Hoffman (AIR Security)",
        ]
        assert rec.source_url == "https://www.air.security/blog-posts/plugin4shell"

    def test_plugin4shell_products_match_the_writeup(self) -> None:
        rec = load_research_records().lookup(PLUGIN4SHELL)
        assert rec is not None
        by_name = {p.product: p for p in rec.products}
        assert by_name["Claude Code"].fixed_in == "2.1.179"
        assert by_name["Codex"].fixed_in == "0.146.0"
        assert by_name["GitHub Copilot"].status == "unfixed"
        assert by_name["Gemini CLI"].status == "wontfix"
        assert rec.checks == ("PLUGIN-003", "PLUGIN-004")

    def test_every_shipped_id_is_the_hash_of_its_source_and_products(self) -> None:
        for rec in load_research_records().records.values():
            assert rec.source_url is not None
            assert rec.id == research_id(
                rec.source_url, [p.product for p in rec.products]
            )

    def test_entry_count_field_matches(self) -> None:
        data = json.loads(SHIPPED.read_text(encoding="utf-8"))
        assert data["entry_count"] == len(data["entries"])

    def test_no_invented_cve_or_package_names(self) -> None:
        text = SHIPPED.read_text(encoding="utf-8")
        assert "CVE-" not in text
        assert "@anthropic-ai" not in text
        assert "@openai" not in text

    def test_record_validates_as_osv_when_jsonschema_is_present(self) -> None:
        pytest.importorskip("jsonschema")
        from mcp_audit.advisory.validate import validate_osv  # noqa: PLC0415

        for raw in json.loads(SHIPPED.read_text(encoding="utf-8"))["entries"]:
            osv = {k: v for k, v in raw.items() if k != "database_specific"}
            validate_osv(osv)

    def test_every_check_id_exists_in_the_source_tree(self) -> None:
        src = "\n".join(
            p.read_text(encoding="utf-8", errors="ignore")
            for p in (REPO / "src" / "mcp_audit").rglob("*.py")
        )
        for rec in load_research_records().records.values():
            for check in rec.checks:
                assert f'"{check}"' in src or f"'{check}'" in src, check


class TestId:
    def test_order_of_products_does_not_matter(self) -> None:
        assert research_id("https://x.test", ["B", "A"]) == research_id(
            "https://x.test", ["A", "B"]
        )

    def test_different_source_gives_a_different_id(self) -> None:
        assert research_id("https://x.test/1", ["A"]) != research_id(
            "https://x.test/2", ["A"]
        )

    def test_shape(self) -> None:
        rid = research_id("https://x.test", ["A"])
        assert rid.startswith("x_MCPRS-") and len(rid) == len("x_MCPRS-") + 12


class TestTolerantLoader:
    def test_missing_file_gives_empty_index_with_error(self, tmp_path: Path) -> None:
        index = load_research_records(tmp_path / "nope.json")
        assert len(index) == 0
        assert index.load_error and "could not be read" in index.load_error

    def test_malformed_json(self, tmp_path: Path) -> None:
        p = tmp_path / "r.json"
        p.write_text("{not json", encoding="utf-8")
        assert load_research_records(p).load_error

    def test_wrong_shape(self, tmp_path: Path) -> None:
        p = tmp_path / "r.json"
        p.write_text("[]", encoding="utf-8")
        assert load_research_records(p).load_error

    def test_one_bad_entry_is_skipped_and_reported_not_fatal(
        self, tmp_path: Path
    ) -> None:
        index = load_research_records(
            _write(tmp_path, [_entry(), "junk", _entry(id="nope")])
        )
        assert len(index) == 1
        assert len(index.skipped) == 2

    def test_withdrawn_is_dropped_silently(self, tmp_path: Path) -> None:
        index = load_research_records(
            _write(tmp_path, [_entry(withdrawn="2026-01-01T00:00:00Z")])
        )
        assert len(index) == 0 and index.skipped == []

    @pytest.mark.parametrize(
        "product",
        [
            {"product": "P", "vendor": "V", "status": "fixed"},  # fixed needs fixed_in
            {"product": "P", "vendor": "V", "status": "unfixed", "fixed_in": "1"},
            {"product": "P", "vendor": "V", "status": "maybe"},
            {"vendor": "V", "status": "unfixed"},
        ],
    )
    def test_inconsistent_product_rows_skip_the_record(
        self, tmp_path: Path, product: dict[str, object]
    ) -> None:
        entry = _entry()
        entry["database_specific"] = {
            "mcp_audit": {"kind": "research", "products": [product]}
        }
        index = load_research_records(_write(tmp_path, [entry]))
        assert len(index) == 0 and len(index.skipped) == 1

    def test_entry_cap_is_reported(self, tmp_path: Path) -> None:
        index = load_research_records(_write(tmp_path, [{}] * (MAX_ENTRIES + 1)))
        assert index.load_error and "limit" in index.load_error

    def test_alias_lookup_is_case_insensitive(self, tmp_path: Path) -> None:
        index = load_research_records(
            _write(tmp_path, [_entry(aliases=["CVE-2026-1"])])
        )
        rec = index.lookup("cve-2026-1")
        assert rec is not None and rec.id == "x_MCPRS-000000000001"
        assert index.lookup("CVE-2026-2") is None


class TestBundling:
    def test_file_is_package_data_that_every_spec_and_the_wheel_already_bundle(
        self,
    ) -> None:
        for spec in REPO.glob("mcp-audit-*.spec"):
            text = spec.read_text(encoding="utf-8")
            assert (
                "(os.path.join(root, 'src/mcp_audit/data'), 'mcp_audit/data')" in text
            ), spec.name
        assert SHIPPED.parent.name == "data"

    def test_loader_default_path_is_the_shipped_file(self) -> None:
        from mcp_audit.registry.research import _resolve_bundled_path  # noqa: PLC0415

        assert _resolve_bundled_path().resolve() == SHIPPED.resolve()
