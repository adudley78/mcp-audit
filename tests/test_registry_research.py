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
CONTEXTCRUSH = "x_MCPRS-32fc646f6f96"


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

    def test_references_are_the_two_sources_the_facts_come_from(self) -> None:
        rec = load_research_records().lookup(PLUGIN4SHELL)
        assert rec is not None
        urls = [u for _, u in rec.references]
        assert "https://www.air.security/blog-posts/plugin4shell" in urls
        assert len(urls) == 2

    def test_details_do_not_claim_commands_that_do_not_exist_yet(self) -> None:
        rec = load_research_records().lookup(PLUGIN4SHELL)
        assert rec is not None
        assert "on this machine" not in rec.details
        assert "GHSA" not in rec.details

    def test_record_validates_as_osv(self) -> None:
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


class TestContextCrush:
    """STORY-0134: a vendor-service flaw with no client version and no check."""

    def _rec(self) -> object:
        rec = load_research_records().lookup(CONTEXTCRUSH)
        assert rec is not None
        return rec

    def test_loads_credited_to_noma_with_the_post_as_primary_source(self) -> None:
        rec = self._rec()
        assert [c.name for c in rec.credits] == ["Eli Ainhorn (Noma Security)"]  # type: ignore[attr-defined]
        assert rec.source_url == (  # type: ignore[attr-defined]
            "https://noma.security/blog/contextcrush-context7-the-mcp-server-vulnerability/"
        )
        assert rec.aliases == ()  # type: ignore[attr-defined]

    def test_one_product_fixed_server_side_and_no_checks(self) -> None:
        rec = self._rec()
        (p,) = rec.products  # type: ignore[attr-defined]
        assert (p.product, p.vendor, p.status) == (
            "Context7 MCP",
            "Upstash",
            "fixed-server-side",
        )
        assert p.fixed_in is None
        assert "2026-02-23" in p.note
        assert "not confirmed by Upstash" in p.note
        assert rec.checks == ()  # type: ignore[attr-defined]

    def test_details_say_no_local_version_shows_exposure_and_no_cve(self) -> None:
        d = self._rec().details  # type: ignore[attr-defined]
        assert "no local version shows" in d
        assert "No CVE was assigned" in d
        assert "Upstash's own confirmation" in d


BYPASS_ASK = "x_MCPRS-c83726dd3047"
BYPASS_ASK_URL = "https://github.com/anthropics/claude-code/issues/103994"


class TestBypassAskOverridden:
    """STORY-0139: a reported client bug, unfixed, no CVE, no check."""

    def _rec(self) -> object:
        rec = load_research_records().lookup(BYPASS_ASK)
        assert rec is not None
        return rec

    def test_id_is_the_hash_of_the_issue_and_product(self) -> None:
        assert research_id(BYPASS_ASK_URL, ["Claude Code"]) == BYPASS_ASK

    def test_credited_to_the_reporter_with_the_issue_as_source(self) -> None:
        rec = self._rec()
        assert [(c.name, c.type) for c in rec.credits] == [("sergvss", "FINDER")]  # type: ignore[attr-defined]
        assert rec.source_url == BYPASS_ASK_URL  # type: ignore[attr-defined]
        assert rec.aliases == ()  # type: ignore[attr-defined]

    def test_one_product_unfixed_with_no_fix_version_and_no_checks(self) -> None:
        rec = self._rec()
        (p,) = rec.products  # type: ignore[attr-defined]
        assert (p.product, p.vendor, p.status) == (
            "Claude Code",
            "Anthropic",
            "unfixed",
        )
        assert p.fixed_in is None
        assert "2.1.302" in p.note and "2.1.316" in p.note
        assert rec.checks == ()  # type: ignore[attr-defined]

    def test_text_says_reported_bug_quotes_the_reporter_and_names_no_cve(self) -> None:
        d = self._rec().details  # type: ignore[attr-defined]
        assert "This is a reported bug, not behaviour" in d
        assert "ask still prompt" in d  # the documented behaviour is kept
        assert "In `bypassPermissions` mode, a `PreToolUse` hook" in d
        assert "protected-path check for those directories" in d
        assert ".git/" in d and ".claude/" in d
        assert "No CVE was assigned" in d
        assert "HARNESS-001" in d and "precondition" in d

    def test_summary_says_reported(self) -> None:
        assert "(reported)" in self._rec().summary  # type: ignore[attr-defined]


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
        entries = [_entry()] * (MAX_ENTRIES + 1)
        index = load_research_records(_write(tmp_path, entries))
        assert index.load_error and "limit" in index.load_error
        assert len(index) == 0

    @pytest.mark.parametrize("field", ["credits", "references", "aliases"])
    def test_wrongly_typed_top_level_lists_skip_not_raise(
        self, tmp_path: Path, field: str
    ) -> None:
        index = load_research_records(
            _write(
                tmp_path, [_entry(**{field: "oops"}), _entry(id="x_MCPRS-000000000002")]
            )
        )
        assert len(index) == 1 and len(index.skipped) == 1

    @pytest.mark.parametrize("bad", ["oops", 7, {"a": 1}])
    def test_wrongly_typed_checks_and_products_skip_not_raise(
        self, tmp_path: Path, bad: object
    ) -> None:
        for key in ("checks", "products"):
            entry = _entry()
            meta = {"kind": "research", "products": [], "checks": []}
            meta[key] = bad
            entry["database_specific"] = {"mcp_audit": meta}
            index = load_research_records(_write(tmp_path, [entry]))
            assert len(index) == 0 and len(index.skipped) == 1, key

    def test_non_object_product_rows_skip_the_record(self, tmp_path: Path) -> None:
        entry = _entry()
        entry["database_specific"] = {
            "mcp_audit": {"kind": "research", "products": [1, 2]}
        }
        index = load_research_records(_write(tmp_path, [entry]))
        assert len(index) == 0 and len(index.skipped) == 1

    @pytest.mark.parametrize("db", ["oops", 7, [], {"mcp_audit": "x"}])
    def test_wrongly_typed_database_specific_is_not_a_research_record(
        self, tmp_path: Path, db: object
    ) -> None:
        index = load_research_records(_write(tmp_path, [_entry(database_specific=db)]))
        assert len(index) == 0 and len(index.skipped) == 1

    @pytest.mark.parametrize(
        "rid",
        ["x_MCPRS-", "x_MCPRS-XYZ", "x_MCPRS-0000000000012", "x_MCPRS-00000000000G", 5],
    )
    def test_malformed_id_shape_is_skipped(self, tmp_path: Path, rid: object) -> None:
        index = load_research_records(_write(tmp_path, [_entry(id=rid)]))
        assert len(index) == 0 and len(index.skipped) == 1

    def test_deeply_nested_json_is_a_load_error_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        p = tmp_path / "r.json"
        p.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
        index = load_research_records(p)
        assert len(index) == 0 and index.load_error

    def test_non_utf8_file_is_a_load_error(self, tmp_path: Path) -> None:
        p = tmp_path / "r.json"
        p.write_bytes(b"\xff\xfe\x00{")
        assert load_research_records(p).load_error

    def test_oversized_file_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import mcp_audit.registry.research as mod  # noqa: PLC0415

        monkeypatch.setattr(mod, "MAX_FILE_BYTES", 10)
        p = _write(tmp_path, [_entry()])
        index = load_research_records(p)
        assert index.load_error and "over" in index.load_error

    def test_duplicate_ids_keep_the_first_and_report(self, tmp_path: Path) -> None:
        index = load_research_records(
            _write(tmp_path, [_entry(summary="first"), _entry(summary="second")])
        )
        assert len(index) == 1
        assert index.records["x_MCPRS-000000000001"].summary == "first"
        assert any("duplicate" in s for s in index.skipped)

    def test_alias_collision_is_reported_and_first_wins(self, tmp_path: Path) -> None:
        index = load_research_records(
            _write(
                tmp_path,
                [
                    _entry(aliases=["A-1"]),
                    _entry(id="x_MCPRS-000000000002", aliases=["a-1"]),
                ],
            )
        )
        rec = index.lookup("A-1")
        assert rec is not None and rec.id == "x_MCPRS-000000000001"
        assert any("alias" in s for s in index.skipped)

    def test_withdrawn_id_is_remembered_apart_from_unknown(
        self, tmp_path: Path
    ) -> None:
        index = load_research_records(
            _write(tmp_path, [_entry(withdrawn="2026-01-01T00:00:00Z")])
        )
        assert index.withdrawn == {"x_MCPRS-000000000001": "2026-01-01T00:00:00Z"}

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

    def test_wheel_packaging_covers_the_package_data_directory(self) -> None:
        text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        assert 'packages = ["src/mcp_audit"]' in text

    def test_loader_default_path_is_the_shipped_file(self) -> None:
        from mcp_audit.registry.research import _resolve_bundled_path  # noqa: PLC0415

        assert _resolve_bundled_path().resolve() == SHIPPED.resolve()
