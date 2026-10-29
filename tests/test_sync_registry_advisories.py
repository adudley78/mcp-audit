"""Tests for scripts/sync_registry_advisories.py (STORY-0083). No network."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "sync_registry_advisories", ROOT / "scripts" / "sync_registry_advisories.py"
)
assert _SPEC and _SPEC.loader
sync_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sync_mod)

WORKFLOW = ROOT / ".github" / "workflows" / "registry-advisory-sync.yml"


# The real downloader, kept before the autouse stub below replaces it.
_REAL_FETCH_MALICIOUS = sync_mod.fetch_malicious_export


@pytest.fixture(autouse=True)
def _no_malicious_download(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never download OSV's bulk export in tests (STORY-0097)."""
    monkeypatch.setattr(sync_mod, "fetch_malicious_export", lambda eco, keep: [])


def _vuln(
    vid: str,
    *,
    aliases: list[str] | None = None,
    name: str = "acme-mcp",
    eco: str = "npm",
    events: list[list[dict]] | None = None,
    summary: str = "Bad thing",
    withdrawn: str | None = None,
) -> dict:
    ranges = [
        {"type": "SEMVER", "events": ev}
        for ev in (events or [[{"introduced": "0"}, {"fixed": "1.2.0"}]])
    ]
    rec: dict = {
        "id": vid,
        "aliases": aliases or [],
        "summary": summary,
        "affected": [{"package": {"name": name, "ecosystem": eco}, "ranges": ranges}],
    }
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


def _entry(**extra: object) -> dict:
    entry: dict = {"name": "acme-mcp", "source": "npm"}
    entry.update(extra)
    return entry


class TestFixedVersion:
    def test_single_fixed_range(self) -> None:
        assert sync_mod.fixed_version(_vuln("GHSA-1"), "acme-mcp", "npm") == "1.2.0"

    def test_highest_fix_across_ranges(self) -> None:
        v = _vuln(
            "GHSA-1",
            events=[
                [{"introduced": "0"}, {"fixed": "1.2.0"}],
                [{"introduced": "2.0.0"}, {"fixed": "2.0.5"}],
            ],
        )
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") == "2.0.5"

    def test_open_ended_range_means_no_fix(self) -> None:
        v = _vuln("GHSA-1", events=[[{"introduced": "0"}]])
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") is None

    def test_last_affected_range_is_bounded(self) -> None:
        """server-filesystem's shape: an old 0.6.x line that stopped, then a fix."""
        v = _vuln(
            "GHSA-1",
            events=[
                [{"introduced": "0"}, {"last_affected": "0.6.2"}],
                [{"introduced": "2025.1.14"}, {"fixed": "2025.7.1"}],
            ],
        )
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") == "2025.7.1"

    def test_only_last_affected_has_no_known_fix(self) -> None:
        v = _vuln("GHSA-1", events=[[{"introduced": "0"}, {"last_affected": "1.0.0"}]])
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") is None

    def test_other_packages_ranges_are_ignored(self) -> None:
        v = _vuln("GHSA-1", name="someone-else")
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") is None

    def test_pypi_names_are_normalized(self) -> None:
        v = _vuln("PYSEC-1", name="Acme_MCP", eco="PyPI")
        assert sync_mod.fixed_version(v, "acme-mcp", "PyPI") == "1.2.0"


class TestMissingForEntry:
    def test_records_the_cve_alias(self) -> None:
        new, fills = sync_mod.missing_for_entry(
            _entry(), [_vuln("GHSA-aaaa", aliases=["CVE-2026-1"])]
        )
        assert fills == {}
        assert new == [
            {
                "cve": "CVE-2026-1",
                "cvss": None,
                "description": "Bad thing",
                "fixed_in": "1.2.0",
            }
        ]

    def test_ghsa_id_when_there_is_no_cve(self) -> None:
        new, _ = sync_mod.missing_for_entry(_entry(), [_vuln("GHSA-bbbb")])
        assert new[0]["cve"] == "GHSA-bbbb"

    def test_an_alias_already_listed_counts_as_present(self) -> None:
        entry = _entry(known_vulnerabilities=["GHSA-aaaa"])
        new, _ = sync_mod.missing_for_entry(
            entry, [_vuln("GHSA-aaaa", aliases=["CVE-2026-1"])]
        )
        assert new == []

    def test_withdrawn_and_malicious_records_are_skipped(self) -> None:
        new, _ = sync_mod.missing_for_entry(
            _entry(),
            [_vuln("GHSA-w", withdrawn="2026-01-01T00:00:00Z"), _vuln("MAL-2026-1")],
        )
        assert new == []

    def test_malware_and_bounded_only_advisories_are_not_recorded(self) -> None:
        # STORY-0128: a PYSEC copy of a MAL record, and a record that only ever
        # bounded an old line (last_affected, no fix), would be stored with no
        # fix and flag every version, the newest release included.
        pysec = _vuln("PYSEC-2026-2", aliases=["MAL-2026-2144"])
        bounded = _vuln(
            "GHSA-bounded",
            events=[[{"introduced": "1.0.0"}, {"last_affected": "1.2.0"}]],
        )
        new, _ = sync_mod.missing_for_entry(_entry(), [pysec, bounded])
        assert new == []

    def test_open_ended_advisory_is_still_recorded(self) -> None:
        open_ended = _vuln("GHSA-open", events=[[{"introduced": "0"}]])
        new, _ = sync_mod.missing_for_entry(_entry(), [open_ended])
        assert [r["cve"] for r in new] == ["GHSA-open"]

    def test_fills_a_missing_fixed_in_on_an_existing_record(self) -> None:
        entry = _entry(
            known_vulnerabilities=["CVE-2026-1"],
            known_vulns=[
                {
                    "cve": "CVE-2026-1",
                    "cvss": None,
                    "description": "x",
                    "fixed_in": None,
                }
            ],
        )
        new, fills = sync_mod.missing_for_entry(
            entry, [_vuln("GHSA-aaaa", aliases=["CVE-2026-1"])]
        )
        assert new == []
        assert fills == {"CVE-2026-1": "1.2.0"}

    def test_never_overwrites_a_recorded_fix(self) -> None:
        entry = _entry(
            known_vulns=[
                {
                    "cve": "CVE-2026-1",
                    "cvss": None,
                    "description": "x",
                    "fixed_in": "9.9.9",
                }
            ]
        )
        _, fills = sync_mod.missing_for_entry(
            entry, [_vuln("GHSA-aaaa", aliases=["CVE-2026-1"])]
        )
        assert fills == {}

    def test_long_summaries_are_truncated(self) -> None:
        new, _ = sync_mod.missing_for_entry(
            _entry(), [_vuln("GHSA-1", summary="x" * 500)]
        )
        assert len(new[0]["description"]) == 200


class TestSyncAndCli:
    def _registry(self, tmp_path: Path) -> Path:
        path = tmp_path / "known-servers.json"
        data = {
            "schema_version": "1.0",
            "last_updated": "2026-10-01",
            "entry_count": 2,
            "entries": [
                _entry(known_vulnerabilities=["CVE-2026-1"]),
                {"name": "other", "source": "pip"},
            ],
        }
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def _fake_osv(name: str, ecosystem: str) -> list[dict]:
        if name == "acme-mcp":
            return [
                _vuln("GHSA-old", aliases=["CVE-2026-1"]),
                _vuln("GHSA-new", aliases=["CVE-2026-2"]),
            ]
        return []

    def test_check_reports_and_does_not_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = self._registry(tmp_path)
        before = path.read_bytes()
        monkeypatch.setattr(sync_mod, "query_osv", self._fake_osv)
        summary = tmp_path / "summary.md"
        out = tmp_path / "proposed.json"
        code = sync_mod.main(
            ["--registry", str(path), "--summary", str(summary), "--out", str(out)]
        )
        assert code == 1
        assert path.read_bytes() == before
        assert "CVE-2026-2" in summary.read_text(encoding="utf-8")
        proposed = json.loads(out.read_text(encoding="utf-8"))
        assert proposed["entries"][0]["known_vulnerabilities"] == [
            "CVE-2026-1",
            "CVE-2026-2",
        ]

    def test_write_then_check_is_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = self._registry(tmp_path)
        monkeypatch.setattr(sync_mod, "query_osv", self._fake_osv)
        assert (
            sync_mod.main(["--registry", str(path), "--write", "--today", "2026-10-13"])
            == 0
        )
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["last_updated"] == "2026-10-13"
        assert data["entries"][0]["known_vulns"][0]["cve"] == "CVE-2026-2"
        assert path.read_text(encoding="utf-8").endswith("}\n")
        assert sync_mod.main(["--registry", str(path)]) == 0

    def test_osv_failure_is_exit_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = self._registry(tmp_path)

        def boom(name: str, ecosystem: str) -> list[dict]:
            raise RuntimeError("OSV unreachable")

        monkeypatch.setattr(sync_mod, "query_osv", boom)
        assert sync_mod.main(["--registry", str(path)]) == 2


class TestBundledRegistry:
    def test_bundled_registry_carries_the_story_examples(self) -> None:
        data = json.loads(
            (ROOT / "registry" / "known-servers.json").read_text(encoding="utf-8")
        )
        by_name = {e["name"]: e for e in data["entries"]}
        assert (
            "CVE-2025-49596"
            in by_name["@modelcontextprotocol/inspector"]["known_vulnerabilities"]
        )
        assert "CVE-2026-51996" in by_name["mcp-remote"]["known_vulnerabilities"]
        assert data["entry_count"] == len(data["entries"])


class TestWorkflow:
    def _load(self) -> dict:
        return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    def test_weekly_and_on_demand(self) -> None:
        wf = self._load()
        on = wf.get("on", wf.get(True))
        assert on["schedule"] == [{"cron": "0 10 * * 1"}]
        assert "workflow_dispatch" in on

    def test_read_only(self) -> None:
        wf = self._load()
        text = WORKFLOW.read_text(encoding="utf-8")
        assert wf["permissions"] == {"contents": "read"}
        runs = [
            step.get("run", "") for job in wf["jobs"].values() for step in job["steps"]
        ]
        assert any("sync_registry_advisories.py --check" in r for r in runs)
        assert not any("--write" in r for r in runs)
        assert "gh pr" not in text
        assert "git push" not in text

    def _step(self, name_prefix: str) -> dict:
        steps = self._load()["jobs"]["check"]["steps"]
        return next(s for s in steps if str(s.get("name", "")).startswith(name_prefix))

    def test_both_registry_files_are_hashed_before_and_after(self) -> None:
        """STORY-0109: the read-only guard covers the malicious mirror too."""
        for prefix in ("Hash registry files before", "Assert the registry files"):
            run = self._step(prefix)["run"]
            assert "registry/known-servers.json" in run
            assert "registry/known-malicious.json" in run

    def test_workflow_run_writes_and_uploads_both_proposed_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """STORY-0109: run the workflow's own command line against the script.

        The check step's arguments are taken from the YAML and passed to
        ``main()`` (OSV stubbed), so the test fails if the workflow stops
        passing ``--malicious-out`` or the upload step stops naming the file
        the script writes.
        """
        import shlex

        run = self._step("Check advisories")["run"]
        runner_temp = tmp_path / "runner"
        runner_temp.mkdir()
        expanded = (
            run.replace("\\\n", " ")
            .replace("${RUNNER_TEMP}", str(runner_temp))
            .replace("${GITHUB_STEP_SUMMARY}", str(tmp_path / "summary.md"))
        )
        argv = shlex.split(expanded)
        assert argv[:2] == ["python", "scripts/sync_registry_advisories.py"]
        assert "--malicious-out" in argv

        reg = TestSyncAndCli()._registry(tmp_path)
        before = reg.read_bytes()
        monkeypatch.setattr(sync_mod, "query_osv", TestSyncAndCli._fake_osv)
        monkeypatch.setattr(
            sync_mod,
            "fetch_malicious_export",
            lambda eco, keep: [_mal("MAL-1", "b-mcp")] if eco == "npm" else [],
        )
        assert sync_mod.main([*argv[2:], "--registry", str(reg)]) == 1

        written = sorted(p.name for p in runner_temp.iterdir())
        assert written == [
            "known-malicious.proposed.json",
            "known-servers.proposed.json",
        ]
        upload = self._step("Upload proposed registry files")
        uploaded = sorted(
            Path(line.strip().replace("${{ runner.temp }}", str(runner_temp))).name
            for line in str(upload["with"]["path"]).splitlines()
            if line.strip()
        )
        assert uploaded == written
        assert "failure()" in str(upload.get("if", ""))
        # Committed files are never written by a --check run.
        assert reg.read_bytes() == before
        assert not (tmp_path / "known-malicious.json").exists()


# ── Known-malicious mirror (STORY-0097) ───────────────────────────────────────


def _mal(
    vid: str,
    name: str,
    eco: str = "npm",
    *,
    versions: list[str] | None = None,
    events: list[dict] | None = None,
    withdrawn: str | None = None,
    aliases: list[str] | None = None,
) -> dict:
    rec: dict = {
        "id": vid,
        "aliases": aliases or [],
        "summary": f"Malicious code in {name} ({eco})",
        "published": "2026-06-09T20:33:49Z",
        "modified": "2026-08-20T15:30:12Z",
        "affected": [
            {
                "package": {"name": name, "ecosystem": eco},
                "versions": versions or [],
                "ranges": [{"type": "SEMVER", "events": events}] if events else [],
            }
        ],
    }
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


_REGISTRY = {
    "entries": [
        {"name": "flowise", "source": "npm"},
        {"name": "Doc_Pull", "source": "pip", "package_ecosystem": "pypi"},
    ]
}


class TestPackageSelector:
    def test_mcp_substring_any_case(self) -> None:
        keep = sync_mod.package_selector({"entries": []})
        assert keep("npm", "mcp-server-github")
        assert keep("npm", "@mcp-use/cli")
        assert keep("PyPI", "TimeMCP")
        assert not keep("npm", "left-pad")

    def test_registry_listed_names_without_mcp(self) -> None:
        keep = sync_mod.package_selector(_REGISTRY)
        assert keep("npm", "flowise")
        assert keep("PyPI", "doc-pull")  # PEP 503
        assert not keep("PyPI", "flowise")  # other ecosystem
        assert not keep("npm", "doc-pull")


class TestMaliciousEntries:
    def test_shape_as_osv_states_it(self) -> None:
        keep = sync_mod.package_selector({"entries": []})
        rec = _mal(
            "MAL-2026-5479",
            "mcp-server-github",
            versions=["0.0.2", "0.0.1"],
            events=[{"introduced": "0"}],
            aliases=["GHSA-95pj-hrh5-27gq"],
        )
        [entry] = sync_mod.malicious_entries([rec], "npm", keep)
        assert entry["id"] == "MAL-2026-5479"
        assert entry["name"] == "mcp-server-github"
        assert entry["aliases"] == ["GHSA-95pj-hrh5-27gq"]
        assert entry["summary"] == "Malicious code in mcp-server-github (npm)"
        assert entry["versions"] == ["0.0.1", "0.0.2"]  # sorted
        assert entry["ranges"] == [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
        assert "modified" not in entry  # left out so re-imports don't churn
        assert "npx-canary" in entry["note"]

    def test_withdrawn_non_mal_other_ecosystem_and_unmatched_are_dropped(self) -> None:
        keep = sync_mod.package_selector({"entries": []})
        recs = [
            _mal("MAL-1", "a-mcp", withdrawn="2026-01-01T00:00:00Z"),
            _mal("GHSA-xxxx", "b-mcp"),
            _mal("MAL-2", "c-mcp", eco="PyPI"),
            _mal("MAL-3", "left-pad"),
            _mal("MAL-4", "d-mcp"),
        ]
        out = sync_mod.malicious_entries(recs, "npm", keep)
        assert [e["id"] for e in out] == ["MAL-4"]

    def test_git_ranges_are_dropped(self) -> None:
        keep = sync_mod.package_selector({"entries": []})
        rec = _mal("MAL-5", "e-mcp", events=[{"introduced": "0"}])
        rec["affected"][0]["ranges"].append(
            {"type": "GIT", "events": [{"introduced": "abc"}]}
        )
        [entry] = sync_mod.malicious_entries([rec], "npm", keep)
        assert [r["type"] for r in entry["ranges"]] == ["SEMVER"]


class TestSyncMalicious:
    @staticmethod
    def _fetch(records: dict[str, list[dict]]):
        def fetch(ecosystem: str, keep):  # type: ignore[no-untyped-def]
            return records.get(ecosystem, [])

        return fetch

    def test_diff_added_removed_changed(self) -> None:
        keep = sync_mod.package_selector({"entries": []})
        old = sync_mod.malicious_entries(
            [_mal("MAL-1", "a-mcp", versions=["1.0.0"]), _mal("MAL-2", "b-mcp")],
            "npm",
            keep,
        )
        fetch = self._fetch(
            {
                "npm": [_mal("MAL-1", "a-mcp", versions=["1.0.0", "1.0.1"])],
                "PyPI": [_mal("MAL-3", "c-mcp", eco="PyPI")],
            }
        )
        diff, entries = sync_mod.sync_malicious({"entries": []}, old, fetch)
        assert diff == {
            "added": ["MAL-3 PyPI/c-mcp"],
            "removed": ["MAL-2 npm/b-mcp"],
            "changed": ["MAL-1 npm/a-mcp"],
        }
        assert [e["id"] for e in entries] == ["MAL-3", "MAL-1"]  # PyPI sorts first

    def test_no_drift_is_an_empty_diff(self) -> None:
        keep = sync_mod.package_selector({"entries": []})
        recs = [_mal("MAL-1", "a-mcp")]
        current = sync_mod.malicious_entries(recs, "npm", keep)
        diff, _ = sync_mod.sync_malicious(
            {"entries": []}, current, self._fetch({"npm": recs})
        )
        assert diff == {}


class TestMaliciousCli:
    def _registry(self, tmp_path: Path) -> Path:
        path = tmp_path / "known-servers.json"
        path.write_text(
            json.dumps({"schema_version": "1.0", "entries": []}) + "\n",
            encoding="utf-8",
        )
        return path

    def _patch(self, monkeypatch: pytest.MonkeyPatch, records: list[dict]) -> None:
        monkeypatch.setattr(sync_mod, "query_osv", lambda name, eco: [])
        monkeypatch.setattr(
            sync_mod,
            "fetch_malicious_export",
            lambda eco, keep: records if eco == "npm" else [],
        )

    def test_check_reports_drift_and_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reg = self._registry(tmp_path)
        self._patch(monkeypatch, [_mal("MAL-1", "a-mcp")])
        summary = tmp_path / "summary.md"
        proposed = tmp_path / "proposed-malicious.json"
        code = sync_mod.main(
            [
                "--registry",
                str(reg),
                "--summary",
                str(summary),
                "--malicious-out",
                str(proposed),
            ]
        )
        assert code == 1
        assert not (tmp_path / "known-malicious.json").exists()
        assert "MAL-1 npm/a-mcp" in summary.read_text(encoding="utf-8")
        assert json.loads(proposed.read_text(encoding="utf-8"))["entry_count"] == 1

    def test_write_then_check_is_clean_and_loadable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.registry.malicious import load_known_malicious

        reg = self._registry(tmp_path)
        self._patch(
            monkeypatch,
            [_mal("MAL-1", "a-mcp", versions=["1.0.0"], events=[{"introduced": "0"}])],
        )
        assert (
            sync_mod.main(["--registry", str(reg), "--write", "--today", "2026-10-25"])
            == 0
        )
        path = tmp_path / "known-malicious.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert doc["last_updated"] == "2026-10-25"
        assert doc["entry_count"] == 1
        assert path.read_text(encoding="utf-8").endswith("}\n")
        # The analyzer's loader reads what the script writes.
        index = load_known_malicious(path)
        assert index.load_error is None
        assert [r.id for r in index.lookup("npm", "a-mcp")] == ["MAL-1"]
        assert sync_mod.main(["--registry", str(reg)]) == 0
        # The registry file itself is untouched by a malicious-only change.
        assert json.loads(reg.read_text(encoding="utf-8")) == {
            "schema_version": "1.0",
            "entries": [],
        }

    def test_export_failure_is_exit_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reg = self._registry(tmp_path)
        monkeypatch.setattr(sync_mod, "query_osv", lambda name, eco: [])

        def boom(eco: str, keep):  # type: ignore[no-untyped-def]
            raise RuntimeError("export unreachable")

        monkeypatch.setattr(sync_mod, "fetch_malicious_export", boom)
        assert sync_mod.main(["--registry", str(reg)]) == 2

    def test_malformed_existing_file_is_exit_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reg = self._registry(tmp_path)
        (tmp_path / "known-malicious.json").write_text("{bad", encoding="utf-8")
        self._patch(monkeypatch, [])
        assert sync_mod.main(["--registry", str(reg)]) == 2


class TestFetchMaliciousExport:
    """The zip-reading path, served from a local fake (no network)."""

    def _serve(self, monkeypatch: pytest.MonkeyPatch, payload: bytes) -> None:
        import io

        class _Resp(io.BytesIO):
            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *exc: object) -> None:
                self.close()

        monkeypatch.setattr(
            sync_mod.urllib.request, "urlopen", lambda url, timeout: _Resp(payload)
        )

    def _zip(self, members: dict[str, object]) -> bytes:
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, doc in members.items():
                zf.writestr(name, doc if isinstance(doc, str) else json.dumps(doc))
        return buf.getvalue()

    def test_keeps_matching_mal_records_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._serve(
            monkeypatch,
            self._zip(
                {
                    "MAL-1.json": _mal("MAL-1", "a-mcp"),
                    "MAL-2.json": _mal("MAL-2", "left-pad"),
                    "GHSA-x.json": _mal("GHSA-x", "b-mcp"),
                }
            ),
        )
        keep = sync_mod.package_selector({"entries": []})
        out = _REAL_FETCH_MALICIOUS("npm", keep)
        assert [r["id"] for r in out] == ["MAL-1"]

    def test_bad_zip_is_a_runtime_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._serve(monkeypatch, b"not a zip")
        with pytest.raises(RuntimeError, match="unreadable"):
            _REAL_FETCH_MALICIOUS("npm", lambda e, n: True)

    def test_bad_member_json_is_a_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._serve(monkeypatch, self._zip({"MAL-1.json": "{bad"}))
        with pytest.raises(RuntimeError):
            _REAL_FETCH_MALICIOUS("npm", lambda e, n: True)

    def test_oversized_download_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._serve(monkeypatch, b"x" * 64)
        monkeypatch.setattr(sync_mod, "_MAX_EXPORT_BYTES", 10)
        with pytest.raises(RuntimeError, match="too large"):
            _REAL_FETCH_MALICIOUS("npm", lambda e, n: True)

    def test_network_error_is_a_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def down(url: str, timeout: int) -> object:
            raise sync_mod.urllib.error.URLError("offline")

        monkeypatch.setattr(sync_mod.urllib.request, "urlopen", down)
        with pytest.raises(RuntimeError, match="download failed"):
            _REAL_FETCH_MALICIOUS("npm", lambda e, n: True)


class TestBundledMaliciousFile:
    """registry/known-malicious.json is exactly what the script would write."""

    @pytest.fixture(scope="class")
    def doc(self) -> dict:
        return json.loads(
            (ROOT / "registry" / "known-malicious.json").read_text(encoding="utf-8")
        )

    def test_header_and_count(self, doc: dict) -> None:
        assert doc["schema_version"] == "1.0"
        assert doc["entry_count"] == len(doc["entries"]) > 200
        assert doc["last_updated"]

    def test_every_entry_matches_the_selection_rule(self, doc: dict) -> None:
        registry = json.loads(
            (ROOT / "registry" / "known-servers.json").read_text(encoding="utf-8")
        )
        keep = sync_mod.package_selector(registry)
        for e in doc["entries"]:
            assert e["id"].startswith("MAL-")
            assert e["ecosystem"] in ("npm", "PyPI")
            assert keep(e["ecosystem"], e["name"]), e
            assert "withdrawn" not in e and "modified" not in e

    def test_sorted_and_unique(self, doc: dict) -> None:
        keys = [sync_mod._entry_key(e) for e in doc["entries"]]
        assert keys == sorted(keys)
        assert len(keys) == len(set(keys))

    def test_canary_family_carries_the_note(self, doc: dict) -> None:
        family = [e for e in doc["entries"] if e["id"] in sync_mod.NOTES]
        assert len(family) == 10
        assert all(e["note"] == sync_mod.NOTES[e["id"]] for e in family)
        assert {e["name"] for e in family} >= {"mcp-server-github", "mcp-server-git"}
        assert not [
            e for e in doc["entries"] if "note" in e and e["id"] not in sync_mod.NOTES
        ]
