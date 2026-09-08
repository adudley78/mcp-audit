"""Tests for scripts/check_release_action_contracts.py (no network)."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_release_action_contracts as contracts  # noqa: E402

REAL_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


def _write_workflow(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "workflow.yml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


class TestFindActionUsages:
    def test_finds_pinned_sha_usage(self, tmp_path: Path) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - name: Upload artifact
                    uses: actions/upload-artifact@{REAL_SHA}
                    with:
                      name: foo
                      path: dist/
            """,
        )
        usages = contracts.find_action_usages(wf)
        assert len(usages) == 1
        usage = usages[0]
        assert usage.repo == "actions/upload-artifact"
        assert usage.sha == REAL_SHA
        assert usage.job == "build"
        assert usage.step_name == "Upload artifact"
        assert usage.with_keys == frozenset({"name", "path"})

    def test_skips_local_composite_action(self, tmp_path: Path) -> None:
        wf = _write_workflow(
            tmp_path,
            """\
            jobs:
              build:
                steps:
                  - uses: ./.github/actions/build-binary
                    with:
                      spec: foo.spec
            """,
        )
        assert contracts.find_action_usages(wf) == []

    def test_skips_floating_ref(self, tmp_path: Path) -> None:
        wf = _write_workflow(
            tmp_path,
            """\
            jobs:
              build:
                steps:
                  - uses: actions/checkout@v4
            """,
        )
        assert contracts.find_action_usages(wf) == []

    def test_step_with_no_with_block_has_empty_keys(self, tmp_path: Path) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - uses: actions/checkout@{REAL_SHA}
            """,
        )
        usages = contracts.find_action_usages(wf)
        assert usages[0].with_keys == frozenset()

    def test_step_name_falls_back_to_uses_string(self, tmp_path: Path) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - uses: actions/checkout@{REAL_SHA}
            """,
        )
        usages = contracts.find_action_usages(wf)
        assert usages[0].step_name == f"actions/checkout@{REAL_SHA}"


class TestIsRequiredWithoutDefault:
    def test_required_true_no_default(self) -> None:
        assert contracts.is_required_without_default({"required": True}) is True

    def test_required_true_with_default(self) -> None:
        spec = {"required": True, "default": "artifact"}
        assert contracts.is_required_without_default(spec) is False

    def test_required_false(self) -> None:
        assert contracts.is_required_without_default({"required": False}) is False

    def test_required_absent_defaults_to_not_required(self) -> None:
        assert contracts.is_required_without_default({}) is False

    def test_required_as_string_true(self) -> None:
        assert contracts.is_required_without_default({"required": "true"}) is True

    def test_required_as_string_false_is_not_required(self) -> None:
        # Guards against Python string-truthiness turning "false" into True.
        assert contracts.is_required_without_default({"required": "false"}) is False

    def test_default_of_none_still_counts_as_missing(self) -> None:
        spec = {"required": True, "default": None}
        assert contracts.is_required_without_default(spec) is True


class TestCheckUsage:
    def _usage(self, with_keys: frozenset[str]) -> contracts.ActionUsage:
        return contracts.ActionUsage(
            repo="actions/upload-artifact",
            sha=REAL_SHA,
            job="build",
            step_name="Upload artifact",
            with_keys=with_keys,
        )

    def test_clean_usage_has_no_violations(self) -> None:
        action_doc = {
            "inputs": {
                "name": {"required": False, "default": "artifact"},
                "path": {"required": True},
            }
        }
        usage = self._usage(frozenset({"name", "path"}))
        assert contracts.check_usage(usage, action_doc) == []

    def test_unknown_input_is_flagged(self) -> None:
        action_doc = {"inputs": {"path": {"required": True}}}
        usage = self._usage(frozenset({"path", "made-up-input"}))
        violations = contracts.check_usage(usage, action_doc)
        assert len(violations) == 1
        assert "made-up-input" in violations[0]
        assert "not a declared input" in violations[0]

    def test_missing_required_input_is_flagged(self) -> None:
        action_doc = {"inputs": {"path": {"required": True}}}
        usage = self._usage(frozenset())
        violations = contracts.check_usage(usage, action_doc)
        assert len(violations) == 1
        assert "required input `path`" in violations[0]
        assert "Input required and not supplied" in violations[0]

    def test_missing_required_input_with_default_is_not_flagged(self) -> None:
        action_doc = {"inputs": {"retention-days": {"required": True, "default": "0"}}}
        usage = self._usage(frozenset())
        assert contracts.check_usage(usage, action_doc) == []

    def test_action_with_no_inputs_key(self) -> None:
        usage = self._usage(frozenset())
        assert contracts.check_usage(usage, {}) == []


class TestFetchActionYaml:
    def test_uses_injected_fetcher_no_network(self) -> None:
        calls: list[str] = []

        def fake_fetch(url: str) -> str:
            calls.append(url)
            return "inputs:\n  path:\n    required: true\n"

        doc = contracts.fetch_action_yaml(
            "actions/upload-artifact", REAL_SHA, fetcher=fake_fetch
        )
        assert doc == {"inputs": {"path": {"required": True}}}
        assert calls == [
            f"https://raw.githubusercontent.com/actions/upload-artifact/{REAL_SHA}/action.yml"
        ]

    def test_falls_back_to_action_yaml_on_404(self) -> None:
        import urllib.error

        def fake_fetch(url: str) -> str:
            if url.endswith("action.yml"):
                raise urllib.error.HTTPError(url, 404, "not found", None, None)
            return "inputs: {}\n"

        doc = contracts.fetch_action_yaml("owner/repo", REAL_SHA, fetcher=fake_fetch)
        assert doc == {"inputs": {}}

    def test_raises_file_not_found_when_neither_candidate_exists(self) -> None:
        import urllib.error

        def fake_fetch(url: str) -> str:
            raise urllib.error.HTTPError(url, 404, "not found", None, None)

        try:
            contracts.fetch_action_yaml("owner/repo", REAL_SHA, fetcher=fake_fetch)
            raise AssertionError("expected FileNotFoundError")
        except FileNotFoundError:
            pass

    def test_non_404_http_error_propagates(self) -> None:
        import urllib.error

        def fake_fetch(url: str) -> str:
            raise urllib.error.HTTPError(url, 500, "server error", None, None)

        try:
            contracts.fetch_action_yaml("owner/repo", REAL_SHA, fetcher=fake_fetch)
            raise AssertionError("expected HTTPError to propagate")
        except urllib.error.HTTPError as exc:
            assert exc.code == 500


class TestCheckWorkflow:
    def test_clean_workflow_no_violations_no_fetch_errors(self, tmp_path: Path) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - uses: actions/upload-artifact@{REAL_SHA}
                    with:
                      path: dist/
            """,
        )

        def fake_fetch(url: str) -> str:
            return (
                "inputs:\n  path:\n    required: true\n  name:\n    required: false\n"
            )

        usages, violations, fetch_errors = contracts.check_workflow(
            wf, fetcher=fake_fetch
        )
        assert len(usages) == 1
        assert violations == []
        assert fetch_errors == []

    def test_fetches_each_unique_action_sha_once(self, tmp_path: Path) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - uses: actions/checkout@{REAL_SHA}
                  - uses: actions/checkout@{REAL_SHA}
            """,
        )
        calls: list[str] = []

        def fake_fetch(url: str) -> str:
            calls.append(url)
            return "inputs: {}\n"

        usages, violations, fetch_errors = contracts.check_workflow(
            wf, fetcher=fake_fetch
        )
        assert len(usages) == 2
        assert len(calls) == 1

    def test_fetch_failure_is_reported_not_raised(self, tmp_path: Path) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - uses: actions/checkout@{REAL_SHA}
            """,
        )

        def fake_fetch(url: str) -> str:
            raise ConnectionError("network is down")

        usages, violations, fetch_errors = contracts.check_workflow(
            wf, fetcher=fake_fetch
        )
        assert len(usages) == 1
        assert violations == []
        assert len(fetch_errors) == 1
        assert "network is down" in fetch_errors[0]

    def test_unknown_input_detected_end_to_end(self, tmp_path: Path) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - name: Upload artifact
                    uses: actions/upload-artifact@{REAL_SHA}
                    with:
                      name: foo
                      totally-made-up-input: yes
            """,
        )

        def fake_fetch(url: str) -> str:
            return (
                "inputs:\n  name:\n    required: false\n  path:\n    required: true\n"
            )

        usages, violations, fetch_errors = contracts.check_workflow(
            wf, fetcher=fake_fetch
        )
        assert fetch_errors == []
        assert len(violations) == 2  # unknown input + missing required `path`
        assert any("totally-made-up-input" in v for v in violations)
        assert any("required input `path`" in v for v in violations)


class TestMain:
    def _patch_fetcher(self, monkeypatch: Any, fake_fetch: Any) -> None:
        original = contracts.fetch_action_yaml

        def patched(repo: str, sha: str, *, fetcher: Any = None) -> dict[str, Any]:
            return original(repo, sha, fetcher=fake_fetch)

        monkeypatch.setattr(contracts, "fetch_action_yaml", patched)

    def test_exit_0_on_clean_workflow(
        self, tmp_path: Path, monkeypatch: Any, capsys: Any
    ) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - uses: actions/checkout@{REAL_SHA}
            """,
        )
        self._patch_fetcher(monkeypatch, lambda url: "inputs: {}\n")
        exit_code = contracts.main(["--workflow", str(wf)])
        assert exit_code == 0
        assert "OK:" in capsys.readouterr().out

    def test_exit_1_on_violation(
        self, tmp_path: Path, monkeypatch: Any, capsys: Any
    ) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - uses: actions/checkout@{REAL_SHA}
                    with:
                      made-up: yes
            """,
        )
        self._patch_fetcher(monkeypatch, lambda url: "inputs: {}\n")
        exit_code = contracts.main(["--workflow", str(wf)])
        assert exit_code == 1
        assert "made-up" in capsys.readouterr().err

    def test_exit_2_on_fetch_error(
        self, tmp_path: Path, monkeypatch: Any, capsys: Any
    ) -> None:
        wf = _write_workflow(
            tmp_path,
            f"""\
            jobs:
              build:
                steps:
                  - uses: actions/checkout@{REAL_SHA}
            """,
        )

        def raising_fetch(
            repo: str, sha: str, *, fetcher: Any = None
        ) -> dict[str, Any]:
            raise ConnectionError("network is down")

        monkeypatch.setattr(contracts, "fetch_action_yaml", raising_fetch)
        exit_code = contracts.main(["--workflow", str(wf)])
        assert exit_code == 2
        assert "could not verify" in capsys.readouterr().err

    def test_exit_2_on_missing_workflow_file(self, tmp_path: Path) -> None:
        exit_code = contracts.main(["--workflow", str(tmp_path / "does-not-exist.yml")])
        assert exit_code == 2
