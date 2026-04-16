"""Tests for pre-commit hook integration.

Covers:
- .pre-commit-hooks.yaml presence and YAML validity
- Required hook fields and correct values
- Exit-code behaviour: empty scan → 0, findings above threshold → 1,
  findings below threshold → 0
- Example file YAML validity
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.models import Finding, ScanResult, ScanScore, Severity

runner = CliRunner()

_REPO_ROOT = Path(__file__).parent.parent
_HOOKS_FILE = _REPO_ROOT / ".pre-commit-hooks.yaml"


# ── Helpers ─────────────────────────────────────────────────────────────────


def _load_yaml(path: Path) -> object:
    """Load and return parsed YAML from *path*; raises on invalid YAML."""
    assert path.exists(), f"File not found: {path}"
    with open(path) as fh:
        return yaml.safe_load(fh)


def _hook_def() -> dict:
    """Return the first (and only) hook definition from .pre-commit-hooks.yaml."""
    doc = _load_yaml(_HOOKS_FILE)
    assert isinstance(doc, list) and len(doc) >= 1, (
        ".pre-commit-hooks.yaml must be a non-empty YAML list"
    )
    return doc[0]


def _finding(severity: Severity, idx: int = 0) -> Finding:
    return Finding(
        id=f"TEST-{idx:03d}",
        severity=severity,
        analyzer="transport",
        client="cursor",
        server="test-server",
        title=f"Test finding {idx}",
        description="A test finding.",
        evidence="evidence text",
        remediation="Fix it.",
        finding_path="/tmp/test.json",  # noqa: S108
    )


def _result_with(*severities: Severity) -> ScanResult:
    findings = [_finding(sev, idx=i) for i, sev in enumerate(severities)]
    return ScanResult(
        clients_scanned=1,
        servers_found=1,
        findings=findings,
        score=ScanScore(
            numeric_score=60,
            grade="C",
            positive_signals=[],
            deductions=[],
        ),
    )


def _empty_result() -> ScanResult:
    return ScanResult(
        clients_scanned=0,
        servers_found=0,
        findings=[],
        score=ScanScore(
            numeric_score=100,
            grade="A",
            positive_signals=["No findings"],
            deductions=[],
        ),
    )


def _patch_scan(result: ScanResult):
    return patch("mcp_audit.cli.run_scan", return_value=result)


# ── File existence and YAML validity ────────────────────────────────────────


class TestHooksFileExists:
    def test_pre_commit_hooks_yaml_exists(self) -> None:
        assert _HOOKS_FILE.exists(), ".pre-commit-hooks.yaml not found at repo root"

    def test_pre_commit_hooks_yaml_is_valid_yaml(self) -> None:
        doc = _load_yaml(_HOOKS_FILE)
        assert doc is not None, ".pre-commit-hooks.yaml parsed as None (empty file?)"

    def test_hooks_file_is_a_list(self) -> None:
        doc = _load_yaml(_HOOKS_FILE)
        assert isinstance(doc, list), (
            ".pre-commit-hooks.yaml must be a YAML list at the top level"
        )

    def test_hooks_file_has_at_least_one_hook(self) -> None:
        doc = _load_yaml(_HOOKS_FILE)
        assert len(doc) >= 1, ".pre-commit-hooks.yaml must define at least one hook"


# ── Required hook fields ────────────────────────────────────────────────────


class TestHookDefinition:
    def test_hook_has_id(self) -> None:
        hook = _hook_def()
        assert "id" in hook, "Hook must have an 'id' field"

    def test_hook_id_is_mcp_audit(self) -> None:
        hook = _hook_def()
        assert hook["id"] == "mcp-audit", (
            f"Hook id must be 'mcp-audit', got {hook['id']!r}"
        )

    def test_hook_has_name(self) -> None:
        hook = _hook_def()
        assert "name" in hook, "Hook must have a 'name' field"

    def test_hook_has_language(self) -> None:
        hook = _hook_def()
        assert "language" in hook, "Hook must have a 'language' field"

    def test_hook_language_is_python(self) -> None:
        hook = _hook_def()
        assert hook["language"] == "python", (
            f"Hook language must be 'python', got {hook['language']!r}"
        )

    def test_hook_has_entry(self) -> None:
        hook = _hook_def()
        assert "entry" in hook, "Hook must have an 'entry' field"

    def test_hook_entry_is_mcp_audit(self) -> None:
        hook = _hook_def()
        assert hook["entry"] == "mcp-audit", (
            f"Hook entry must be 'mcp-audit', got {hook['entry']!r}"
        )

    def test_hook_pass_filenames_is_false(self) -> None:
        """pass_filenames=False is critical: mcp-audit uses its own discovery logic.

        pre-commit would otherwise pass individual staged JSON filenames to the
        entry command, but mcp-audit scan expects to discover full config files
        via its own client-aware discovery, not receive arbitrary JSON paths.
        """
        hook = _hook_def()
        assert hook.get("pass_filenames") is False, (
            "pass_filenames must be False — mcp-audit uses its own auto-discovery"
        )

    def test_hook_types_includes_json(self) -> None:
        hook = _hook_def()
        types = hook.get("types", [])
        assert "json" in types, (
            f"'types' must include 'json' to gate the hook on staged JSON files; "
            f"got {types!r}"
        )

    def test_hook_always_run_is_false(self) -> None:
        hook = _hook_def()
        assert hook.get("always_run") is False, (
            "always_run must be False — hook should only fire when JSON files are staged"  # noqa: E501
        )


# ── Exit-code behaviour ──────────────────────────────────────────────────────


class TestHookExitCodes:
    def test_exits_0_when_no_mcp_configs_found(self, tmp_path: Path) -> None:
        """An empty directory produces no findings — hook must not block the commit.

        This is the most important correctness property: a pre-commit hook that
        errors on repos without MCP configs will be uninstalled immediately.
        """
        with (
            patch("mcp_audit.discovery._get_client_specs", return_value=[]),
            patch("mcp_audit.cli.run_scan", return_value=_empty_result()),
        ):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "high"],
            )
        assert result.exit_code == 0, (
            f"Expected exit 0 for empty scan, got {result.exit_code}; "
            f"output: {result.output}"
        )

    def test_exits_1_when_high_finding_at_high_threshold(self) -> None:
        """HIGH finding at --severity-threshold high must block the commit (exit 1)."""
        with _patch_scan(_result_with(Severity.HIGH)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "high"],
            )
        assert result.exit_code == 1, (
            f"Expected exit 1 for HIGH finding at 'high' threshold, "
            f"got {result.exit_code}"
        )

    def test_exits_1_when_critical_finding_at_high_threshold(self) -> None:
        """CRITICAL finding at --severity-threshold high must block the commit."""
        with _patch_scan(_result_with(Severity.CRITICAL)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "high"],
            )
        assert result.exit_code == 1

    def test_exits_0_when_only_medium_finding_at_high_threshold(self) -> None:
        """MEDIUM finding below the 'high' threshold must not block the commit."""
        with _patch_scan(_result_with(Severity.MEDIUM)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "high"],
            )
        assert result.exit_code == 0, (
            f"Expected exit 0 for MEDIUM finding at 'high' threshold, "
            f"got {result.exit_code}"
        )

    def test_exits_0_when_only_low_finding_at_high_threshold(self) -> None:
        with _patch_scan(_result_with(Severity.LOW)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "high"],
            )
        assert result.exit_code == 0

    def test_exits_0_when_only_info_finding_at_high_threshold(self) -> None:
        with _patch_scan(_result_with(Severity.INFO)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "high"],
            )
        assert result.exit_code == 0

    def test_exits_1_when_medium_finding_at_medium_threshold(self) -> None:
        """Strict config (--severity-threshold medium) blocks on MEDIUM+."""
        with _patch_scan(_result_with(Severity.MEDIUM)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "medium"],
            )
        assert result.exit_code == 1

    def test_exits_0_when_only_low_finding_at_medium_threshold(self) -> None:
        with _patch_scan(_result_with(Severity.LOW)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "medium"],
            )
        assert result.exit_code == 0


# ── Example file YAML validity ───────────────────────────────────────────────


class TestExampleFiles:
    _EXAMPLES_DIR = _REPO_ROOT / "examples" / "pre-commit"

    def test_basic_example_exists(self) -> None:
        assert (self._EXAMPLES_DIR / "basic.yaml").exists()

    def test_basic_example_is_valid_yaml(self) -> None:
        doc = _load_yaml(self._EXAMPLES_DIR / "basic.yaml")
        assert doc is not None

    def test_basic_example_has_repos_key(self) -> None:
        doc = _load_yaml(self._EXAMPLES_DIR / "basic.yaml")
        assert "repos" in doc

    def test_basic_example_references_mcp_audit_hook(self) -> None:
        doc = _load_yaml(self._EXAMPLES_DIR / "basic.yaml")
        hook_ids = [
            h["id"] for repo in doc.get("repos", []) for h in repo.get("hooks", [])
        ]
        assert "mcp-audit" in hook_ids, (
            f"basic.yaml must reference hook id 'mcp-audit'; found: {hook_ids}"
        )

    def test_strict_example_exists(self) -> None:
        assert (self._EXAMPLES_DIR / "strict.yaml").exists()

    def test_strict_example_is_valid_yaml(self) -> None:
        doc = _load_yaml(self._EXAMPLES_DIR / "strict.yaml")
        assert doc is not None

    def test_strict_example_has_repos_key(self) -> None:
        doc = _load_yaml(self._EXAMPLES_DIR / "strict.yaml")
        assert "repos" in doc

    def test_strict_example_references_mcp_audit_hook(self) -> None:
        doc = _load_yaml(self._EXAMPLES_DIR / "strict.yaml")
        hook_ids = [
            h["id"] for repo in doc.get("repos", []) for h in repo.get("hooks", [])
        ]
        assert "mcp-audit" in hook_ids, (
            f"strict.yaml must reference hook id 'mcp-audit'; found: {hook_ids}"
        )

    def test_strict_example_overrides_severity_threshold(self) -> None:
        """The strict example must lower the threshold to 'medium'."""
        doc = _load_yaml(self._EXAMPLES_DIR / "strict.yaml")
        for repo in doc.get("repos", []):
            for hook in repo.get("hooks", []):
                if hook.get("id") == "mcp-audit":
                    args = hook.get("args", [])
                    assert "medium" in args, (
                        f"strict.yaml hook args must include 'medium'; got {args!r}"
                    )
                    return
        raise AssertionError("mcp-audit hook not found in strict.yaml")
