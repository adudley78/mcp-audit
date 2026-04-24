"""Validate that action.yml is well-formed and Marketplace-ready.

Covers structural requirements (name, description, author, branding, inputs,
outputs, composite runs block), input/output schema stability, and a handful
of correctness invariants for the shell steps:

    - `--format sarif` is used instead of a non-existent `--sarif` flag.
    - `github/codeql-action/upload-sarif@v4` is used (v3 / Node 20 deprecated
      2026-06-02).
    - `baseline compare` is invoked with a positional argument, not `--name`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ACTION_YAML = Path(__file__).parent.parent / "action.yml"


@pytest.fixture(scope="module")
def action() -> dict:
    return yaml.safe_load(ACTION_YAML.read_text())


class TestActionYamlStructure:
    def test_required_top_level_keys(self, action: dict) -> None:
        for key in (
            "name",
            "description",
            "author",
            "branding",
            "inputs",
            "outputs",
            "runs",
        ):
            assert key in action, f"action.yml missing required key: {key}"

    def test_runs_using_composite(self, action: dict) -> None:
        assert action["runs"]["using"] == "composite"

    def test_branding_present(self, action: dict) -> None:
        branding = action["branding"]
        assert branding.get("icon"), "branding.icon must be non-empty"
        assert branding.get("color"), "branding.color must be non-empty"

    def test_all_inputs_have_description_and_required(self, action: dict) -> None:
        for name, inp in action["inputs"].items():
            assert "description" in inp, f"input '{name}' missing description"
            assert "required" in inp, f"input '{name}' missing required field"

    def test_all_outputs_have_description(self, action: dict) -> None:
        for name, out in action["outputs"].items():
            assert "description" in out, f"output '{name}' missing description"

    def test_expected_inputs_present(self, action: dict) -> None:
        expected = {
            "config-paths",
            "severity-threshold",
            "sarif-output",
            "upload-sarif",
            "check-vulns",
            "verify-signatures",
            "run-sast",
            "sast-path",
            "baseline-name",
            "fail-on-findings",
            "version",
        }
        missing = expected - set(action["inputs"].keys())
        assert not missing, f"action.yml missing expected inputs: {missing}"

    def test_old_input_names_removed(self, action: dict) -> None:
        """Ensure old schema names are gone — they silently do nothing if left."""
        old_names = {"format", "sast", "baseline"}
        present = old_names & set(action["inputs"].keys())
        assert not present, (
            f"Old input names still present in action.yml: {present}. "
            "Rename mapping: sast→run-sast, baseline→baseline-name; "
            "'format' removed."
        )

    def test_expected_outputs_present(self, action: dict) -> None:
        expected = {"findings-count", "grade", "sarif-path"}
        missing = expected - set(action["outputs"].keys())
        assert not missing, f"action.yml missing expected outputs: {missing}"

    def test_old_output_name_removed(self, action: dict) -> None:
        """`finding-count` (no s) was renamed to `findings-count`."""
        assert "finding-count" not in action["outputs"], (
            "Old output 'finding-count' still present. Rename to 'findings-count'."
        )


class TestActionYamlSecurity:
    def test_no_hardcoded_secrets(self) -> None:
        content = ACTION_YAML.read_text()
        patterns = [
            r"sk-[a-zA-Z0-9]{20,}",
            r"ghp_[a-zA-Z0-9]{36}",
            r"AKIA[A-Z0-9]{16}",
        ]
        for pattern in patterns:
            assert not re.search(pattern, content), (
                f"Possible hardcoded secret matching {pattern!r} in action.yml"
            )

    def test_no_sarif_flag_typo(self) -> None:
        """Shell steps must use `--format sarif`, not the non-existent `--sarif` flag.

        The leading hyphens and trailing space narrow the check to CLI flag
        usage and skip unrelated substrings like 'upload-sarif'.
        """
        content = ACTION_YAML.read_text()
        for lineno, line in enumerate(content.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "--sarif " in line and "upload-sarif" not in line:
                pytest.fail(
                    f"Found '--sarif' flag in action.yml at line {lineno}: "
                    f"{line.strip()!r}. Use '--format sarif --output <path>'."
                )

    def test_upload_sarif_uses_v4(self) -> None:
        """SARIF upload must use `codeql-action/upload-sarif@v4`.

        v3 (Node 20) is deprecated as of 2026-06-02.
        """
        content = ACTION_YAML.read_text()
        assert "upload-sarif@v4" in content, (
            "SARIF upload step must use github/codeql-action/upload-sarif@v4. "
            "v3 (Node 20) is deprecated as of 2026-06-02."
        )
        assert "upload-sarif@v3" not in content, (
            "upload-sarif@v3 found — replace with @v4."
        )

    def test_baseline_compare_uses_positional_arg(self) -> None:
        """`baseline compare` takes a positional argument, not `--name`.

        Wrong form crashes at runtime with an unknown-option error.
        """
        content = ACTION_YAML.read_text()
        assert "baseline compare --name" not in content, (
            "`baseline compare` does not accept --name. "
            'Use: mcp-audit baseline compare "$BASELINE_NAME" (positional).'
        )
