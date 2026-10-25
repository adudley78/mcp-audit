"""Validate that action.yml and setup-action/action.yml are well-formed.

Covers structural requirements (name, description, author, branding, inputs,
outputs, composite runs block), input/output schema stability, and a handful
of correctness invariants for the shell steps:

    - `--format sarif` is used instead of a non-existent `--sarif` flag.
    - `github/codeql-action/upload-sarif` is SHA-pinned to a v4 release (v3 /
      Node 20 deprecated 2026-06-02).
    - every third-party action ref in action.yml, setup-action/ and .github/
      is pinned to a full commit SHA with a version comment (STORY-0102).
    - `baseline compare` is invoked with a positional argument, not `--name`.
    - setup-action/action.yml has the required structure and expected I/O.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ACTION_YAML = Path(__file__).parent.parent / "action.yml"
SETUP_ACTION_YAML = Path(__file__).parent.parent / "setup-action" / "action.yml"


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
            "lock-verify",
            "lock-resolve",
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
        """SARIF upload must be a SHA-pinned `codeql-action/upload-sarif` v4.

        v3 (Node 20) is deprecated as of 2026-06-02. The ref is a commit SHA
        (a tag can be moved after review); the comment names the v4 release.
        """
        content = ACTION_YAML.read_text()
        assert re.search(
            r"uses: github/codeql-action/upload-sarif@[0-9a-f]{40} # v4\.\d+\.\d+\b",
            content,
        ), (
            "SARIF upload step must use github/codeql-action/upload-sarif pinned "
            "to a v4 commit SHA (`@<sha> # v4.x.y`). v3 (Node 20) is deprecated "
            "as of 2026-06-02."
        )
        assert "upload-sarif@v3" not in content, (
            "upload-sarif@v3 found — replace with a v4 commit SHA."
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

    def test_lock_verify_step_uses_if_present(self, action: dict) -> None:
        """The lock-verify step must never break a repo with no mcp-lock.json.

        `--if-present` (STORY-0070) makes a missing lock file a soft, exit-0
        skip; without it, enabling `lock-verify` on a repo that has not run
        `mcp-audit lock` yet would hard-fail with exit 2.
        """
        steps = action["runs"]["steps"]
        lock_steps = [s for s in steps if "lock" in s.get("name", "").lower()]
        assert lock_steps, "action.yml must have a lock-verification step"
        combined_run = "\n".join(s.get("run", "") for s in lock_steps)
        assert "--if-present" in combined_run, (
            "lock-verify step must pass --if-present so a repo without "
            "mcp-lock.json does not get a hard failure."
        )
        assert "lock --verify" in combined_run

    def test_lock_verify_step_gated_by_input(self, action: dict) -> None:
        steps = action["runs"]["steps"]
        lock_steps = [s for s in steps if "lock" in s.get("name", "").lower()]
        for step in lock_steps:
            assert "inputs.lock-verify" in step.get("if", ""), (
                f"Step {step.get('name')!r} must be gated on inputs.lock-verify"
            )

    def test_scanner_action_uses_setup_action(self, action: dict) -> None:
        """The scanner action must delegate install to ./setup-action, not pip."""
        steps = action["runs"]["steps"]
        uses_refs = [s.get("uses", "") for s in steps]

        # setup-action must be referenced
        assert any("setup-action" in u for u in uses_refs), (
            "action.yml must delegate install to ./setup-action "
            "(replace the pip install step with `uses: ./setup-action`)."
        )

        # pip install must not remain
        content = ACTION_YAML.read_text()
        assert "pip install mcp-audit-scanner" not in content, (
            "action.yml still contains `pip install mcp-audit-scanner`. "
            "Remove it — the binary is now installed via ./setup-action."
        )
        assert "setup-python" not in content, (
            "action.yml still contains `actions/setup-python`. "
            "Remove it — Python setup is no longer needed for binary install."
        )


@pytest.fixture(scope="module")
def setup_action() -> dict:
    return yaml.safe_load(SETUP_ACTION_YAML.read_text())


class TestSetupActionYaml:
    """Validate setup-action/action.yml structure and correctness."""

    def test_file_exists(self) -> None:
        assert SETUP_ACTION_YAML.exists(), (
            "setup-action/action.yml not found. Create it as documented in STORY-0033."
        )

    def test_required_top_level_keys(self, setup_action: dict) -> None:
        for key in (
            "name",
            "description",
            "author",
            "branding",
            "inputs",
            "outputs",
            "runs",
        ):
            assert key in setup_action, (
                f"setup-action/action.yml missing required key: {key}"
            )

    def test_runs_using_composite(self, setup_action: dict) -> None:
        assert setup_action["runs"]["using"] == "composite"

    def test_expected_inputs_present(self, setup_action: dict) -> None:
        assert "version" in setup_action["inputs"], (
            "setup-action/action.yml must have a 'version' input"
        )
        assert "github-token" in setup_action["inputs"], (
            "setup-action/action.yml must have a 'github-token' input "
            "for API rate-limit handling"
        )

    def test_all_inputs_have_description_and_required(self, setup_action: dict) -> None:
        for name, inp in setup_action["inputs"].items():
            assert "description" in inp, (
                f"setup-action input '{name}' missing description"
            )
            assert "required" in inp, (
                f"setup-action input '{name}' missing required field"
            )

    def test_output_mcp_audit_version(self, setup_action: dict) -> None:
        assert "mcp-audit-version" in setup_action["outputs"], (
            "setup-action/action.yml must expose a 'mcp-audit-version' output"
        )

    def test_all_outputs_have_description(self, setup_action: dict) -> None:
        for name, out in setup_action["outputs"].items():
            assert "description" in out, (
                f"setup-action output '{name}' missing description"
            )

    def test_version_input_defaults_to_latest(self, setup_action: dict) -> None:
        version_input = setup_action["inputs"]["version"]
        assert version_input.get("default") == "latest", (
            "setup-action version input must default to 'latest'"
        )

    def test_uses_actions_cache(self, setup_action: dict) -> None:
        steps = setup_action["runs"]["steps"]
        uses_refs = [s.get("uses", "") for s in steps]
        assert any("actions/cache" in u for u in uses_refs), (
            "setup-action must use actions/cache for binary caching"
        )

    def test_no_hardcoded_secrets(self) -> None:
        content = SETUP_ACTION_YAML.read_text()
        patterns = [
            r"sk-[a-zA-Z0-9]{20,}",
            r"ghp_[a-zA-Z0-9]{36}",
            r"AKIA[A-Z0-9]{16}",
        ]
        for pattern in patterns:
            assert not re.search(pattern, content), (
                f"Possible hardcoded secret matching {pattern!r} "
                "in setup-action/action.yml"
            )

    def test_all_four_platforms_covered(self) -> None:
        """Binary name mapping must cover all four supported OS/arch combos."""
        content = SETUP_ACTION_YAML.read_text()
        for binary in (
            "mcp-audit-linux-x86_64",
            "mcp-audit-darwin-x86_64",
            "mcp-audit-darwin-arm64",
            "mcp-audit-windows-x86_64",
        ):
            assert binary in content, (
                f"setup-action/action.yml missing binary mapping for: {binary}"
            )

    def test_windows_exe_extension(self) -> None:
        content = SETUP_ACTION_YAML.read_text()
        assert ".exe" in content, (
            "setup-action must handle .exe extension for Windows binary"
        )


# ---------------------------------------------------------------------------
# Every third-party action ref is SHA-pinned (STORY-0102)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent
_SHA_PIN_RE = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _action_files() -> list[Path]:
    """Every file GitHub reads `uses:` refs from: workflows and composites."""
    files = sorted((_REPO_ROOT / ".github").rglob("*.yml"))
    files += sorted((_REPO_ROOT / ".github").rglob("*.yaml"))
    return [ACTION_YAML, SETUP_ACTION_YAML, *files]


def _walk_uses(node: object) -> list[str]:
    """Every string value of a `uses` key anywhere in a parsed YAML document.

    Parsing (rather than matching lines) also sees flow-style steps such as
    `- { uses: owner/repo@v1 }` and reusable-workflow `jobs.<id>.uses`.
    """
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uses" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_walk_uses(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk_uses(item))
    return found


def _uses_refs() -> list[tuple[Path, str]]:
    """Return (file, ref) for every `uses:` in every action/workflow file."""
    refs: list[tuple[Path, str]] = []
    for path in _action_files():
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            refs.extend((path, ref) for ref in _walk_uses(doc))
    return refs


def _has_version_comment(path: Path, ref: str) -> bool:
    """True when the line carrying *ref* ends with a `# vX[.Y.Z]` comment."""
    pattern = re.compile(
        rf"uses:\s*['\"]?{re.escape(ref)}['\"]?[\s,}}]*#\s*v\d+(?:\.\d+)*\b"
    )
    return any(
        pattern.search(line) and not line.lstrip().startswith("#")
        for line in path.read_text(encoding="utf-8").splitlines()
    )


def test_uses_walker_sees_flow_style_and_reusable_workflow_refs() -> None:
    """Guard the walker: block, flow-style and `jobs.<id>.uses` refs all count."""
    doc = yaml.safe_load(
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "      - uses: one/block@v1\n"
        "      - { uses: two/flow@v2, with: { x: 1 } }\n"
        "  b:\n"
        "    uses: three/reusable/.github/workflows/w.yml@v3\n"
    )
    assert sorted(_walk_uses(doc)) == [
        "one/block@v1",
        "three/reusable/.github/workflows/w.yml@v3",
        "two/flow@v2",
    ]


def test_action_ref_scan_sees_the_codeql_refs() -> None:
    """Guard the scanner itself: it must find the four codeql-action refs."""
    codeql = [r for r in _uses_refs() if r[1].startswith("github/codeql-action/")]
    names = sorted(r[1].split("@")[0] for r in codeql)
    assert names == [
        "github/codeql-action/analyze",
        "github/codeql-action/autobuild",
        "github/codeql-action/init",
        "github/codeql-action/upload-sarif",
    ]


def test_every_third_party_action_ref_is_sha_pinned() -> None:
    """A tag can be moved after review; a 40-hex commit SHA cannot.

    Local refs (`./...`) are this repo's own code at the same commit. The
    trailing `# vX.Y.Z` comment is what Dependabot reads and updates.
    """
    bad = []
    for path, ref in _uses_refs():
        if ref.startswith("./"):
            continue
        rel = path.relative_to(_REPO_ROOT)
        if not _SHA_PIN_RE.match(ref):
            bad.append(f"{rel}: {ref} is not pinned to a commit SHA")
        elif not _has_version_comment(path, ref):
            bad.append(f"{rel}: {ref} has no `# vX.Y.Z` comment")
    assert not bad, "\n".join(bad)


def test_codeql_action_refs_share_one_sha() -> None:
    """init/autobuild/analyze/upload-sarif are one release; one bump moves all."""
    shas = {
        ref.split("@")[1]
        for _, ref in _uses_refs()
        if ref.startswith("github/codeql-action/")
    }
    assert len(shas) == 1, f"codeql-action SHA drift: {shas}"
