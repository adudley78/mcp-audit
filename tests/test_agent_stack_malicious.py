"""STORY-0152: the known-malicious mirror covers the agent stack, not only MCP names.

``scripts/sync_registry_advisories.py`` keeps OSV ``MAL-*`` records whose
package name contains ``mcp``, that the registry lists, or (since STORY-0152)
that has a token naming a coding agent mcp-audit reads or an agent skill
(:data:`AGENT_STACK_TOKENS`).  These tests pin the filter on names from OSV's
2026-11-11 export, that the shipped file is what the filter keeps and stays
bounded, and that every offline consumer (SC-008, ``vet``, ``affected``)
reads the added records.  No network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcp_audit.affected.match import rules_for_advisory
from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer
from mcp_audit.models import ServerConfig
from mcp_audit.registry.loader import load_registry
from mcp_audit.registry.malicious import load_known_malicious
from mcp_audit.registry.research import load_research_records

ROOT = Path(__file__).resolve().parent.parent
BUNDLED = ROOT / "registry" / "known-malicious.json"

sys.path.insert(0, str(ROOT / "scripts"))
try:
    import sync_registry_advisories as sync  # noqa: E402
finally:
    sys.path.pop(0)


# ── The filter ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        "agentic-awesome-skills",  # MAL-2026-18192
        "opencode-skills-collection",  # MAL-2026-18193
        "@chatclub/claude-code",
        "claude-desktop-setup",
        "@ikyyofc/gemini-cli",
        "gemini-cli-a2a-server",
        "cursor-bypass",
        "@mastra/cursor",
        "codex-setup",
        "openclaw-agent",
        "@openclaw-cn/cli",
        "amazon-q-vscode",
        "claw-subagent-service",
        "skills-validator",
        "CLAUDE_Lite",
    ],
)
def test_agent_stack_names_are_kept(name: str) -> None:
    assert sync.is_agent_stack_name(name)


@pytest.mark.parametrize(
    "name",
    [
        # Substrings of the words, not tokens (OSV spam shapes).
        "skilled_wildebeest_beige-32",
        "gitsskill",
        "inclined_ant_z3n",
        "searchcursor",
        "codexworld",
        "superagent-eleventy-mongoose-schema",
        # Words measured and left out.
        "gemini-publish-gacrux-morgan",
        "vite-plugin-next-refresh",
        "@posthog/agent",
        "anthropic-sdk",
        "openai-beta",
        "magellan-prompts-wormhole-apollo",
        "",
    ],
)
def test_other_names_are_not(name: str) -> None:
    assert not sync.is_agent_stack_name(name)


def test_selector_still_keeps_mcp_names_and_registry_entries() -> None:
    keep = sync.package_selector(
        {"entries": [{"name": "Some.Server", "package_ecosystem": "pypi"}]}
    )
    assert keep("npm", "timemcp")
    assert keep("PyPI", "some-server")
    assert keep("npm", "agentic-awesome-skills")
    assert not keep("npm", "left-pad")


def test_selector_keeps_an_agent_stack_record_from_an_export() -> None:
    records = [
        {
            "id": "MAL-2026-18192",
            "aliases": ["GHSA-rgwm-3jj9-h563"],
            "summary": "Malicious code in agentic-awesome-skills (npm)",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "agentic-awesome-skills"},
                    "versions": ["19.8.0"],
                }
            ],
        },
        {
            "id": "MAL-2026-1",
            "affected": [{"package": {"ecosystem": "npm", "name": "skilled_kiwi"}}],
        },
    ]
    keep = sync.package_selector({"entries": []})
    entries = sync.malicious_entries(records, "npm", keep)
    assert [e["name"] for e in entries] == ["agentic-awesome-skills"]


# ── The shipped file ─────────────────────────────────────────────────────────


def _shipped() -> dict:
    return json.loads(BUNDLED.read_text(encoding="utf-8"))


def test_every_shipped_record_passes_the_filter() -> None:
    registry = json.loads(
        (ROOT / "registry" / "known-servers.json").read_text(encoding="utf-8")
    )
    keep = sync.package_selector(registry)
    for entry in _shipped()["entries"]:
        assert keep(entry["ecosystem"], entry["name"]), entry["name"]


def test_shipped_file_stays_bounded() -> None:
    """335 records on 2026-11-11; far under the loader's 50,000-entry cap.

    The token list is closed, so growth follows OSV's rate for these names.
    If this fails, re-measure the filter (STORY-0152) before raising it.
    """
    doc = _shipped()
    assert doc["entry_count"] == len(doc["entries"])
    assert 300 <= len(doc["entries"]) <= 1500
    assert BUNDLED.stat().st_size < 1024 * 1024


def test_header_describes_the_filter() -> None:
    assert "agent skill" in _shipped()["description"]


# ── Every offline consumer reads the added records ───────────────────────────


@pytest.mark.parametrize(
    ("eco", "name", "rid"),
    [
        ("npm", "agentic-awesome-skills", "MAL-2026-18192"),
        ("npm", "opencode-skills-collection", "MAL-2026-18193"),
        ("npm", "@chatclub/claude-code", "MAL-2025-49379"),
        ("npm", "@ikyyofc/gemini-cli", "MAL-2026-4394"),
        ("pypi", "claude-lite", "MAL-2026-2269"),
        # mcp-named, published 2026-11-10 after the last write.
        ("npm", "@lemili9804/mcp-weather-server", "MAL-2026-19085"),
    ],
)
def test_lookup_finds_the_record(eco: str, name: str, rid: str) -> None:
    assert rid in [r.id for r in load_known_malicious().lookup(eco, name)]


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "agentic-awesome-skills"]),
        ("npx", ["-y", "opencode-skills-collection@4.1.6"]),
        ("npx", ["-y", "@chatclub/claude-code"]),
        ("uvx", ["claude-lite"]),
    ],
)
def test_a_launch_is_sc_008(command: str, args: list[str]) -> None:
    server = ServerConfig(
        name="s", command=command, args=args, client="claude", config_path="/x.json"
    )
    out = SupplyChainAnalyzer(offline_registry=True).analyze(server)
    assert "SC-008" in [f.id for f in out]


def test_vet_reports_the_skill_collection() -> None:
    from typer.testing import CliRunner

    from mcp_audit.cli import app

    result = CliRunner().invoke(
        app, ["vet", "agentic-awesome-skills", "--format", "json"]
    )
    verdict = json.loads(result.stdout)
    assert [m["id"] for m in verdict["malicious"]] == ["MAL-2026-18192"]
    # The record lists past releases only, so vet (which answers for the
    # latest release) shows the panel and exits 0, as for any such record.
    assert verdict["malicious"][0]["latest_affected"] is False
    assert result.exit_code == 0
    text = CliRunner().invoke(app, ["vet", "agentic-awesome-skills"]).output
    assert "Malicious releases listed in OSV" in text


def test_affected_resolves_the_record_offline() -> None:
    ruleset = rules_for_advisory(
        "MAL-2026-18193",
        load_registry(),
        load_known_malicious(),
        load_research_records(),
    )
    assert ruleset.found
    assert "known-malicious mirror" in ruleset.sources


# ── Knostic credit on two @ifasn records (STORY-0152) ────────────────────────


@pytest.mark.parametrize(
    ("name", "rid", "fact"),
    [
        ("@ifasn/mmdd-doc-mcp", "MAL-2026-18489", "121.199.24.94"),
        ("@ifasn/ms-doc-mcp", "MAL-2026-18603", "output/env_audit.txt"),
    ],
)
def test_knostic_markdown_records_credit_the_researcher(
    name: str, rid: str, fact: str
) -> None:
    (rec,) = [r for r in load_known_malicious().lookup("npm", name) if r.id == rid]
    note = rec.note or ""
    assert "Tamir Isaschar (Knostic)" in note
    assert "more-than-markdown-hidden-data-collection" in note
    assert fact in note
    raw = {e["id"]: e for e in _shipped()["entries"]}
    assert raw[rid]["note"] == sync.NOTES[rid]
