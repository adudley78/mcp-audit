"""Analyze agent instruction and memory files for security issues.

Finding IDs
-----------
SKILL-001 (HIGH)
    Injection or exfiltration instruction detected in a skill / command /
    instruction file.  Fires when any PATTERNS entry from
    :mod:`mcp_audit.analyzers.poisoning` (except POISON-040/060 obfuscation
    patterns and POISON-050 length) matches the file body.

SKILL-002 (MEDIUM)
    Obfuscated or oversized block in a skill / command file.  Fires on
    zero-width Unicode (POISON-040), homoglyph substitution (POISON-060),
    or body length ≥ 2 000 chars.

SKILL-003 (MEDIUM)
    Unpinned external content instruction.  Fires when the file body
    references a raw ``http://`` or ``https://`` URL, suggesting the
    instruction may pull in or reference external (and potentially
    attacker-controlled) content at runtime.

MEM-001 (MEDIUM)
    Imperative override instruction in a memory file.  Fires on POISON-012
    (behavioral override) patterns only — more conservative than SKILL-001
    to control false-positive rate on innocuous project CLAUDE.md files.

MEM-002 (MEDIUM)
    Injection pattern in a memory file.  Fires on the restricted subset
    confirmed for memory: POISON-010 (XML markers), POISON-011 (LLM format
    markers), POISON-040 (zero-width Unicode), POISON-060 (homoglyphs).
    Exfiltration, cross-tool, and length patterns are intentionally excluded
    — the false-positive rate on innocent memory files is too high.

Pattern import policy
---------------------
Detection patterns are **imported** from :mod:`mcp_audit.analyzers.poisoning`
— the ``PATTERNS`` list is NOT forked or duplicated here.  Any change to the
master pattern list in ``poisoning.py`` automatically applies here.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from mcp_audit.agent_files.models import AgentFile, AgentFileSurface
from mcp_audit.analyzers.poisoning import PATTERNS, DetectionPattern
from mcp_audit.models import Finding, Severity

if TYPE_CHECKING:
    pass

# ── Pattern sub-sets ──────────────────────────────────────────────────────────

# IDs of obfuscation patterns that become SKILL-002 (not SKILL-001).
_OBFUSCATION_IDS: frozenset[str] = frozenset({"POISON-040", "POISON-060"})

# IDs of patterns used for MEM-002 (restricted memory injection set).
_MEM_INJECTION_IDS: frozenset[str] = frozenset(
    {"POISON-010", "POISON-011", "POISON-040", "POISON-060"}
)

# ID of the excessive-length pattern — applied to skills but not memory.
_LENGTH_PATTERN_ID: str = "POISON-050"

# MEM-001 uses the behavioral override pattern only.
_MEM_OVERRIDE_ID: str = "POISON-012"

# Minimum body length (chars) that triggers SKILL-002 oversized finding.
_SKILL_OVERSIZED_THRESHOLD: int = 2_000

# URL pattern for SKILL-003 (raw http/https URL in instruction text).
_EXTERNAL_URL_RE: re.Pattern[str] = re.compile(
    r"https?://[^\s\)\]>\"']{10,}", re.IGNORECASE
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_skill_surface(af: AgentFile) -> bool:
    """Return True for skill/command/instruction surfaces (not memory)."""
    return af.surface in (
        AgentFileSurface.CLAUDE_COMMAND,
        AgentFileSurface.CURSOR_RULE,
        AgentFileSurface.COPILOT_INSTRUCTION,
        AgentFileSurface.COPILOT_SCOPED,
        AgentFileSurface.COPILOT_PROMPT,
    )


def _is_memory_surface(af: AgentFile) -> bool:
    """Return True for memory/context surfaces."""
    return af.surface == AgentFileSurface.CLAUDE_MEMORY


def _skill_finding(
    af: AgentFile,
    finding_id: str,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    owasp_mcp_top_10: list[str],
    cwe: str | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="agent_files",
        client=af.client,
        server=af.display_name,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        finding_path=str(af.path),
        owasp_mcp_top_10=owasp_mcp_top_10,
        cwe=cwe,
    )


# ── Skill/instruction analyzers ───────────────────────────────────────────────


def _analyze_skill(af: AgentFile) -> list[Finding]:
    """Analyze one skill / command / instruction file.

    Returns SKILL-001, SKILL-002, and/or SKILL-003 findings.
    Deduplicates by (finding_id, poison_pattern_id) so the same pattern
    cannot produce two findings on the same file.
    """
    findings: list[Finding] = []
    text = af.body
    seen: set[tuple[str, str]] = set()

    def _emit(fid: str, pat_id: str, f: Finding) -> None:
        key = (fid, pat_id)
        if key not in seen:
            seen.add(key)
            findings.append(f)

    for pat in PATTERNS:
        # Length pattern: only fire when the full body is long enough — use
        # the len() check instead of running the DOTALL regex for speed.
        if pat.id == _LENGTH_PATTERN_ID:
            if len(text) >= _SKILL_OVERSIZED_THRESHOLD:
                _emit(
                    "SKILL-002",
                    pat.id,
                    _skill_finding(
                        af,
                        "SKILL-002",
                        Severity.MEDIUM,
                        "Oversized skill/command file",
                        (
                            f"The file '{af.path.name}' contains"
                            f" {len(text):,} characters, which exceeds the"
                            f" {_SKILL_OVERSIZED_THRESHOLD:,}-character"
                            " threshold. Oversized instruction files can be"
                            " used to inject hidden content into the agent"
                            " context window."
                        ),
                        f"File length: {len(text):,} chars",
                        "Review the full file content for hidden instructions."
                        " Keep skill files concise.",
                        owasp_mcp_top_10=["MCP03"],
                        cwe="CWE-116",
                    ),
                )
            continue

        match = pat.pattern.search(text)
        if not match:
            continue

        evidence_snippet = match.group(0)[:120]

        if pat.id in _OBFUSCATION_IDS:
            _emit(
                "SKILL-002",
                pat.id,
                _skill_finding(
                    af,
                    "SKILL-002",
                    Severity.MEDIUM,
                    f"Obfuscated content in skill file ({pat.name})",
                    (
                        f"The file '{af.path.name}' contains obfuscated"
                        f" content: {pat.description}. Stealth Unicode"
                        " techniques hide malicious instructions from human"
                        " reviewers while remaining readable to language models."
                    ),
                    f"Matched: {evidence_snippet!r}",
                    "Investigate and remove obfuscating Unicode characters.",
                    owasp_mcp_top_10=["MCP03"],
                    cwe=pat.cwe or "CWE-116",
                ),
            )
        else:
            # Injection / exfiltration pattern → SKILL-001
            _emit(
                "SKILL-001",
                pat.id,
                _skill_finding(
                    af,
                    "SKILL-001",
                    Severity.HIGH,
                    f"Injection/exfiltration instruction in skill file ({pat.name})",
                    (
                        f"The file '{af.path.name}' contains an instruction"
                        f" matching the pattern '{pat.name}': {pat.description}."
                        " This pattern is associated with prompt injection or"
                        " data exfiltration attacks."
                    ),
                    f"Matched: {evidence_snippet!r}",
                    (
                        "Review the file for malicious instructions. Remove any"
                        " content you did not intentionally add."
                    ),
                    owasp_mcp_top_10=["MCP03", "MCP01"],
                    cwe=pat.cwe,
                ),
            )

    # SKILL-003: unpinned external URL
    url_match = _EXTERNAL_URL_RE.search(text)
    if url_match:
        url_snippet = url_match.group(0)[:100]
        key = ("SKILL-003", "url")
        if key not in seen:
            seen.add(key)
            findings.append(
                _skill_finding(
                    af,
                    "SKILL-003",
                    Severity.MEDIUM,
                    "Skill file references external URL",
                    (
                        f"The file '{af.path.name}' references an external URL"
                        f" ({url_snippet!r}). Instruction files that fetch or"
                        " link to unpinned external content can be used to"
                        " inject malicious instructions via a compromised or"
                        " attacker-controlled external resource."
                    ),
                    f"URL: {url_snippet!r}",
                    (
                        "Pin all referenced external resources to a specific,"
                        " verified commit or content hash. Prefer self-contained"
                        " instruction files with no outbound references."
                    ),
                    owasp_mcp_top_10=["MCP03", "MCP04"],
                    cwe="CWE-829",
                )
            )

    return findings


# ── Memory analyzers ──────────────────────────────────────────────────────────


def _analyze_memory(af: AgentFile) -> list[Finding]:
    """Analyze one memory/context file (CLAUDE.md tiers).

    Uses the restricted pattern subset confirmed for memory to control FP rate.
    Returns MEM-001 and/or MEM-002 findings.
    """
    findings: list[Finding] = []
    text = af.body
    seen: set[tuple[str, str]] = set()

    # Patterns indexed by ID for O(1) lookup.
    patterns_by_id: dict[str, DetectionPattern] = {p.id: p for p in PATTERNS}

    def _emit(fid: str, pat_id: str, f: Finding) -> None:
        key = (fid, pat_id)
        if key not in seen:
            seen.add(key)
            findings.append(f)

    # MEM-001: behavioral override patterns only (POISON-012)
    override_pat = patterns_by_id.get(_MEM_OVERRIDE_ID)
    if override_pat:
        m = override_pat.pattern.search(text)
        if m:
            evidence_snippet = m.group(0)[:120]
            _emit(
                "MEM-001",
                _MEM_OVERRIDE_ID,
                _skill_finding(
                    af,
                    "MEM-001",
                    Severity.MEDIUM,
                    "Imperative override instruction in memory file",
                    (
                        f"The memory file '{af.path.name}' contains an"
                        " instruction that attempts to override agent behavior"
                        f" ({override_pat.description}). Memory files are"
                        " injected into every session — a malicious override"
                        " instruction persists across all future interactions."
                    ),
                    f"Matched: {evidence_snippet!r}",
                    (
                        "Review the memory file for instructions you did not"
                        " intentionally add. Remove any behavioral overrides."
                        " Restrict write access: chmod 600 CLAUDE.md (or"
                        " equivalent)."
                    ),
                    owasp_mcp_top_10=["MCP03"],
                    cwe="CWE-74",
                ),
            )

    # MEM-002: restricted injection subset (POISON-010/011/040/060)
    for pat_id in sorted(_MEM_INJECTION_IDS):
        pat = patterns_by_id.get(pat_id)
        if pat is None:
            continue
        m = pat.pattern.search(text)
        if not m:
            continue
        evidence_snippet = m.group(0)[:120]
        _emit(
            "MEM-002",
            pat_id,
            _skill_finding(
                af,
                "MEM-002",
                Severity.MEDIUM,
                f"Injection pattern in memory file ({pat.name})",
                (
                    f"The memory file '{af.path.name}' contains an injection"
                    f" pattern: {pat.description}. Because memory files are"
                    " loaded into every agent session, a single injected pattern"
                    " provides persistent control over the agent's behavior."
                ),
                f"Matched: {evidence_snippet!r}",
                (
                    "Inspect the memory file for content you did not add."
                    " Remove the offending pattern. Restrict write access to"
                    " the file."
                ),
                owasp_mcp_top_10=["MCP03"],
                cwe=pat.cwe or "CWE-74",
            ),
        )

    return findings


# ── Public API ────────────────────────────────────────────────────────────────


def analyze_agent_files(files: list[AgentFile]) -> list[Finding]:
    """Analyze a list of agent files for security issues.

    Dispatches each file to the appropriate analyzer based on its surface type.

    Args:
        files: Agent files returned by :func:`~mcp_audit.agent_files.discovery
            .discover_agent_files`.

    Returns:
        List of :class:`~mcp_audit.models.Finding` objects.  Empty when no
        issues are detected.
    """
    findings: list[Finding] = []
    for af in files:
        if _is_skill_surface(af):
            findings.extend(_analyze_skill(af))
        elif _is_memory_surface(af):
            findings.extend(_analyze_memory(af))
    return findings
