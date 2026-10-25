#!/usr/bin/env python3
"""Measure how well POISON-* findings match reality (STORY-0088). Dev tooling only.

Not shipped in the wheel and never imported by ``mcp_audit``; nothing in a scan
path calls it. It feeds tool definitions to the same code ``scan --connect``
runs (``build_runtime_server_config`` + ``PoisoningAnalyzer``) and counts what
fires. Two measurements, both written to
``docs/research/poisoning-benchmark/results.json`` and explained in
``docs/poisoning.md``:

``precision``
    Offline. The published top-100 npm scan
    (``docs/research/2026-10-top100-npm/summary.json``, mcp-audit 0.21.0) and
    the hand labels in ``docs/research/poisoning-benchmark/top100-labels.json``.
    Every finding in the corpus must be covered by a label, or the run fails.
    This is a fixed measurement of the code that produced those findings
    (``labelled_patterns_fingerprint``); re-measuring it needs a fresh
    enumeration of the corpus, which runs third-party servers and so never
    happens here or in CI. When the current code differs, the run prints a
    STALE line. What does re-run is the replay of every committed evidence
    fragment through the current analyzer, plus (under ``recall``) MCPTox's
    clean-tool flag rate: those are the precision checks a later change is
    gated on.

``recall``
    Needs MCPTox (arXiv 2508.14925, AAAI 2026): ``response_all.json`` (1,348
    poisoned test cases, 1,312 of them marked valid, plus the 45 servers'
    clean tool lists) and ``pure_tool.json`` (485 poisoned descriptions with no
    keyword wrapper). ``--source`` is a local directory holding both files or
    an ``https://`` base URL; the default is the authors' anonymized
    repository. Dev-only network: the files are read into memory, hashed and
    never written anywhere. The dataset has no stated licence, so it is never
    committed; ``results.json`` records each file's SHA-256 instead.

Recall and the clean-tool flag rate are reported twice: for any POISON-*
finding (what a plain ``scan`` exits 1 on, its default threshold being INFO)
and for HIGH or CRITICAL only (what ``check``, the pre-commit default and
``--severity-threshold high`` fail on).

``--check`` compares a fresh measurement with ``results.json`` and exits 1
only on a regression: fewer poisoned cases detected, or more clean tools
flagged. Improvements are reported, not failed. ``--write`` records the fresh
measurement, and never after a regression. ``recall`` is a manual,
release-time measurement and never runs in CI: run it before any release that
changes ``analyzers/poisoning.py`` or ``build_runtime_server_config`` (the
offline fingerprint test in ``tests/test_bench_poisoning.py`` fails until you
do).

Usage::

    python scripts/bench_poisoning.py precision --check
    python scripts/bench_poisoning.py recall --check
    python scripts/bench_poisoning.py recall --source ~/data/mcptox --write
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import inspect
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_audit.analyzers import poisoning as _poisoning
from mcp_audit.mcp_client import build_runtime_server_config
from mcp_audit.models import ServerConfig, ServerEnumeration, ToolInfo, TransportType

ROOT = Path(__file__).resolve().parent.parent
RESULTS_PATH = ROOT / "docs" / "research" / "poisoning-benchmark" / "results.json"
LABELS_PATH = ROOT / "docs" / "research" / "poisoning-benchmark" / "top100-labels.json"
SUMMARY_PATH = ROOT / "docs" / "research" / "2026-10-top100-npm" / "summary.json"

MCPTOX_DEFAULT_SOURCE = "https://anonymous.4open.science/api/repo/AAAI26-7C02/file/"
MCPTOX_FILES = ("response_all.json", "pure_tool.json")
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 120.0

# MCPTox's data files say "Template-1/2/3"; the paper's Table 1 calls the same
# three paradigms P1/P2/P3 (confirmed by content: Template-1 tools mimic a
# common function, Template-2 tools pose as a pre-check another tool must run
# first, Template-3 tools rewrite another tool's arguments).
PARADIGMS: dict[str, str] = {"Template-1": "P1", "Template-2": "P2", "Template-3": "P3"}
PARADIGM_NAMES: dict[str, str] = {
    "P1": "explicit trigger, function hijacking",
    "P2": "implicit trigger, function hijacking",
    "P3": "implicit trigger, parameter tampering",
}
# The two "enhanced settings" of MCPTox §4.4, detected the way the authors'
# own analysis notebook classifies them (substring tests).
WRAPPERS: tuple[str, ...] = ("important", "ignore", "none")
# What `check`, the pre-commit default and `--severity-threshold high` fail on.
HIGH_OR_ABOVE: frozenset[str] = frozenset({"HIGH", "CRITICAL"})

_TOOL_HEADER = re.compile(
    r"\s*Tool:\s*(?P<name>[^\n]*)\n\s*Description:\s*(?P<rest>.*)", re.S
)
_ARG_LINE = re.compile(r"\s*-\s*(?P<name>[^:\n]+):\s*(?P<desc>.*)")
_TOOL_SPLIT = re.compile(r"(?=^Tool: )", re.M)


class BenchError(Exception):
    """The input data is not what the benchmark expects (exit code 2)."""


class DatasetUnavailableError(BenchError):
    """MCPTox could not be fetched, or no longer matches the pinned hashes."""


@dataclass
class ToolDef:
    """One tool definition as an MCP client would receive it."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)


# ── shared plumbing ───────────────────────────────────────────────────────────


def _source(obj: Any) -> str:
    """Return *obj*'s source with line endings normalized (CRLF checkouts)."""
    return inspect.getsource(obj).replace("\r\n", "\n")


def fingerprint_payload() -> dict[str, Any]:
    """Return everything the detection-code fingerprint covers.

    The whole source of ``analyzers/poisoning.py`` (patterns, normalization,
    concealment channels, the analyzer itself) and of
    ``mcp_client.build_runtime_server_config`` (which decides what text of a
    live tool reaches the analyzer), plus the pattern table as loaded.
    """
    return {
        "poisoning_module_source": _source(_poisoning),
        "build_runtime_server_config_source": _source(build_runtime_server_config),
        "patterns": [
            [
                p.id,
                p.pattern.pattern,
                p.pattern.flags,
                p.severity.value,
                p.description_only,
                list(p.requires_cooccurrence or ()),
            ]
            for p in _poisoning.PATTERNS
        ],
        "confusables": sorted(_poisoning._CONFUSABLES.items()),
        "strip_categories": sorted(_poisoning._STRIP_CATEGORIES),
        "obfuscation_ids": sorted(_poisoning._OBFUSCATION_PATTERN_IDS),
        "cooccurrence_window": _poisoning._COOCCURRENCE_WINDOW,
    }


def patterns_fingerprint() -> str:
    """Return a SHA-256 over the POISON-* detection code (:func:`fingerprint_payload`).

    Any change to ``analyzers/poisoning.py`` or ``build_runtime_server_config``
    changes it. A measurement taken under a different fingerprint describes
    different code.
    """
    blob = json.dumps(fingerprint_payload(), ensure_ascii=True, sort_keys=True)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def poison_findings(tool: ToolDef) -> list[tuple[str, str]]:
    """Return sorted ``(id, severity)`` POISON-* findings ``scan --connect`` reports."""
    server = ServerConfig(
        name="bench",
        client="bench",
        config_path=Path("bench.json"),
        transport=TransportType.STDIO,
        command="bench",
    )
    enumeration = ServerEnumeration(
        tools=[
            ToolInfo(
                name=tool.name,
                description=tool.description,
                input_schema=tool.input_schema,
            )
        ]
    )
    runtime = build_runtime_server_config(server, enumeration)
    if runtime is None:
        return []
    findings = _poisoning.PoisoningAnalyzer().analyze(runtime)
    return sorted(
        {(f.id, str(f.severity)) for f in findings if f.id.startswith("POISON-")}
    )


def poison_ids(tool: ToolDef) -> list[str]:
    """Return the sorted POISON-* IDs the ``scan --connect`` path reports for *tool*."""
    return sorted({fid for fid, _ in poison_findings(tool)})


def _detected(findings: list[tuple[str, str]], high_only: bool) -> bool:
    if high_only:
        return any(sev in HIGH_OR_ABOVE for _, sev in findings)
    return bool(findings)


def _rate(hit: int, total: int) -> float | None:
    return round(hit / total, 4) if total else None


def _cell(hit: int, total: int) -> dict[str, Any]:
    return {"detected": hit, "total": total, "rate": _rate(hit, total)}


def _pct(cell: dict[str, Any]) -> str:
    total = cell.get("total") or cell.get("findings") or 0
    hit = cell.get("detected", cell.get("true_positive", 0))
    return "n/a" if not total else f"{hit * 100 / total:.1f}%"


# ── MCPTox parsing ───────────────────────────────────────────────────────────


def unescape_newlines(text: str) -> str:
    r"""Turn literal ``\n`` sequences into newlines when the text has no real ones.

    About half of MCPTox's records were stored with escaped newlines; the
    content is otherwise identical.
    """
    if "\n" not in text and "\\n" in text:
        return text.replace("\\n", "\n")
    return text


def _input_schema(arguments: str) -> dict[str, Any]:
    """Rebuild an input schema from MCPTox's ``Arguments:`` lines."""
    properties: dict[str, Any] = {}
    for line in arguments.splitlines():
        m = _ARG_LINE.match(line)
        if not m:
            continue
        name = m.group("name").strip()
        if not name or name.lower() == "no arguments":
            continue
        desc = re.sub(r"\s*\(required\)\s*$", "", m.group("desc").strip())
        properties[name] = (
            {} if desc in ("", "No description") else {"description": desc}
        )
    return {"type": "object", "properties": properties}


def split_description(body: str) -> tuple[str, dict[str, Any]]:
    """Split ``<description>\\nArguments:\\n- a: b`` into description and schema."""
    desc, _, args = body.partition("\nArguments:")
    return desc.strip(), _input_schema(args)


def parse_tool_block(text: str) -> ToolDef | None:
    """Parse ``Tool: <name>\\nDescription: <text>[\\nArguments: ...]``.

    Returns ``None`` when *text* is not that shape.
    """
    m = _TOOL_HEADER.match(unescape_newlines(text))
    if not m:
        return None
    desc, schema = split_description(m.group("rest"))
    return ToolDef(name=m.group("name").strip(), description=desc, input_schema=schema)


def wrapper_of(text: str) -> str:
    """Return which MCPTox wrapper a poisoned description carries.

    One valid case carries both; it counts as ``important`` here (the authors'
    notebook sets it aside), which changes no total.
    """
    if "<IMPORTANT>" in text:
        return "important"
    if "Ignore the previous" in text:
        return "ignore"
    return "none"


def _paradigm(raw: Any) -> str:
    code = PARADIGMS.get(str(raw))
    if code is None:
        raise BenchError(f"unknown MCPTox paradigm {raw!r}")
    return code


def _servers(response_all: dict[str, Any]) -> dict[str, Any]:
    servers = response_all.get("servers")
    if not isinstance(servers, dict) or not servers:
        raise BenchError("response_all.json has no 'servers' object")
    return servers


def benchmark_cases(
    response_all: dict[str, Any],
) -> tuple[list[tuple[str, str, ToolDef]], int]:
    """Return ``[(paradigm, wrapper, tool)]`` for valid cases, and the excluded count.

    A case is valid when ``wrong_data`` is 0; that leaves exactly the 1,312
    cases the paper states.
    """
    cases: list[tuple[str, str, ToolDef]] = []
    excluded = 0
    for sname, server in _servers(response_all).items():
        for inst in server.get("malicious_instance") or []:
            if inst.get("wrong_data"):
                excluded += 1
                continue
            text = str(inst.get("poisoned_tool") or "")
            tool = parse_tool_block(text)
            if tool is None:
                raise BenchError(f"unparseable poisoned_tool in server {sname!r}")
            paradigm = _paradigm((inst.get("metadata") or {}).get("paradigm"))
            cases.append((paradigm, wrapper_of(text), tool))
    return cases, excluded


def clean_tools(response_all: dict[str, Any]) -> list[tuple[str, ToolDef]]:
    """Return ``[(server, tool)]`` for the 45 servers' real tools (the benign side).

    Taken from each server's ``clean_system_promot`` and limited to the names
    in its ``tool_names`` (353 tools, the paper's count); one server's prompt
    lists tools beyond its ``tool_names``.
    """
    tools: list[tuple[str, ToolDef]] = []
    for sname, server in _servers(response_all).items():
        wanted = set(server.get("tool_names") or [])
        prompt = unescape_newlines(str(server.get("clean_system_promot") or ""))
        found: set[str] = set()
        for block in _TOOL_SPLIT.split(prompt):
            tool = parse_tool_block(block) if block.startswith("Tool: ") else None
            if tool is not None and tool.name in wanted and tool.name not in found:
                found.add(tool.name)
                tools.append((sname, tool))
        if found != wanted:
            missing = sorted(wanted - found)
            raise BenchError(f"server {sname!r}: clean tools not found: {missing}")
    return tools


def unwrapped_descriptions(pure_tool: list[Any]) -> list[tuple[str, ToolDef]]:
    """Return ``[(paradigm, tool)]`` for ``pure_tool.json`` (no keyword wrappers)."""
    out: list[tuple[str, ToolDef]] = []
    if not isinstance(pure_tool, list):
        raise BenchError("pure_tool.json is not a list")
    for group in pure_tool:
        for key, rec in (group or {}).items():
            content = unescape_newlines(str(rec.get("tool_content") or ""))
            desc, schema = split_description(content)
            name = str(rec.get("tool_name") or key)
            out.append((_paradigm(rec.get("paradigm")), ToolDef(name, desc, schema)))
    return out


def _recall_table(
    rows: list[tuple[str, list[tuple[str, str]]]], *, high_only: bool = False
) -> dict[str, Any]:
    """Turn ``[(paradigm, findings)]`` into per-paradigm and overall cells."""
    table: dict[str, Any] = {}
    for code in ("P1", "P2", "P3"):
        sub = [f for p, f in rows if p == code]
        table[code] = _cell(sum(_detected(f, high_only) for f in sub), len(sub))
    table["all"] = _cell(sum(_detected(f, high_only) for _, f in rows), len(rows))
    return table


def file_digests(files: dict[str, bytes]) -> dict[str, dict[str, Any]]:
    """Return ``{name: {"sha256", "bytes"}}`` for the MCPTox files."""
    return {
        name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        for name, data in sorted(files.items())
    }


def measure_recall(files: dict[str, bytes]) -> dict[str, Any]:
    """Run POISON-* over MCPTox; return the ``mcptox`` section of ``results.json``."""
    try:
        response_all = json.loads(files["response_all.json"])
        pure_tool = json.loads(files["pure_tool.json"])
    except (KeyError, ValueError) as exc:
        raise BenchError(f"MCPTox files unreadable: {exc}") from exc

    cases, excluded = benchmark_cases(response_all)
    case_rows = [(p, w, poison_findings(t)) for p, w, t in cases]
    all_rows = [(p, f) for p, _, f in case_rows]

    def by_wrapper(high_only: bool) -> dict[str, Any]:
        return {
            w: _recall_table(
                [(p, f) for p, ww, f in case_rows if ww == w], high_only=high_only
            )
            for w in WRAPPERS
        }

    detections = Counter(i for _, f in all_rows for i in {fid for fid, _ in f})

    pure_rows = [(p, poison_findings(t)) for p, t in unwrapped_descriptions(pure_tool)]
    pure_detections = Counter(i for _, f in pure_rows for i in {fid for fid, _ in f})

    benign = [(srv, poison_findings(t)) for srv, t in clean_tools(response_all)]
    benign_ids = Counter(i for _, f in benign for i in {fid for fid, _ in f})
    flagged_servers = Counter(srv for srv, f in benign if f)

    return {
        "dataset": "MCPTox (arXiv 2508.14925, AAAI 2026)",
        "source": "https://anonymous.4open.science/r/AAAI26-7C02",
        "paradigms": PARADIGM_NAMES,
        "wrappers": {
            "important": "an <IMPORTANT> block (MCPTox enhanced setting 1)",
            "ignore": "'Ignore the previous instructions' (enhanced setting 2)",
            "none": "no wrapper (the base setting)",
        },
        "files": file_digests(files),
        "patterns_fingerprint": patterns_fingerprint(),
        "detected_means": (
            "at least one POISON-* finding on the tool, any severity (what a plain "
            "scan exits 1 on)"
        ),
        "high_or_above_means": (
            "at least one HIGH or CRITICAL POISON-* finding (what check, the "
            "pre-commit default and --severity-threshold high fail on)"
        ),
        "benchmark_cases": {
            "excluded_wrong_data": excluded,
            "recall": _recall_table(all_rows),
            "recall_high_or_above": _recall_table(all_rows, high_only=True),
            "recall_by_wrapper": by_wrapper(False),
            "recall_by_wrapper_high_or_above": by_wrapper(True),
            "detections_by_id": dict(sorted(detections.items())),
        },
        "unwrapped_descriptions": {
            "recall": _recall_table(pure_rows),
            "recall_high_or_above": _recall_table(pure_rows, high_only=True),
            "detections_by_id": dict(sorted(pure_detections.items())),
        },
        "clean_tools": {
            "total": len(benign),
            "flagged": sum(_detected(f, False) for _, f in benign),
            "flagged_high_or_above": sum(_detected(f, True) for _, f in benign),
            "findings_by_id": dict(sorted(benign_ids.items())),
            "flagged_by_server": dict(sorted(flagged_servers.items())),
        },
    }


# ── fetching ─────────────────────────────────────────────────────────────────


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only when it stays on ``https://``."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        """Refuse a redirect to any non-https URL; otherwise defer to urllib."""
        if not newurl.startswith("https://"):
            raise BenchError(f"refusing redirect to non-https URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str) -> bytes:
    """GET an ``https://`` URL into memory, capped at :data:`MAX_DOWNLOAD_BYTES`."""
    if not url.startswith("https://"):
        raise BenchError(f"refusing non-https URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-audit-bench"})  # noqa: S310
    opener = urllib.request.build_opener(HttpsOnlyRedirectHandler)
    try:
        # nosec B310: https-only, redirects included; dev-only public dataset.
        with opener.open(req, timeout=FETCH_TIMEOUT_SECONDS) as resp:  # nosec B310
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        raise DatasetUnavailableError(f"{url}: {exc}") from exc
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise BenchError(f"{url}: larger than {MAX_DOWNLOAD_BYTES} bytes")
    return data


def load_mcptox(source: str) -> dict[str, bytes]:
    """Read MCPTox's two files from a local directory or an ``https://`` base URL."""
    if source.startswith(("https://", "http://")):
        base = source if source.endswith("/") else source + "/"
        return {name: _fetch(base + name) for name in MCPTOX_FILES}
    directory = Path(source).expanduser().resolve()
    if not directory.is_dir():
        raise DatasetUnavailableError(f"{directory}: not a directory")
    out: dict[str, bytes] = {}
    for name in MCPTOX_FILES:
        path = directory / name
        if not path.is_file():
            raise DatasetUnavailableError(f"{path}: missing")
        if path.stat().st_size > MAX_DOWNLOAD_BYTES:
            raise BenchError(f"{path}: larger than {MAX_DOWNLOAD_BYTES} bytes")
        out[name] = path.read_bytes()
    return out


# ── top-100 precision ────────────────────────────────────────────────────────


def _strip_matched(evidence: str) -> str:
    return evidence.strip().removeprefix("Matched: ")


def corpus_groups(summary: dict[str, Any]) -> dict[tuple[str, str], int]:
    """Return ``{(finding ID, evidence fragment): count}`` from the published summary.

    ``""`` stands for "no fragment published" (POISON-050 reports a length,
    and POISON-060's per-character counts were not published, only the set).
    """
    p = summary.get("poisoning") or {}
    by_id: dict[str, int] = dict(p.get("by_id") or {})
    groups: dict[tuple[str, str], int] = {}
    for phrase, n in (p.get("p030_evidence") or {}).items():
        groups[("POISON-030", phrase)] = int(n)
    for fid, ev in p.get("p012_p020") or []:
        key = (str(fid), _strip_matched(str(ev)))
        groups[key] = groups.get(key, 0) + 1
    accounted = Counter()
    for (fid, _), n in groups.items():
        accounted[fid] += n
    for fid, total in by_id.items():
        rest = int(total) - accounted[fid]
        if rest < 0:
            raise BenchError(f"{fid}: evidence groups exceed the published total")
        if rest:
            groups[(fid, "")] = rest
    return groups


def poison_060_characters(summary: dict[str, Any]) -> list[str]:
    """Return every character POISON-060 matched in the corpus.

    The summary keeps up to 12 distinct evidence strings; fewer than 12 means
    the list is the complete set.
    """
    sample = list((summary.get("poisoning") or {}).get("p060_evidence_sample") or [])
    if len(sample) >= 12:
        raise BenchError(
            "p060_evidence_sample may be truncated; cannot treat it as complete"
        )
    return [_strip_matched(s) for s in sample]


_LABEL_VALUES = ("true_positive", "false_positive")


def _validate_labels(labels: Any) -> list[dict[str, Any]]:
    """Return the label entries, or raise :class:`BenchError` naming what is wrong."""
    if not isinstance(labels, dict) or not isinstance(labels.get("labels"), list):
        raise BenchError("labels file has no 'labels' list")
    fp = labels.get("labelled_patterns_fingerprint")
    if not isinstance(fp, str) or not fp.startswith("sha256:"):
        raise BenchError("labels file has no 'labelled_patterns_fingerprint'")
    entries: list[dict[str, Any]] = labels["labels"]
    for i, lab in enumerate(entries):
        if not isinstance(lab, dict):
            raise BenchError(f"label {i} is not an object")
        absent = [k for k in ("id", "label", "basis") if not lab.get(k)]
        if absent:
            raise BenchError(f"label {i} ({lab.get('id')!r}) is missing {absent}")
        if lab["label"] not in _LABEL_VALUES:
            raise BenchError(
                f"label {i} ({lab['id']}): label must be true_positive or "
                "false_positive"
            )
        if not isinstance(lab.get("evidence", []), list):
            raise BenchError(f"label {i} ({lab['id']}): evidence must be a list")
    return entries


def measure_precision(
    summary: dict[str, Any], labels: dict[str, Any]
) -> dict[str, Any]:
    """Score the published top-100 poisoning findings against the hand labels.

    Raises :class:`BenchError` unless every finding in the corpus is covered
    by exactly one label.
    """
    groups = corpus_groups(summary)
    entries = _validate_labels(labels)
    covered: dict[tuple[str, str], dict[str, Any]] = {}
    for lab in entries:
        fid = str(lab["id"])
        evidence = [str(e) for e in lab.get("evidence") or []]
        # POISON-060's per-character counts were not published and POISON-050
        # has no fragment, so each is one group keyed on "".
        keys = (
            [(fid, e) for e in evidence]
            if evidence and fid != "POISON-060"
            else [(fid, "")]
        )
        for key in keys:
            if key in covered:
                raise BenchError(f"label for {key} given twice")
            covered[key] = lab
        if fid == "POISON-060" and sorted(evidence) != sorted(
            poison_060_characters(summary)
        ):
            raise BenchError(
                "POISON-060 label evidence differs from the corpus character set"
            )
    missing = sorted(set(groups) - set(covered))
    extra = sorted(set(covered) - set(groups))
    if missing or extra:
        raise BenchError(
            f"labels do not match the corpus: missing={missing} extra={extra}"
        )
    for lab in entries:
        n = sum(groups[k] for k, v in covered.items() if v is lab)
        if "count" in lab and int(lab["count"]) != n:
            raise BenchError(
                f"{lab['id']} {lab.get('evidence')}: "
                f"label says {lab['count']}, corpus has {n}"
            )

    per_id: dict[str, dict[str, Any]] = {}
    for (fid, ev), n in sorted(groups.items()):
        label = covered[(fid, ev)]["label"]
        cell = per_id.setdefault(
            fid, {"findings": 0, "true_positive": 0, "false_positive": 0}
        )
        cell["findings"] += n
        cell[label] += n
    for cell in per_id.values():
        cell["precision"] = _rate(cell["true_positive"], cell["findings"])
    tp = sum(c["true_positive"] for c in per_id.values())
    total = sum(c["findings"] for c in per_id.values())
    basis = Counter()
    for (fid, ev), n in groups.items():
        basis[covered[(fid, ev)]["basis"]] += n
    tools_total = int((summary.get("tools") or {}).get("total") or 0)
    severity = dict((summary.get("poisoning") or {}).get("by_id_sev") or {})
    for fid, cell in per_id.items():
        cell["severity"] = severity.get(fid)
    high = [c for c in per_id.values() if c["severity"] in HIGH_OR_ABOVE]
    high_total = sum(c["findings"] for c in high)
    high_tp = sum(c["true_positive"] for c in high)
    return {
        "corpus": "docs/research/2026-10-top100-npm/summary.json",
        "labels": "docs/research/poisoning-benchmark/top100-labels.json",
        "scanner_version": labels.get("scanner_version"),
        "labelled_patterns_fingerprint": labels["labelled_patterns_fingerprint"],
        "findings": total,
        "true_positive": tp,
        "false_positive": total - tp,
        "precision": _rate(tp, total),
        "findings_high_or_above": high_total,
        "true_positive_high_or_above": high_tp,
        "precision_high_or_above": _rate(high_tp, high_total),
        "tools_scanned": tools_total,
        "findings_per_100_tools": round(total * 100 / tools_total, 1)
        if tools_total
        else None,
        "label_basis": dict(sorted(basis.items())),
        "by_id": per_id,
    }


def replay_evidence(summary: dict[str, Any]) -> dict[str, Any]:
    """Run the current analyzer over every evidence fragment the corpus publishes.

    Returns which POISON-* IDs fire on each fragment, and how many of the
    corpus's findings the current code still reproduces from the committed
    text alone (a fragment lacks its surrounding description, so a pattern
    that needs nearby context, such as POISON-020, cannot reproduce).
    """
    groups = corpus_groups(summary)
    fragments: list[dict[str, Any]] = []
    reproduced = 0
    for fid, ev in sorted(groups):
        texts = (
            poison_060_characters(summary) if fid == "POISON-060" and not ev else [ev]
        )
        texts = [t for t in texts if t]
        rows = [{"text": t, "fires": poison_ids(ToolDef("replay", t))} for t in texts]
        if rows and all(fid in r["fires"] for r in rows):
            reproduced += groups[(fid, ev)]
        fragments.append({"id": fid, "count": groups[(fid, ev)], "fragments": rows})
    return {
        "patterns_fingerprint": patterns_fingerprint(),
        "findings_reproduced_from_committed_text": reproduced,
        "groups": fragments,
    }


# ── comparison ───────────────────────────────────────────────────────────────


def _cells(section: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Flatten every recall cell in an ``mcptox`` section to ``{path: cell}``."""
    out: dict[str, dict[str, Any]] = {}
    bench = section.get("benchmark_cases") or {}
    pure = section.get("unwrapped_descriptions") or {}
    for suffix in ("", "_high_or_above"):
        for code, cell in (bench.get("recall" + suffix) or {}).items():
            out[f"benchmark_cases{suffix}/{code}"] = cell
        for wrapper, table in (bench.get("recall_by_wrapper" + suffix) or {}).items():
            for code, cell in table.items():
                out[f"benchmark_cases{suffix}/{wrapper}/{code}"] = cell
        for code, cell in (pure.get("recall" + suffix) or {}).items():
            out[f"unwrapped_descriptions{suffix}/{code}"] = cell
    return out


def compare_recall(
    pinned: dict[str, Any], fresh: dict[str, Any]
) -> tuple[list[str], list[str]]:
    """Return ``(regressions, improvements)`` between two ``mcptox`` sections.

    Raises :class:`DatasetUnavailableError` when the dataset files differ from the
    pinned hashes (the numbers would not be comparable).
    """
    if (pinned.get("files") or {}) != (fresh.get("files") or {}):
        raise DatasetUnavailableError(
            "MCPTox files differ from the pinned SHA-256 values"
        )
    regressions: list[str] = []
    improvements: list[str] = []
    old, new = _cells(pinned), _cells(fresh)
    for path in sorted(set(old) | set(new)):
        a, b = old.get(path), new.get(path)
        if a is None or b is None or a["total"] != b["total"]:
            regressions.append(f"{path}: case set changed ({a} -> {b})")
        elif b["detected"] < a["detected"]:
            regressions.append(f"{path}: detected {a['detected']} -> {b['detected']}")
        elif b["detected"] > a["detected"]:
            improvements.append(f"{path}: detected {a['detected']} -> {b['detected']}")
    for key in ("flagged", "flagged_high_or_above"):
        fa = (pinned.get("clean_tools") or {}).get(key, 0)
        fb = (fresh.get("clean_tools") or {}).get(key, 0)
        if fb > fa:
            regressions.append(f"clean_tools: {key} {fa} -> {fb}")
        elif fb < fa:
            improvements.append(f"clean_tools: {key} {fa} -> {fb}")
    return regressions, improvements


def compare_precision(
    pinned: dict[str, Any], fresh: dict[str, Any]
) -> tuple[list[str], list[str]]:
    """Return ``(regressions, improvements)`` between two ``top100`` sections.

    A regression is a new POISON-* ID firing on a committed fragment, or a
    change in the labelled precision; a pattern that stops firing on a
    known-benign fragment is an improvement.
    """
    regressions: list[str] = []
    improvements: list[str] = []
    if pinned.get("precision") != fresh.get("precision"):
        regressions.append(
            f"labelled precision {pinned.get('precision')} -> "
            f"{fresh.get('precision')}; re-pin with --write"
        )
    old = {
        (g["id"], r["text"]): set(r["fires"])
        for g in (pinned.get("replay") or {}).get("groups", [])
        for r in g["fragments"]
    }
    new = {
        (g["id"], r["text"]): set(r["fires"])
        for g in (fresh.get("replay") or {}).get("groups", [])
        for r in g["fragments"]
    }
    for key in sorted(set(old) | set(new)):
        a, b = old.get(key, set()), new.get(key, set())
        if b - a:
            regressions.append(f"{key}: now also fires {sorted(b - a)}")
        if a - b:
            improvements.append(f"{key}: no longer fires {sorted(a - b)}")
    return regressions, improvements


# ── CLI ──────────────────────────────────────────────────────────────────────


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BenchError(f"{path}: {exc}") from exc


def _write_section(path: Path, key: str, section: dict[str, Any]) -> None:
    data = _read_json(path) if path.exists() else {}
    data[key] = section
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _print_recall(section: dict[str, Any]) -> None:
    bench = section["benchmark_cases"]
    print(f"benchmark cases (excluded wrong_data: {bench['excluded_wrong_data']})")
    for suffix, label in (("", "any severity"), ("_high_or_above", "HIGH or above")):
        print(f"  recall, {label}:  all | important | ignore | none")
        for code in ("P1", "P2", "P3", "all"):
            cells = [bench["recall" + suffix][code]] + [
                bench["recall_by_wrapper" + suffix][w][code] for w in WRAPPERS
            ]
            shown = "  ".join(f"{c['detected']}/{c['total']} {_pct(c)}" for c in cells)
            print(f"    {code:<3} {shown}")
    pure = section["unwrapped_descriptions"]
    for code in ("P1", "P2", "P3", "all"):
        a, h = pure["recall"][code], pure["recall_high_or_above"][code]
        print(
            f"  unwrapped {code:<3} {a['detected']}/{a['total']} {_pct(a)}"
            f"   HIGH+ {h['detected']}/{h['total']} {_pct(h)}"
        )
    clean = section["clean_tools"]
    print(
        "clean-tool flag rate (the precision check that re-runs after a change): "
        f"{clean['flagged']}/{clean['total']} any severity, "
        f"{clean['flagged_high_or_above']}/{clean['total']} HIGH+ "
        f"{clean['findings_by_id']}"
    )


def _print_precision(section: dict[str, Any]) -> None:
    print(
        f"top-100 npm (fixed measurement, {section['scanner_version']}): "
        f"{section['true_positive']}/{section['findings']} real "
        f"(precision {_pct(section)}), basis {section['label_basis']}"
    )
    print(
        f"  HIGH or above: {section['true_positive_high_or_above']}/"
        f"{section['findings_high_or_above']} real"
    )
    for fid, cell in section["by_id"].items():
        print(
            f"  {fid} ({cell['severity']}): {cell['true_positive']}/{cell['findings']}"
        )
    replay = section["replay"]
    print(
        "committed-fragment replay with the current code (re-runs after a change): "
        f"{replay['findings_reproduced_from_committed_text']} of "
        f"{section['findings']} findings reproduce"
    )
    if section["labelled_patterns_fingerprint"] != replay["patterns_fingerprint"]:
        print(
            "STALE: the top-100 labels describe different POISON-* code "
            f"(labelled {section['labelled_patterns_fingerprint']}, current "
            f"{replay['patterns_fingerprint']}). The 0-of-661 precision is a "
            "fixed measurement of the old code; re-measuring it needs a fresh "
            "enumeration of the corpus (runs third-party servers, never in CI). "
            "The precision checks that do re-run: this replay and the MCPTox "
            "clean-tool flag rate (`recall --check`)."
        )


def _finish(regressions: list[str], improvements: list[str], what: str) -> int:
    for line in improvements:
        print(f"improved: {line}")
    if improvements:
        print(
            f"{what} improved: re-run with --write, then update "
            "docs/poisoning.md and GAPS.md."
        )
    for line in regressions:
        print(f"REGRESSION: {line}", file=sys.stderr)
    return 1 if regressions else 0


def _write_unless_regressed(status: int, path: Path, key: str, data: Any) -> None:
    if status:
        print(f"not writing {path}: --check found a regression", file=sys.stderr)
        return
    _write_section(path, key, data)


def run_precision(args: argparse.Namespace) -> int:
    """``precision`` subcommand."""
    section = measure_precision(_read_json(args.summary), _read_json(args.labels))
    section["replay"] = replay_evidence(_read_json(args.summary))
    _print_precision(section)
    status = 0
    if args.check:
        pinned = (_read_json(args.results).get("top100")) or {}
        status = _finish(*compare_precision(pinned, section), "precision")
    if args.write:
        _write_unless_regressed(status, args.results, "top100", section)
    return status


def run_recall(args: argparse.Namespace) -> int:
    """``recall`` subcommand."""
    results = _read_json(args.results) if args.results.exists() else {}
    pinned = results.get("mcptox") or {}
    if args.check and not pinned:
        raise BenchError(f"{args.results}: no 'mcptox' section to check against")
    files = load_mcptox(args.source)
    # Hash before parsing, always: a host that answers with an error page must
    # read as "not the pinned dataset", not as a malformed one.
    digests = file_digests(files)
    for name, d in digests.items():
        print(f"{name}: sha256 {d['sha256']} ({d['bytes']} bytes)")
    if pinned:
        same = digests == (pinned.get("files") or {})
        print(
            "hashes match the pinned results"
            if same
            else f"hashes DIFFER from {args.results} (pinned {pinned.get('files')})"
        )
        if args.check and not same:
            raise DatasetUnavailableError(
                "MCPTox files differ from the pinned SHA-256 values"
            )
    section = measure_recall(files)
    _print_recall(section)
    status = 0
    if args.check:
        status = _finish(*compare_recall(pinned, section), "recall")
    if args.write:
        _write_unless_regressed(status, args.results, "mcptox", section)
    return status


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("precision", "recall"):
        p = sub.add_parser(name)
        p.add_argument("--results", type=Path, default=RESULTS_PATH)
        p.add_argument("--check", action="store_true", help="exit 1 on a regression")
        p.add_argument("--write", action="store_true", help="record into --results")
    sub.choices["precision"].add_argument("--summary", type=Path, default=SUMMARY_PATH)
    sub.choices["precision"].add_argument("--labels", type=Path, default=LABELS_PATH)
    sub.choices["recall"].add_argument("--source", default=MCPTOX_DEFAULT_SOURCE)
    args = parser.parse_args(argv)
    try:
        return run_precision(args) if args.command == "precision" else run_recall(args)
    except BenchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
