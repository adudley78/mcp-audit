"""Snapshot output formatters: CycloneDX AI/ML-BOM and native JSON.

Produces the two output shapes for ``mcp-audit snapshot``:

- :func:`format_cyclonedx_aibom` — CycloneDX 1.5 JSON with mcp-audit-specific
  ``properties`` blocks, ``components`` per server, and ``vulnerabilities``
  per finding.  Validates against the official CycloneDX JSON schema.
- :func:`format_native` — flatter mcp-audit-native JSON wrapping the existing
  :class:`~mcp_audit.models.ScanResult` serialisation with snapshot metadata.
- :func:`sign_snapshot` — sigstore-sign a snapshot file, producing a ``.sig``
  bundle alongside it.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_audit import __version__
from mcp_audit.models import ScanResult

# ── CycloneDX helpers ──────────────────────────────────────────────────────────


def _cyclonedx_timestamp(dt: datetime) -> str:
    """Format *dt* as an ISO 8601 UTC timestamp for CycloneDX metadata.

    Args:
        dt: A :class:`~datetime.datetime` instance (timezone-aware preferred).

    Returns:
        String like ``"2026-05-03T12:34:56Z"``.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _severity_to_cyclonedx(severity: str) -> str:
    """Map mcp-audit Severity strings to CycloneDX vulnerability severity labels.

    Args:
        severity: One of ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, ``INFO``.

    Returns:
        Lowercase CycloneDX severity string.
    """
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
    }
    return mapping.get(severity.upper(), "unknown")


def _cwe_int(cwe: str | None) -> int | None:
    """Parse a CWE identifier string (e.g. ``"CWE-312"``) into an integer.

    Args:
        cwe: CWE string like ``"CWE-312"`` or ``"312"``, or ``None``.

    Returns:
        Integer CWE number, or ``None`` if *cwe* is absent or unparseable.
    """
    if not cwe:
        return None
    stripped = cwe.upper().replace("CWE-", "")
    try:
        return int(stripped)
    except ValueError:
        return None


def _extract_capability_tags(server_name: str, result: ScanResult) -> list[str]:
    """Best-effort extraction of capability tags for *server_name*.

    Looks for the server in the attack-path summary (``paths_broken_by`` and
    individual path hops) to infer capabilities from source/sink info.  Falls
    back to an empty list when the summary is absent.

    Args:
        server_name: MCP server name.
        result: Full :class:`~mcp_audit.models.ScanResult`.

    Returns:
        List of capability tag strings (may be empty).
    """
    if result.attack_path_summary is None:
        return []
    tags: set[str] = set()
    for path in result.attack_path_summary.paths:
        if server_name in path.hops:
            idx = path.hops.index(server_name)
            if idx == 0:
                tags.add(path.source_capability)
            if idx == len(path.hops) - 1:
                tags.add(path.sink_capability)
    return sorted(tags)


def _owasp_categories_from_result(result: ScanResult) -> str:
    """Collect all OWASP MCP Top 10 codes that fired in *result*, comma-separated.

    Args:
        result: Full :class:`~mcp_audit.models.ScanResult`.

    Returns:
        Sorted, comma-separated codes (e.g. ``"MCP01,MCP03,MCP09"``), or
        empty string if no mappings exist.
    """
    codes: set[str] = set()
    for finding in result.findings:
        codes.update(finding.owasp_mcp_top_10)
    return ",".join(sorted(codes))


def format_cyclonedx_aibom(
    result: ScanResult,
    host_id: str,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 AI/ML-BOM JSON document from *result*.

    Every MCP server becomes a CycloneDX ``component`` of ``type: application``
    with mcp-audit-specific ``properties`` blocks.  Every finding becomes a
    ``vulnerability`` entry with ratings, CWE, and a properties block carrying
    the OWASP MCP Top 10 mapping.

    Args:
        result: Completed :class:`~mcp_audit.models.ScanResult`.
        host_id: Hostname or asset identifier for ``mcp-audit:host_id`` property.

    Returns:
        A :class:`dict` ready for ``json.dumps``.
    """
    now = _cyclonedx_timestamp(result.timestamp)
    bom_ref_map: dict[str, str] = {}  # server_name → bom-ref

    # ── Components ────────────────────────────────────────────────────────────
    components: list[dict[str, Any]] = []
    for server in result.servers:
        ref = f"mcp-server-{server.name}"
        bom_ref_map[server.name] = ref
        capability_tags = _extract_capability_tags(server.name, result)
        server_findings = [f.id for f in result.findings if f.server == server.name]
        cmd_display = server.command or ""
        if server.args:
            cmd_display = " ".join([cmd_display] + server.args[:4])

        comp: dict[str, Any] = {
            "type": "application",
            "bom-ref": ref,
            "name": server.name,
            "description": f"MCP server: {cmd_display}".strip(),
            "properties": [
                {
                    "name": "mcp-audit:capability_tags",
                    "value": ",".join(capability_tags) if capability_tags else "",
                },
                {
                    "name": "mcp-audit:transport",
                    "value": server.transport.value,
                },
                {
                    "name": "mcp-audit:client",
                    "value": server.client,
                },
                {
                    "name": "mcp-audit:finding_ids",
                    "value": ",".join(server_findings),
                },
            ],
        }
        if server.command:
            comp["properties"].append(
                {"name": "mcp-audit:command", "value": cmd_display}
            )
        if server.url:
            comp["properties"].append({"name": "mcp-audit:url", "value": server.url})
        components.append(comp)

    # ── Vulnerabilities ───────────────────────────────────────────────────────
    vulnerabilities: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for finding in result.findings:
        # Deduplicate by (id, server) — same finding can appear for multiple
        # servers in a fleet merge, but snapshot is per-host so (id, server) is
        # the right key.
        dedup_key = f"{finding.id}::{finding.server}"
        if dedup_key in seen_ids:
            continue
        seen_ids.add(dedup_key)

        affects_ref = bom_ref_map.get(finding.server, f"mcp-server-{finding.server}")
        vuln_props: list[dict[str, str]] = [
            {
                "name": "mcp-audit:analyzer",
                "value": finding.analyzer,
            },
            {
                "name": "mcp-audit:evidence",
                "value": finding.evidence,
            },
        ]
        if finding.owasp_mcp_top_10:
            vuln_props.append(
                {
                    "name": "mcp-audit:owasp_mcp_top_10",
                    "value": ",".join(finding.owasp_mcp_top_10),
                }
            )
        if finding.cve:
            vuln_props.append(
                {
                    "name": "mcp-audit:cve",
                    "value": ",".join(finding.cve),
                }
            )

        vuln: dict[str, Any] = {
            "bom-ref": f"finding-{finding.id}-{finding.server}",
            "id": finding.id,
            "source": {
                "name": "mcp-audit",
                "url": "https://github.com/adudley78/mcp-audit",
            },
            "ratings": [
                {
                    "source": {"name": "mcp-audit"},
                    "severity": _severity_to_cyclonedx(finding.severity),
                    "method": "other",
                }
            ],
            "description": finding.title,
            "detail": finding.description,
            "recommendation": finding.remediation,
            "affects": [{"ref": affects_ref}],
            "properties": vuln_props,
        }

        cwe_num = _cwe_int(finding.cwe)
        if cwe_num is not None:
            vuln["cwes"] = [cwe_num]

        vulnerabilities.append(vuln)

    # ── Attack path summary as component ──────────────────────────────────────
    # Embed a synthetic "attack-surface" component that captures the summary.
    if result.attack_path_summary and result.attack_path_summary.paths:
        aps = result.attack_path_summary
        attack_comp: dict[str, Any] = {
            "type": "data",
            "bom-ref": "mcp-attack-surface",
            "name": "mcp-attack-surface",
            "description": (
                f"MCP attack-path summary: {len(aps.paths)} path(s), "
                f"hitting-set: {', '.join(aps.hitting_set) or 'none'}"
            ),
            "properties": [
                {
                    "name": "mcp-audit:attack_path_count",
                    "value": str(len(aps.paths)),
                },
                {
                    "name": "mcp-audit:hitting_set",
                    "value": ",".join(aps.hitting_set),
                },
            ],
        }
        for ap in aps.paths:
            attack_comp["properties"].append(
                {
                    "name": f"mcp-audit:attack_path:{ap.id}",
                    "value": " → ".join(ap.hops),
                }
            )
        components.append(attack_comp)

    # ── Metadata ──────────────────────────────────────────────────────────────
    owasp_codes = _owasp_categories_from_result(result)
    meta_props: list[dict[str, str]] = [
        {"name": "mcp-audit:host_id", "value": host_id},
    ]
    if result.score is not None:
        meta_props.extend(
            [
                {"name": "mcp-audit:scan_grade", "value": result.score.grade},
                {
                    "name": "mcp-audit:scan_numeric_score",
                    "value": str(result.score.numeric_score),
                },
            ]
        )
    meta_props.append(
        {"name": "mcp-audit:owasp_mcp_top_10_categories", "value": owasp_codes}
    )
    meta_props.append(
        {"name": "mcp-audit:finding_count", "value": str(len(result.findings))}
    )
    meta_props.append(
        {"name": "mcp-audit:server_count", "value": str(len(result.servers))}
    )

    tools_block: list[dict[str, Any]] = [
        {
            "vendor": "mcp-audit",
            "name": "mcp-audit",
            "version": __version__,
            "externalReferences": [
                {
                    "type": "website",
                    "url": "https://github.com/adudley78/mcp-audit",
                }
            ],
        }
    ]

    metadata: dict[str, Any] = {
        "timestamp": now,
        "tools": tools_block,
        "properties": meta_props,
    }

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def format_native(
    result: ScanResult,
    host_id: str,
) -> dict[str, Any]:
    """Build a flatter mcp-audit-native snapshot JSON document.

    Wraps the existing :class:`~mcp_audit.models.ScanResult` serialisation with
    additional snapshot metadata so the shape is consistent with the CycloneDX
    output's metadata block.

    Args:
        result: Completed :class:`~mcp_audit.models.ScanResult`.
        host_id: Hostname or asset identifier.

    Returns:
        A :class:`dict` ready for ``json.dumps``.
    """
    now = _cyclonedx_timestamp(result.timestamp)
    owasp_codes = _owasp_categories_from_result(result)

    metadata: dict[str, Any] = {
        "timestamp": now,
        "tools": [
            {
                "name": "mcp-audit",
                "version": __version__,
            }
        ],
        "properties": [
            {"name": "mcp-audit:host_id", "value": host_id},
            {
                "name": "mcp-audit:scan_grade",
                "value": result.score.grade if result.score else "",
            },
            {
                "name": "mcp-audit:scan_numeric_score",
                "value": str(result.score.numeric_score) if result.score else "",
            },
            {
                "name": "mcp-audit:owasp_mcp_top_10_categories",
                "value": owasp_codes,
            },
            {
                "name": "mcp-audit:finding_count",
                "value": str(len(result.findings)),
            },
            {
                "name": "mcp-audit:server_count",
                "value": str(len(result.servers)),
            },
        ],
    }

    return {
        "format": "mcp-audit-native",
        "format_version": "1",
        "metadata": metadata,
        "snapshot_data": json.loads(result.model_dump_json(by_alias=True)),
    }


def format_stream_lines(result: ScanResult) -> list[str]:
    """Serialise each finding in *result* as a single-line JSON string.

    Suitable for piping into ``vector``, a Splunk HEC forwarder, or any
    SIEM ingestor that expects newline-delimited JSON.

    Each line is a self-contained JSON object with at minimum: ``id``,
    ``severity``, ``analyzer``, ``server``, ``title``, ``description``,
    ``evidence``, ``remediation``, and ``owasp_mcp_top_10``.

    Args:
        result: Completed :class:`~mcp_audit.models.ScanResult`.

    Returns:
        List of JSON strings (one per finding), each without a trailing newline.
    """
    lines: list[str] = []
    ts = _cyclonedx_timestamp(result.timestamp)
    host_id = result.machine.hostname if result.machine else "unknown"
    for finding in result.findings:
        record: dict[str, Any] = {
            "timestamp": ts,
            "host_id": host_id,
            "mcp_audit_version": result.version,
            **finding.model_dump(),
        }
        lines.append(json.dumps(record, default=str))
    return lines


# ── Sigstore signing ───────────────────────────────────────────────────────────


def sign_snapshot(path: Path) -> Path:
    """Sign the snapshot at *path* using sigstore ambient OIDC identity.

    Produces a ``<snapshot>.sig`` file alongside *path* containing the
    sigstore bundle JSON.  The unsigned snapshot at *path* is **not** modified.

    Signing requires:
    - The ``sigstore`` library (``pip install 'mcp-audit-scanner[attestation]'``).
    - An ambient OIDC credential (GitHub Actions ``id-token``, Google Cloud
      Workload Identity, or an interactive browser flow).

    If signing succeeds, the ``.sig`` file is a valid sigstore bundle that can
    be verified with ``sigstore verify artifact --bundle <path>.sig <path>``.

    Args:
        path: Path to the snapshot JSON file to sign.

    Returns:
        Path to the newly created ``.sig`` file (``path`` with ``.sig`` appended).

    Raises:
        ImportError: If the ``sigstore`` optional dependency is not installed.
        RuntimeError: If signing fails for any reason (no ambient credential,
            network error, Rekor timeout, etc.).  The unsigned snapshot is still
            present at *path*.
    """
    try:
        from sigstore.oidc import detect_credential  # noqa: PLC0415
        from sigstore.sign import Signer  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "sigstore is not installed. "
            "Enable signing with: pip install 'mcp-audit-scanner[attestation]'"
        ) from exc

    sig_path = Path(str(path) + ".sig")
    data = path.read_bytes()

    # Compute SHA-256 for integrity reference (embedded in the sig file header).
    sha256 = hashlib.sha256(data).hexdigest()

    try:
        identity = detect_credential(audience="sigstore")
    except Exception as exc:
        raise RuntimeError(
            f"No ambient OIDC credential available for sigstore signing: {exc}\n"
            "In CI set id-token: write permission; locally use "
            "'sigstore sign' CLI for interactive browser flow."
        ) from exc

    try:
        with Signer.production(identity=identity) as signer:
            result = signer.sign_artifact(input_=data)
        bundle = result.to_bundle()
        bundle_json = bundle.to_json()
    except Exception as exc:
        raise RuntimeError(f"sigstore signing failed: {exc}") from exc

    # Write a JSON wrapper: bundle + sha256 for belt-and-suspenders verification.
    sig_doc = {
        "sha256": sha256,
        "bundle": json.loads(bundle_json),
    }
    sig_path.write_text(json.dumps(sig_doc, indent=2), encoding="utf-8")
    return sig_path


def sha256_snapshot(path: Path) -> str:
    """Compute the SHA-256 hex digest of the snapshot file at *path*.

    Used when sigstore is unavailable to provide at least a content fingerprint.

    Args:
        path: Path to the snapshot JSON file.

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()
