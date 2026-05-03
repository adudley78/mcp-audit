"""Rehydrate a historical snapshot into a live attack-path graph.

Given an old ``mcp-audit snapshot`` JSON file, reconstruct the
:class:`~mcp_audit.models.AttackPathSummary` as it was at the snapshot
timestamp — bypassing live config discovery entirely.

This lets incident responders answer "what attack paths were possible at
the time the alert fired?" even after the developer has changed or deleted
their MCP configs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_audit.analyzers.attack_paths import summarize_attack_paths
from mcp_audit.models import (
    Finding,
    MachineInfo,
    ScanResult,
    ScanScore,
    Severity,
    TransportType,
)


@dataclass
class RehydratedSnapshot:
    """Result of rehydrating a historical snapshot.

    Attributes:
        snapshot_timestamp: ISO 8601 timestamp recorded in the snapshot.
        host_id: Hostname recorded in the snapshot.
        version: mcp-audit version that produced the snapshot.
        result: Reconstructed :class:`~mcp_audit.models.ScanResult` with the
            attack-path graph as it was at snapshot time.
    """

    snapshot_timestamp: str
    host_id: str
    version: str
    result: ScanResult


# ── Schema helpers ─────────────────────────────────────────────────────────────


def _require(data: dict[str, Any], key: str, context: str = "") -> Any:
    """Extract a required key from *data* or raise with a useful message.

    Args:
        data: Dictionary to extract from.
        key: Key to look up.
        context: Optional human-readable label for the dict (for error messages).

    Returns:
        The value at *key*.

    Raises:
        ValueError: If *key* is absent or ``None``.
    """
    val = data.get(key)
    if val is None:
        prefix = f"{context}: " if context else ""
        raise ValueError(f"{prefix}required field '{key}' is missing or null")
    return val


def _parse_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    """Validate and extract snapshot metadata block.

    Args:
        raw: Top-level snapshot dict.

    Returns:
        The ``metadata`` sub-dict.

    Raises:
        ValueError: If ``metadata`` or its required fields are absent.
    """
    meta = _require(raw, "metadata", "snapshot")
    if not isinstance(meta, dict):
        raise ValueError("snapshot: 'metadata' must be an object")
    _require(meta, "timestamp", "metadata")
    return meta  # type: ignore[return-value]


# ── Reconstruction helpers ─────────────────────────────────────────────────────


def _servers_from_cyclonedx(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract server records from a CycloneDX snapshot.

    Args:
        raw: Top-level CycloneDX snapshot dict.

    Returns:
        List of server property dicts (name + capability tags) suitable for
        passing to :func:`_rebuild_scan_result`.
    """
    components = raw.get("components") or []
    servers: list[dict[str, Any]] = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name", "unknown")
        props: dict[str, str] = {}
        for prop in comp.get("properties") or []:
            if isinstance(prop, dict) and "name" in prop and "value" in prop:
                props[prop["name"]] = str(prop["value"])
        servers.append(
            {
                "name": name,
                "capability_tags": props.get("mcp-audit:capability_tags", ""),
                "transport": props.get("mcp-audit:transport", "unknown"),
                "client": props.get("mcp-audit:client", "unknown"),
                "command": props.get("mcp-audit:command"),
            }
        )
    return servers


def _servers_from_native(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract server records from a native-format snapshot.

    Args:
        raw: Top-level native snapshot dict (``snapshot_data`` sub-key holds
            a serialised :class:`~mcp_audit.models.ScanResult`).

    Returns:
        List of server dicts extracted from the embedded ``servers`` list.
    """
    scan_data = raw.get("snapshot_data") or {}
    servers_raw = scan_data.get("servers") or []
    servers: list[dict[str, Any]] = []
    for s in servers_raw:
        if isinstance(s, dict):
            servers.append(s)
    return servers


def _detect_format(raw: dict[str, Any]) -> str:
    """Detect whether *raw* is a CycloneDX or native snapshot.

    Args:
        raw: Top-level snapshot dict.

    Returns:
        ``"cyclonedx"`` or ``"native"``.
    """
    if raw.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "snapshot_data" in raw:
        return "native"
    # Heuristic: CycloneDX always has a ``components`` key.
    if "components" in raw:
        return "cyclonedx"
    return "native"


def _rebuild_scan_result(
    server_records: list[dict[str, Any]],
    findings_raw: list[dict[str, Any]],
    meta: dict[str, Any],
) -> ScanResult:
    """Reconstruct a :class:`~mcp_audit.models.ScanResult` from raw records.

    Rebuilds the attack-path graph by calling
    :func:`~mcp_audit.analyzers.attack_paths.summarize_attack_paths` against
    the reconstructed server list.  Does **not** re-run live discovery or any
    other analyzer.

    Args:
        server_records: List of server dicts from the snapshot.
        findings_raw: List of finding dicts from the snapshot.
        meta: ``metadata`` sub-dict from the snapshot.

    Returns:
        A :class:`~mcp_audit.models.ScanResult` with the reconstructed graph.
    """
    from mcp_audit.models import ServerConfig  # noqa: PLC0415

    # Reconstruct ServerConfig objects
    servers: list[ServerConfig] = []
    for rec in server_records:
        name = rec.get("name") or "unknown"
        transport_raw = rec.get("transport") or "unknown"
        try:
            transport = TransportType(transport_raw)
        except ValueError:
            transport = TransportType.UNKNOWN
        servers.append(
            ServerConfig(
                name=name,
                client=rec.get("client") or "unknown",
                config_path=Path("/rehydrated"),
                transport=transport,
                command=rec.get("command"),
                args=rec.get("args") or [],
                env={},
                raw=rec,
            )
        )

    # Reconstruct Finding objects
    findings: list[Finding] = []
    for fd in findings_raw:
        if not isinstance(fd, dict):
            continue
        try:
            findings.append(Finding.model_validate(fd))
        except Exception:  # noqa: BLE001, S112
            continue

    # Extract props for score
    props: dict[str, str] = {}
    for prop in meta.get("properties") or []:
        if isinstance(prop, dict) and "name" in prop and "value" in prop:
            props[prop["name"]] = str(prop["value"])

    score: ScanScore | None = None
    grade = props.get("mcp-audit:scan_grade", "")
    numeric_raw = props.get("mcp-audit:scan_numeric_score", "")
    if grade and numeric_raw.isdigit():
        score = ScanScore(
            numeric_score=int(numeric_raw),
            grade=grade,
            positive_signals=[],
            deductions=[],
        )

    # Reconstruct machine info
    machine = MachineInfo(
        hostname=props.get("mcp-audit:host_id", "unknown"),
        username="rehydrated",
        os="unknown",
        os_version="unknown",
        scan_id="00000000-0000-0000-0000-000000000000",
    )

    # Rebuild attack paths from reconstructed servers + findings
    attack_path_summary = summarize_attack_paths(servers, findings)

    return ScanResult(
        version=meta.get("mcp-audit:version") or "unknown",
        servers=servers,
        findings=findings,
        attack_path_summary=attack_path_summary,
        score=score,
        machine=machine,
    )


# ── Public API ─────────────────────────────────────────────────────────────────


def load_snapshot(path: Path) -> dict[str, Any]:
    """Parse and lightly validate a snapshot JSON file.

    Args:
        path: Path to the snapshot ``.json`` file.

    Returns:
        The parsed snapshot dict.

    Raises:
        ValueError: If the file is missing, corrupt, or fails schema validation.
    """
    resolved = path.resolve()
    if not resolved.exists():
        raise ValueError(f"Snapshot file not found: {path}")
    try:
        raw: dict[str, Any] = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot parse snapshot JSON from {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"Snapshot at {path} is not a JSON object")
    _parse_metadata(raw)  # validates metadata block
    return raw


def rehydrate(path: Path) -> RehydratedSnapshot:
    """Reconstruct the attack-path graph from a historical snapshot.

    Reads the snapshot at *path*, rebuilds :class:`~mcp_audit.models.ServerConfig`
    objects and :class:`~mcp_audit.models.Finding` objects from the recorded
    data, then calls :func:`~mcp_audit.analyzers.attack_paths.summarize_attack_paths`
    to regenerate the graph — exactly as it would have appeared at snapshot time.

    Args:
        path: Path to the saved ``.snapshot.json`` file.

    Returns:
        :class:`RehydratedSnapshot` with the reconstructed graph and metadata.

    Raises:
        ValueError: If the snapshot is corrupt or missing required fields.
    """
    raw = load_snapshot(path)
    fmt = _detect_format(raw)
    meta = _parse_metadata(raw)

    if fmt == "cyclonedx":
        server_records = _servers_from_cyclonedx(raw)
        findings_raw: list[dict[str, Any]] = []
        for vuln in raw.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_props: dict[str, str] = {}
            for p in vuln.get("properties") or []:
                if isinstance(p, dict):
                    vuln_props[p.get("name", "")] = str(p.get("value", ""))
            ratings = vuln.get("ratings") or [{}]
            severity_str = (ratings[0].get("severity") or "info").upper()
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.INFO
            affects = vuln.get("affects") or [{}]
            server_name = (affects[0].get("ref") or "").replace("mcp-server-", "")
            findings_raw.append(
                {
                    "id": vuln.get("id") or "UNKNOWN",
                    "severity": severity,
                    "analyzer": vuln_props.get("mcp-audit:analyzer", "unknown"),
                    "client": "rehydrated",
                    "server": server_name,
                    "title": vuln.get("description") or "",
                    "description": vuln.get("description") or "",
                    "evidence": vuln_props.get("mcp-audit:evidence", ""),
                    "remediation": vuln.get("recommendation") or "",
                    "owasp_mcp_top_10": [
                        c.strip()
                        for c in vuln_props.get("mcp-audit:owasp_mcp_top_10", "").split(
                            ","
                        )
                        if c.strip()
                    ],
                }
            )
    else:
        scan_data = raw.get("snapshot_data") or {}
        server_records = _servers_from_native(raw)
        findings_raw = scan_data.get("findings") or []

    result = _rebuild_scan_result(server_records, findings_raw, meta)

    # Resolve timestamp
    ts_raw = meta.get("timestamp") or ""
    timestamp_str = ts_raw if isinstance(ts_raw, str) else str(ts_raw)

    # Resolve host_id
    props: dict[str, str] = {}
    for prop in meta.get("properties") or []:
        if isinstance(prop, dict) and "name" in prop and "value" in prop:
            props[prop["name"]] = str(prop["value"])
    host_id = props.get("mcp-audit:host_id", "unknown")

    # Version from metadata.tools array or top-level
    version_str = "unknown"
    for tool in meta.get("tools") or []:
        if isinstance(tool, dict) and tool.get("name") == "mcp-audit":
            version_str = tool.get("version") or "unknown"
            break

    return RehydratedSnapshot(
        snapshot_timestamp=timestamp_str,
        host_id=host_id,
        version=version_str,
        result=result,
    )
