"""Scanner orchestrator: discovery → parsing → analysis → results."""

from __future__ import annotations

import asyncio
from pathlib import Path

from platformdirs import user_config_dir

from mcp_audit.analyzers.attack_paths import summarize_attack_paths
from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.credentials import CredentialsAnalyzer
from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
from mcp_audit.analyzers.rug_pull import RugPullAnalyzer, derive_state_path
from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer
from mcp_audit.analyzers.toxic_flow import ToxicFlowAnalyzer
from mcp_audit.analyzers.transport import TransportAnalyzer
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import discover_configs
from mcp_audit.models import Finding, RegistryStats, ScanResult, ServerConfig, Severity
from mcp_audit.scoring import calculate_score

_USER_RULES_DIR = Path(user_config_dir("mcp-audit")) / "rules"


def _extract_registry(analyzers: list[BaseAnalyzer]):
    """Return the :class:`KnownServerRegistry` owned by a SupplyChainAnalyzer.

    The scanner uses this to avoid reloading the registry JSON a second
    time when threading it into the toxic-flow analyzer.  Returns ``None``
    when no :class:`SupplyChainAnalyzer` is present (e.g. a custom analyzer
    list that excludes supply-chain checks).

    Args:
        analyzers: The list of analyzers used during the scan.

    Returns:
        The shared :class:`~mcp_audit.registry.loader.KnownServerRegistry`
        instance, or ``None`` if unavailable.
    """
    for analyzer in analyzers:
        if isinstance(analyzer, SupplyChainAnalyzer):
            return analyzer.registry
    return None


def _extract_registry_stats(
    analyzers: list[BaseAnalyzer],
) -> RegistryStats | None:
    """Extract registry metadata from the SupplyChainAnalyzer in *analyzers*.

    Uses the live ``len(registry.entries)`` count rather than the stored
    ``entry_count`` field, so the value stays accurate even if an entry was
    added without updating the field.

    Args:
        analyzers: The list of analyzers used during the scan.

    Returns:
        :class:`~mcp_audit.models.RegistryStats` if a
        :class:`~mcp_audit.analyzers.supply_chain.SupplyChainAnalyzer` is
        present, otherwise ``None``.
    """
    for analyzer in analyzers:
        if isinstance(analyzer, SupplyChainAnalyzer):
            reg = analyzer.registry
            return RegistryStats(
                entry_count=len(reg.entries),
                schema_version=reg.schema_version,
                last_updated=reg.last_updated,
            )
    return None


def _analyzer_crash_finding(
    analyzer_name: str, server: ServerConfig, exc: Exception
) -> Finding:
    """Build a HIGH-severity finding when an analyzer throws an exception."""
    return Finding(
        id="SCAN-ERR",
        severity=Severity.HIGH,
        analyzer="scanner",
        client=server.client,
        server=server.name,
        title=(
            f"Analyzer '{analyzer_name}' crashed on server "
            f"'{server.name}' — manual review required"
        ),
        description=(
            f"The {analyzer_name} analyzer raised an unexpected exception. "
            "Its findings for this server were not produced. A malicious "
            "config may be crafted to trigger this failure."
        ),
        evidence=f"{type(exc).__name__}: {exc}",
        remediation=(
            "Manually inspect this server configuration. Report this error "
            "to the mcp-audit maintainers if it persists."
        ),
        finding_path=str(server.config_path),
    )


def _run_rules_engine(
    servers: list[ServerConfig],
    extra_rules_dirs: list[Path] | None,
) -> list[Finding]:
    """Load and run the policy-as-code rule engine against all servers.

    Always loads bundled community rules.  When *extra_rules_dirs* is
    provided (caller is responsible for Pro-gating), also loads rules from
    those directories (user rules take precedence on ID conflicts).

    Args:
        servers: All discovered server configurations.
        extra_rules_dirs: Additional directories to load rules from.

    Returns:
        List of Finding objects produced by matching rules.
    """
    from mcp_audit.rules.engine import (  # noqa: PLC0415
        RuleEngine,
        load_bundled_community_rules,
        load_rules_from_dir,
        merge_rules,
    )

    community_rules = load_bundled_community_rules()

    if extra_rules_dirs:
        user_rules: list = []
        for d in extra_rules_dirs:
            user_rules.extend(load_rules_from_dir(d))
        # User rules take precedence on ID conflicts.
        all_rules = merge_rules(user_rules, community_rules)
    else:
        all_rules = community_rules

    engine = RuleEngine(all_rules)
    findings: list[Finding] = []
    for server in servers:
        findings.extend(engine.match_server(server))
    return findings


def get_default_analyzers() -> list[BaseAnalyzer]:
    """Return the default set of per-server analyzers.

    Note: :class:`~mcp_audit.analyzers.rug_pull.RugPullAnalyzer` is intentionally
    excluded here — it operates across all servers collectively and is invoked
    separately via :func:`run_scan`.
    """
    return [
        PoisoningAnalyzer(),
        CredentialsAnalyzer(),
        TransportAnalyzer(),
        SupplyChainAnalyzer(),
    ]


async def run_scan_async(
    extra_paths: list[Path] | None = None,
    analyzers: list[BaseAnalyzer] | None = None,
    connect: bool = False,
    state_path: Path | None = None,
    skip_rug_pull: bool = False,
    offline: bool = False,
    extra_rules_dirs: list[Path] | None = None,
) -> ScanResult:
    """Async scan entrypoint with optional live server enumeration.

    Performs the same static analysis as :func:`run_scan`.  When *connect* is
    ``True``, additionally attempts to connect to each discovered server via the
    MCP protocol, enumerate its live tool/resource/prompt definitions, and run
    the :class:`~mcp_audit.analyzers.poisoning.PoisoningAnalyzer` against the
    runtime data.  This surfaces poisoned tool descriptions that look clean in
    static config files.

    Requires the ``mcp`` optional dependency when *connect* is ``True``::

        pip install 'mcp-audit[mcp]'

    Args:
        extra_paths: Additional config paths to scan.
        analyzers: Custom per-server analyzer list.  Uses defaults if ``None``.
        connect: When ``True``, attempt live MCP protocol connections.
        state_path: Override the rug-pull state file location (useful in tests).
        skip_rug_pull: Skip rug-pull analysis entirely.  Used by ``pin``/``diff``.
        offline: When ``True``, forbid all network calls.
        extra_rules_dirs: Additional rule directories to load (Pro-gated by caller).

    Returns:
        :class:`~mcp_audit.models.ScanResult` with all findings.

    Raises:
        ValueError: If *connect* and *offline* are both ``True``.
    """
    if offline and connect:
        raise ValueError("Cannot use --connect with --offline")

    if analyzers is None:
        analyzers = get_default_analyzers()

    result = ScanResult()

    # ── Discover configs ───────────────────────────────────────────────────────
    configs = discover_configs(extra_paths=extra_paths)
    result.clients_scanned = len({c.client_name for c in configs})

    # ── Parse all configs up-front ─────────────────────────────────────────────
    all_servers: list[ServerConfig] = []
    for config in configs:
        try:
            servers = parse_config(config)
            all_servers.extend(servers)
        except ValueError as e:
            result.errors.append(str(e))

    result.servers_found = len(all_servers)
    result.servers = all_servers

    # ── Per-server static analysis ─────────────────────────────────────────────
    for server in all_servers:
        for analyzer in analyzers:
            try:
                findings = analyzer.analyze(server)
                for finding in findings:
                    finding.finding_path = str(server.config_path)
                result.findings.extend(findings)
            except Exception as e:  # noqa: BLE001
                result.findings.append(
                    _analyzer_crash_finding(analyzer.name, server, e)
                )

    # ── Live enumeration (opt-in) ──────────────────────────────────────────────
    if connect:
        from mcp_audit.mcp_client import (  # noqa: PLC0415
            build_runtime_server_config,
            connect_and_enumerate,
        )

        poisoning = PoisoningAnalyzer()

        for server in all_servers:
            enumeration = await connect_and_enumerate(server)

            if enumeration.error:
                result.errors.append(f"[connect] {server.name}: {enumeration.error}")
                continue

            runtime_config = build_runtime_server_config(server, enumeration)
            if runtime_config is None:
                continue

            try:
                runtime_findings = poisoning.analyze(runtime_config)
                for finding in runtime_findings:
                    finding.finding_path = str(server.config_path)
                    finding.description = f"[runtime] {finding.description}"
                result.findings.extend(runtime_findings)
            except Exception as e:  # noqa: BLE001
                result.findings.append(
                    _analyzer_crash_finding("poisoning (runtime)", server, e)
                )

    # ── Rug-pull analysis (cross-server, stateful) ─────────────────────────────
    if not skip_rug_pull:
        # Scope the state file to the exact set of configs being scanned so
        # that demo configs and real-machine configs never share a baseline.
        effective_state = (
            state_path if state_path is not None else derive_state_path(configs)
        )
        rug_pull = RugPullAnalyzer(state_path=effective_state)
        try:
            result.findings.extend(rug_pull.analyze_all(all_servers))
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"rug_pull error: {e}")

    # ── Toxic flow analysis (cross-server, stateless) ──────────────────────────
    # Share the SupplyChainAnalyzer's registry so capability data is read
    # from disk exactly once per scan.
    try:
        result.findings.extend(
            ToxicFlowAnalyzer(registry=_extract_registry(analyzers)).analyze_all(
                all_servers
            )
        )
    except Exception as e:  # noqa: BLE001
        result.errors.append(f"toxic_flow error: {e}")

    # ── Attack path summarization ──────────────────────────────────────────────
    try:
        toxic_findings = [f for f in result.findings if f.analyzer == "toxic_flow"]
        result.attack_path_summary = summarize_attack_paths(all_servers, toxic_findings)
    except Exception as e:  # noqa: BLE001
        result.errors.append(f"attack_paths error: {e}")

    # ── Policy-as-code rule engine ─────────────────────────────────────────────
    try:
        result.findings.extend(_run_rules_engine(all_servers, extra_rules_dirs))
    except Exception as e:  # noqa: BLE001
        result.errors.append(f"rules_engine error: {e}")

    # ── Scoring ────────────────────────────────────────────────────────────────
    result.score = calculate_score(result.findings)

    # ── Registry metadata ──────────────────────────────────────────────────────
    result.registry_stats = _extract_registry_stats(analyzers)

    return result


def run_scan(
    extra_paths: list[Path] | None = None,
    analyzers: list[BaseAnalyzer] | None = None,
    connect: bool = False,
    state_path: Path | None = None,
    skip_rug_pull: bool = False,
    offline: bool = False,
    extra_rules_dirs: list[Path] | None = None,
) -> ScanResult:
    """Run a complete scan: discover configs, parse them, analyze, return results.

    When *connect* is ``False`` (the default), this is a pure static analysis —
    no network calls, no subprocess spawning.  All configs are parsed first so
    that the rug-pull analyzer receives the full server list in a single
    :meth:`analyze_all` call.

    When *connect* is ``True``, delegates to :func:`run_scan_async` via
    :func:`asyncio.run` to perform live MCP protocol connections.

    Args:
        extra_paths: Additional config paths to scan.
        analyzers: Custom per-server analyzer list.  Uses defaults if ``None``.
        connect: When ``True``, attempt live MCP protocol connections.
        state_path: Override the rug-pull state file location.  Useful in tests.
        skip_rug_pull: When ``True``, skip rug-pull analysis entirely.  Used by
            the ``pin`` and ``diff`` CLI commands which manage state directly.
        offline: When ``True``, forbid all network calls.
        extra_rules_dirs: Additional rule directories to load (Pro-gated by caller).

    Returns:
        :class:`~mcp_audit.models.ScanResult` with all findings.

    Raises:
        ValueError: If *connect* and *offline* are both ``True``.
    """
    if offline and connect:
        raise ValueError("Cannot use --connect with --offline")

    if connect:
        return asyncio.run(
            run_scan_async(
                extra_paths=extra_paths,
                analyzers=analyzers,
                connect=True,
                state_path=state_path,
                skip_rug_pull=skip_rug_pull,
                offline=offline,
                extra_rules_dirs=extra_rules_dirs,
            )
        )

    # ── Static-only sync path (unchanged from original) ───────────────────────
    if analyzers is None:
        analyzers = get_default_analyzers()

    result = ScanResult()

    configs = discover_configs(extra_paths=extra_paths)
    result.clients_scanned = len({c.client_name for c in configs})

    all_servers: list[ServerConfig] = []
    for config in configs:
        try:
            servers = parse_config(config)
            all_servers.extend(servers)
        except ValueError as e:
            result.errors.append(str(e))

    result.servers_found = len(all_servers)
    result.servers = all_servers

    for server in all_servers:
        for analyzer in analyzers:
            try:
                findings = analyzer.analyze(server)
                for finding in findings:
                    finding.finding_path = str(server.config_path)
                result.findings.extend(findings)
            except Exception as e:  # noqa: BLE001
                result.findings.append(
                    _analyzer_crash_finding(analyzer.name, server, e)
                )

    if not skip_rug_pull:
        effective_state = (
            state_path if state_path is not None else derive_state_path(configs)
        )
        rug_pull = RugPullAnalyzer(state_path=effective_state)
        try:
            result.findings.extend(rug_pull.analyze_all(all_servers))
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"rug_pull error: {e}")

    # Share the SupplyChainAnalyzer's registry so capability data is read
    # from disk exactly once per scan.
    try:
        result.findings.extend(
            ToxicFlowAnalyzer(registry=_extract_registry(analyzers)).analyze_all(
                all_servers
            )
        )
    except Exception as e:  # noqa: BLE001
        result.errors.append(f"toxic_flow error: {e}")

    # ── Attack path summarization ──────────────────────────────────────────────
    try:
        toxic_findings = [f for f in result.findings if f.analyzer == "toxic_flow"]
        result.attack_path_summary = summarize_attack_paths(all_servers, toxic_findings)
    except Exception as e:  # noqa: BLE001
        result.errors.append(f"attack_paths error: {e}")

    # ── Policy-as-code rule engine ─────────────────────────────────────────────
    try:
        result.findings.extend(_run_rules_engine(all_servers, extra_rules_dirs))
    except Exception as e:  # noqa: BLE001
        result.errors.append(f"rules_engine error: {e}")

    # ── Scoring ────────────────────────────────────────────────────────────────
    result.score = calculate_score(result.findings)

    # ── Registry metadata ──────────────────────────────────────────────────────
    result.registry_stats = _extract_registry_stats(analyzers)

    return result
