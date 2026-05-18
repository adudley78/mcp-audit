"""Fix strategy for TRANSPORT-001 — upgrade http:// URLs to https://."""

from __future__ import annotations

import copy

from mcp_audit.fixer.strategies.base import BaseFixStrategy, find_server_section
from mcp_audit.models import Finding


class TransportFixStrategy(BaseFixStrategy):
    """Rewrite ``http://`` server URLs to ``https://`` for TRANSPORT-001 findings.

    Only rewrites URLs for non-localhost remote hosts (the same condition the
    :class:`~mcp_audit.analyzers.transport.TransportAnalyzer` uses to fire the
    finding), so the fix is always safe to apply.

    The fix is idempotent: if the URL already uses ``https://``, the config is
    returned unchanged.
    """

    def can_fix(self, finding: Finding) -> bool:
        return finding.id == "TRANSPORT-001"

    def apply(self, config: dict, finding: Finding) -> tuple[dict, str]:
        server_dict, root_key = find_server_section(config, finding.server)
        if server_dict is None or root_key is None:
            raise ValueError(
                f"Server {finding.server!r} not found in config; cannot apply fix."
            )

        url: str | None = server_dict.get("url")
        if url is None:
            raise ValueError(
                f"Server {finding.server!r} has no 'url' field; "
                "cannot apply TRANSPORT-001 fix."
            )

        if not url.startswith("http://"):
            return config, f"URL for {finding.server!r} is not http:// (already fixed)"

        new_url = "https://" + url[len("http://") :]
        new_config = copy.deepcopy(config)
        new_config[root_key][finding.server]["url"] = new_url
        return (
            new_config,
            f"Upgraded URL for {finding.server!r}: {url!r} → {new_url!r}",
        )
