"""Abstract base class for all fix strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_audit.models import Finding

# MCP config root keys — VS Code uses "servers"; all other clients use "mcpServers".
_ROOT_KEYS: tuple[str, ...] = ("mcpServers", "servers")


def find_server_section(
    config: dict, server_name: str
) -> tuple[dict | None, str | None]:
    """Locate a server's configuration dict inside a raw config document.

    Checks both ``"mcpServers"`` (all clients) and ``"servers"`` (VS Code)
    root keys and returns the first match.

    Args:
        config: Parsed top-level config JSON dict.
        server_name: The server name key to find.

    Returns:
        ``(server_dict, root_key)`` when found; ``(None, None)`` otherwise.
    """
    for root_key in _ROOT_KEYS:
        if root_key in config:
            servers = config[root_key]
            if isinstance(servers, dict) and server_name in servers:
                return servers[server_name], root_key
    return None, None


class BaseFixStrategy(ABC):
    """Abstract base class for a single-finding-type remediation strategy.

    Implementors must define :meth:`can_fix` and :meth:`apply`.  The fixer
    orchestrator calls :meth:`can_fix` to route each finding to the right
    strategy, then calls :meth:`apply` to mutate the in-memory config dict.
    """

    @abstractmethod
    def can_fix(self, finding: Finding) -> bool:
        """Return ``True`` when this strategy knows how to fix *finding*.

        Args:
            finding: The :class:`~mcp_audit.models.Finding` to evaluate.

        Returns:
            ``True`` when the finding ID/type is handled by this strategy.
        """
        ...

    @abstractmethod
    def apply(self, config: dict, finding: Finding) -> tuple[dict, str]:
        """Apply the remediation for *finding* to *config*.

        The method receives the full top-level config dict (already parsed from
        JSON) and must return a **new** dict representing the modified config
        together with a human-readable description of what was changed.

        Implementations must be idempotent: if the finding has already been
        remediated (e.g. credential already replaced with ``${…}``), return the
        config unchanged and include ``"(already fixed)"`` in the description.

        Args:
            config: Full parsed config dict.  Do not mutate it in place — copy
                the relevant subtree and return the modified top-level dict.
            finding: The finding to remediate.

        Returns:
            ``(modified_config_dict, human_readable_description)`` where the
            description is one line suitable for a diff summary.

        Raises:
            ValueError: When the target server or field cannot be located.
        """
        ...
