"""Base class for all security analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_audit.models import Finding, ServerConfig


class BaseAnalyzer(ABC):
    """Abstract base class for MCP security analyzers.

    All analyzers must implement the `analyze` method, which takes a
    ServerConfig and returns a list of Findings (possibly empty).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this analyzer (e.g., 'poisoning', 'credentials')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this analyzer checks."""
        ...

    @abstractmethod
    def analyze(self, server: ServerConfig) -> list[Finding]:
        """Analyze a server configuration and return findings.

        Args:
            server: The MCP server configuration to analyze.

        Returns:
            List of security findings. Empty list means no issues found.
        """
        ...
