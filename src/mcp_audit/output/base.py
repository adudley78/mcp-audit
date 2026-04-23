"""Abstract base class for output formatters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_audit.models import ScanResult


class BaseFormatter(ABC):
    """All output formatters inherit from this class and implement ``format``."""

    @abstractmethod
    def format(self, result: ScanResult) -> str:
        """Serialise a ScanResult to a string representation.

        Args:
            result: The completed scan result to format.

        Returns:
            String output ready for writing to stdout or a file.
        """
