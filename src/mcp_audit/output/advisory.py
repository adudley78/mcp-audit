"""Advisory output formatter — a scan result as a list of OSV 1.6.0 records.

This is the single-document face of the advisory subsystem: it turns a
:class:`~mcp_audit.models.ScanResult` into the same JSON array that
``mcp-audit advise`` writes to ``feed/osv/all.json``, so anything that already
consumes a formatter (``--format`` dispatch, piping to a file, an HTTP handler) can
emit advisories without knowing the feed layout exists.

Writing a *feed* — one file per advisory, an index, and detached signatures — is a
directory operation and therefore cannot be a :class:`BaseFormatter`, whose contract
returns a single string. That lives in :func:`mcp_audit.advisory.feed.write_feed`.
The two share :func:`~mcp_audit.advisory.feed.build_advisories`, so a record emitted
here is byte-identical to the same record inside a published feed.
"""

from __future__ import annotations

import json

from mcp_audit.advisory.feed import build_advisories
from mcp_audit.models import ScanResult, Severity
from mcp_audit.output.base import BaseFormatter


class AdvisoryFormatter(BaseFormatter):
    """Serialise a scan result as a JSON array of OSV 1.6.0 advisory records.

    Args:
        now: RFC 3339 UTC timestamp stamped onto every advisory. Required, and not
            defaulted to the wall clock, because advisory records are published
            artifacts that must be byte-reproducible: see ``docs/advisory-feed.md``.
        min_severity: Drop findings below this severity when given.
        only_observation: Keep only ``"package-intrinsic"`` or ``"deployment"``
            records when given.
        indent: ``json.dumps`` indent. ``None`` gives compact output.
    """

    def __init__(
        self,
        *,
        now: str,
        min_severity: Severity | None = None,
        only_observation: str | None = None,
        indent: int | None = 2,
    ) -> None:
        self.now = now
        self.min_severity = min_severity
        self.only_observation = only_observation
        self.indent = indent

    def format(self, result: ScanResult) -> str:
        """Return every eligible finding as an OSV record, ordered by advisory ID.

        Findings on servers with no published npm/PyPI package, and findings that
        assert no vulnerability, are omitted — see
        :func:`~mcp_audit.advisory.feed.build_advisories`.
        """
        report = build_advisories(
            result,
            now=self.now,
            min_severity=self.min_severity,
            only_observation=self.only_observation,
        )
        records = [advisory.to_osv() for advisory in report.advisories]
        return json.dumps(
            records, indent=self.indent, sort_keys=True, ensure_ascii=False
        )
