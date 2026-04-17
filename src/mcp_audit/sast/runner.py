"""Semgrep-based SAST runner for MCP server source code."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.models import Finding, Severity
from mcp_audit.sast.bundler import get_bundled_rules_path

SEMGREP_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}

# Security: maximum wall-clock seconds allowed for a semgrep invocation.
# A hung semgrep process must not hang the entire scanner indefinitely.
SEMGREP_TIMEOUT_SECONDS: int = 300

# Repo-root semgrep-rules/ directory (development mode).
_REPO_RULES_DIR = Path(__file__).parent.parent.parent.parent / "semgrep-rules"


@dataclass
class SastResult:
    """Result from a Semgrep SAST scan."""

    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    files_scanned: int = 0
    semgrep_version: str | None = None
    error: str | None = None


def find_semgrep() -> str | None:
    """Return path to the semgrep binary, or None if not installed.

    Security: resolved via shutil.which() (PATH lookup only) — not from a
    user-controlled env var or CLI argument.
    """
    return shutil.which("semgrep")


def find_rules_dir() -> Path | None:
    """Resolve the semgrep-rules/ directory.

    Resolution order:
    1. Repo root (development)
    2. PyInstaller _MEIPASS (bundled binary)
    3. Directory adjacent to the mcp-audit executable
    """
    # 1. Repo root (development / editable install)
    if _REPO_RULES_DIR.is_dir():
        return _REPO_RULES_DIR

    # 2. PyInstaller bundle
    bundled = get_bundled_rules_path()
    if bundled is not None:
        return bundled

    # 3. Adjacent to the running executable (e.g., installed alongside binary)
    exe_path = Path(shutil.which("mcp-audit") or "")
    if exe_path.parent.is_dir():
        adjacent = exe_path.parent / "semgrep-rules"
        if adjacent.is_dir():
            return adjacent

    return None


def run_semgrep(
    target_path: Path,
    rules_dir: Path | None = None,
) -> SastResult:
    """Run semgrep against target_path using the mcp-audit rule pack.

    Returns a SastResult with findings or an error string. Never raises.

    - If semgrep is not installed: returns SastResult with error message
      and empty findings.
    - If rules_dir is not found: returns SastResult with error message.
    - If semgrep exits non-zero because findings were found: parses normally.
    - If semgrep has a real error: captures stderr and returns error.
    """
    # Security: resolve to an absolute path so the subprocess receives a
    # canonical path — prevents relative-path confusion attacks.
    target_path = target_path.resolve()

    semgrep_bin = find_semgrep()
    if semgrep_bin is None:
        return SastResult(
            error=("semgrep is not installed. Install it with: pip install semgrep")
        )

    effective_rules_dir = rules_dir or find_rules_dir()
    if effective_rules_dir is None:
        return SastResult(
            error=(
                "semgrep-rules/ directory not found. "
                "Ensure the mcp-audit package is fully installed."
            )
        )

    # Security: command is list form — shell=False (default), no injection possible.
    cmd = [
        semgrep_bin,
        "--config",
        str(effective_rules_dir),
        str(target_path),
        "--json",
        "--quiet",
        "--no-git-ignore",
    ]

    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,  # Security: stderr captured, not inherited by tty.
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return SastResult(
            error=f"semgrep timed out after {SEMGREP_TIMEOUT_SECONDS} seconds"
        )
    except Exception as exc:  # noqa: BLE001
        return SastResult(error=f"Failed to run semgrep: {exc}")

    # semgrep exits 1 when findings are present — that's expected, not an error.
    # Exit code 2 indicates a real error.
    if proc.returncode == 2:
        stderr = proc.stderr.strip()
        return SastResult(error=f"semgrep error: {stderr or 'unknown error'}")

    try:
        output = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return SastResult(error=f"Failed to parse semgrep JSON output: {exc}")

    findings = parse_semgrep_output(output, target_path)
    version = output.get("version")

    # Extract file count from results if available
    scanned_files: set[str] = {r.get("path", "") for r in output.get("results", [])}

    return SastResult(
        findings=findings,
        rules_run=len(output.get("rules", [])),
        files_scanned=len(scanned_files),
        semgrep_version=version,
    )


def _finding_id(rule_id: str, file_path: str, line: int) -> str:
    """Produce a deterministic finding ID from rule + file + line."""
    raw = f"sast:{rule_id}:{file_path}:{line}"
    return "SAST-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


def parse_semgrep_output(semgrep_json: dict, target_path: Path) -> list[Finding]:
    """Convert semgrep JSON output to mcp-audit Finding objects.

    Semgrep JSON structure (relevant fields):

    .. code-block:: json

        {
          "results": [
            {
              "check_id": "python.injection.mcp-subprocess-string-cmd",
              "path": "src/my_server.py",
              "start": {"line": 42},
              "extra": {
                "message": "...",
                "severity": "WARNING",
                "metadata": {"cwe": "CWE-78", "category": "injection"}
              }
            }
          ],
          "version": "1.x.x"
        }
    """
    findings: list[Finding] = []

    for result in semgrep_json.get("results", []):
        check_id: str = result.get("check_id", "unknown")
        file_path: str = result.get("path", str(target_path))
        line: int = result.get("start", {}).get("line", 0)
        extra: dict = result.get("extra", {})
        message: str = extra.get("message", "No message")
        raw_severity: str = extra.get("severity", "WARNING").upper()
        metadata: dict = extra.get("metadata", {})

        severity = SEMGREP_SEVERITY_MAP.get(raw_severity, Severity.HIGH)
        rule_short = check_id.split(".")[-1] if "." in check_id else check_id
        cwe: str | None = metadata.get("cwe")
        category: str = metadata.get("category", "sast")

        finding_id = _finding_id(check_id, file_path, line)
        server_name = Path(file_path).name

        evidence_data = {
            "rule_id": check_id,
            "file": file_path,
            "line": line,
            "cwe": cwe,
            "category": category,
        }

        findings.append(
            Finding(
                id=finding_id,
                severity=severity,
                analyzer="sast",
                client="sast",
                server=server_name,
                title=rule_short,
                description=message,
                evidence=json.dumps(evidence_data),
                remediation=_remediation_for_category(category),
                cwe=cwe,
                finding_path=file_path,
            )
        )

    return findings


def _remediation_for_category(category: str) -> str:
    """Return a brief remediation hint for a given SAST finding category."""
    hints: dict[str, str] = {
        "injection": (
            "Validate and sanitise all user-supplied input before passing it "
            "to system calls, eval(), file paths, or SQL queries."
        ),
        "poisoning": (
            "Remove prompt injection keywords and URLs from tool descriptions. "
            "Descriptions should be plain natural language."
        ),
        "credentials": (
            "Move credentials to environment variables or a secrets manager. "
            "Never hardcode API keys, passwords, or connection strings."
        ),
        "protocol": (
            "Validate MCP tool arguments before use. Return generic error "
            "messages rather than raw exception text or stack traces."
        ),
        "transport": (
            "Enable TLS for HTTP MCP servers. Bind to 127.0.0.1 rather than "
            "0.0.0.0 unless network access is explicitly required."
        ),
    }
    return hints.get(
        category,
        "Review the flagged code and apply secure coding practices.",
    )
