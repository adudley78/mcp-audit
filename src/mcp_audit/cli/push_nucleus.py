"""push-nucleus command — Enterprise-gated Nucleus Security FlexConnect push.

Runs a full scan and uploads the FlexConnect JSON directly to a Nucleus
project via the upload API, polls the resulting import job to completion,
and prints a Rich summary panel.

Upload approach (multipart/form-data) mirrors the validated implementation in
``scripts/validate_nucleus.py``. No third-party HTTP library is used.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from mcp_audit import cli as _cli
from mcp_audit._gate import gate
from mcp_audit.cli import app, console
from mcp_audit.cli._helpers import _write_output
from mcp_audit.cli.scan import _apply_severity_threshold
from mcp_audit.output.nucleus import format_nucleus

# Browser-like User-Agent avoids Cloudflare bot detection on Nucleus instances.
# Copied verbatim from scripts/validate_nucleus.py — keep in sync if updated.
_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_POLL_INTERVAL_SECONDS = 3
_TERMINAL_STATUSES: frozenset[str] = frozenset({"DONE", "ERROR", "DESCHEDULED"})


def _build_ssl_ctx() -> ssl.SSLContext:
    """Create a permissive SSL context for dev/staging Nucleus environments.

    Skips hostname and certificate verification. This is intentional for
    enterprise dev environments that may use self-signed certificates — do NOT
    use in production without explicit acknowledgment of the TLS risk.
    """
    # Dev-only: permissive SSL mirrors scripts/validate_nucleus.py approach.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _upload_scan(
    base_api_url: str,
    project_id: int,
    api_key: str,
    payload_json: str,
    ssl_ctx: ssl.SSLContext,
    con: Console,
) -> dict:
    """Upload a FlexConnect JSON payload via multipart/form-data.

    Matches the canonical upload approach validated in
    ``scripts/validate_nucleus.py::_upload_scan``.

    Args:
        base_api_url: Full base URL including ``/nucleus/api`` prefix.
        project_id: Nucleus project ID to upload into.
        api_key: Nucleus API key sent as the ``x-apikey`` header.
        payload_json: Serialised FlexConnect JSON string.
        ssl_ctx: SSL context; permissive for dev environments.
        con: Rich console for error output.

    Returns:
        Parsed JSON response dict, expected to contain ``job_id``.

    Raises:
        typer.Exit(2): On HTTP or network errors.
    """
    boundary = f"----NucleusBoundary{os.urandom(8).hex()}"
    json_bytes = payload_json.encode()

    content_disp = (
        'Content-Disposition: form-data; name="file"; filename="mcp-audit-scan.json"'
    )
    body = (
        f"--{boundary}\r\n"
        f"{content_disp}\r\n"
        f"Content-Type: application/json\r\n"
        f"\r\n"
    ).encode() + json_bytes + f"\r\n--{boundary}--\r\n".encode()

    url = f"{base_api_url}/projects/{project_id}/scans"
    req = urllib.request.Request(  # noqa: S310 — URL is user-supplied https:// Nucleus endpoint
        url,
        data=body,
        method="POST",
        headers={
            "x-apikey": api_key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "application/json",
            "User-Agent": _UA,
        },
    )
    try:
        with urllib.request.urlopen(  # noqa: S310  # nosec B310 — same URL validated above
            req, timeout=30, context=ssl_ctx
        ) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        con.print(f"[red]HTTP {exc.code} {exc.reason}[/red]")
        con.print(f"[red]  URL: {url}[/red]")
        con.print(f"[red]  Response body: {body_text[:500]}[/red]")
        raise typer.Exit(2) from None
    except urllib.error.URLError as exc:
        con.print(f"[red]Network error uploading to Nucleus: {exc.reason}[/red]")
        raise typer.Exit(2) from None


def _poll_job(
    base_api_url: str,
    project_id: int,
    job_id: int,
    api_key: str,
    ssl_ctx: ssl.SSLContext,
    timeout: int,
    con: Console,
) -> dict:
    """Poll Nucleus job status until a terminal state or timeout expires.

    Handles both list and dict response shapes; the Nucleus API is inconsistent
    across versions (see ``scripts/validate_nucleus.py::_poll_job``).

    Args:
        base_api_url: Full base URL including ``/nucleus/api`` prefix.
        project_id: Nucleus project ID.
        job_id: Job ID returned by the upload endpoint.
        api_key: Nucleus API key sent as the ``x-apikey`` header.
        ssl_ctx: SSL context; permissive for dev environments.
        timeout: Maximum seconds to wait before giving up.
        con: Rich console for progress output.

    Returns:
        Final job object dict when a terminal state (``DONE``, ``ERROR``, or
        ``DESCHEDULED``) is reached.

    Raises:
        typer.Exit(2): On timeout or unrecoverable network errors.
    """
    deadline = time.monotonic() + timeout
    url = f"{base_api_url}/projects/{project_id}/jobs/{job_id}"
    req_headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": _UA,
    }

    while time.monotonic() < deadline:
        req = urllib.request.Request(  # noqa: S310 — URL is the same Nucleus endpoint
            url, method="GET", headers=req_headers
        )
        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310 — same URL
                req, timeout=30, context=ssl_ctx
            ) as resp:
                job = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode(errors="replace")
            con.print(f"[red]Poll HTTP {exc.code}: {body_text[:200]}[/red]")
            raise typer.Exit(2) from None
        except urllib.error.URLError as exc:
            con.print(f"[red]Poll network error: {exc.reason}[/red]")
            raise typer.Exit(2) from None

        # The API may return a list or a dict depending on version — handle both.
        if isinstance(job, list):
            job = job[0] if job else {}

        status = job.get("status", "UNKNOWN")
        msg = (job.get("status_message") or "")[:80]
        con.print(f"[dim]  Job {job_id}: {status} — {msg}[/dim]")

        if status in _TERMINAL_STATUSES:
            return job

        time.sleep(_POLL_INTERVAL_SECONDS)

    con.print(
        f"[red]Timeout: job {job_id} did not reach a terminal state "
        f"within {timeout}s.[/red]"
    )
    raise typer.Exit(2)


@app.command(name="push-nucleus")
def push_nucleus(
    url: str = typer.Option(  # noqa: B008
        ...,
        "--url",
        help="Nucleus instance base URL, e.g. https://nucleus-demo.nucleussec.com",
    ),
    project_id: int = typer.Option(  # noqa: B008
        ...,
        "--project-id",
        help="Nucleus project ID",
    ),
    api_key: str | None = typer.Option(  # noqa: B008
        None,
        "--api-key",
        help="Nucleus API key (falls back to NUCLEUS_API_KEY env var when omitted)",
    ),
    asset_prefix: str | None = typer.Option(  # noqa: B008
        None,
        "--asset-prefix",
        help=(
            "Override the hostname used as the asset identifier in FlexConnect output. "
            "Useful when the hostname is not meaningful (e.g. 'MacBookAir')."
        ),
    ),
    config_paths: list[Path] | None = typer.Option(  # noqa: B008
        None,
        "--config-paths",
        help="Paths to scan (same as scan --config-paths). Repeatable.",
    ),
    severity_threshold: str = typer.Option(  # noqa: B008
        "INFO",
        "--severity-threshold",
        "-s",
        help=(
            "Minimum severity to include before pushing. "
            "Default: INFO (all findings). Accepted: critical, high, medium, low, info."
        ),
    ),
    timeout: int = typer.Option(  # noqa: B008
        120,
        "--timeout",
        help="Job poll timeout in seconds (default: 120).",
    ),
    output_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--output-file",
        "-o",
        help=(
            "Also write the FlexConnect JSON to this path "
            "(parent dirs created automatically)."
        ),
    ),
) -> None:
    """Run a scan and push results to Nucleus Security via FlexConnect API.

    Requires an Enterprise license.  Polls the import job to completion and
    prints a Rich summary panel with the project ID, job ID, finding count,
    and a direct link to the Nucleus findings view.

    Examples::

        mcp-audit push-nucleus \\
            --url https://nucleus-demo.nucleussec.com --project-id 42

        mcp-audit push-nucleus \\
            --url https://nucleus.corp.example.com --project-id 7 \\
            --severity-threshold HIGH --output-file pushed-scan.json
    """
    if not gate("nucleus", console):
        raise typer.Exit(1)

    # Resolve API key: explicit flag → NUCLEUS_API_KEY env var.
    resolved_key = (api_key or os.environ.get("NUCLEUS_API_KEY", "")).strip()
    if not resolved_key:
        console.print(
            "[red]Error:[/red] No API key supplied. "
            "Pass [bold]--api-key[/bold] or set the "
            "[bold]NUCLEUS_API_KEY[/bold] environment variable."
        )
        raise typer.Exit(2)

    # Validate all user-supplied config paths before running the scan.
    extra_paths: list[Path] | None = None
    if config_paths:
        for p in config_paths:
            if not p.resolve().exists():
                console.print(f"[red]Error:[/red] Config path not found: {p}")
                raise typer.Exit(2)
        extra_paths = list(config_paths)

    result = _cli.run_scan(extra_paths=extra_paths)
    result = _apply_severity_threshold(result, severity_threshold, console)

    nucleus_json = format_nucleus(result, asset_prefix=asset_prefix, console=console)
    if nucleus_json is None:
        # Defensive: gate() already confirmed enterprise tier, but format_nucleus
        # performs its own license check — surface a clear error if both diverge.
        console.print(
            "[red]Error:[/red] Failed to produce FlexConnect JSON. "
            "Verify your Enterprise license is active with "
            "[bold]mcp-audit license[/bold]."
        )
        raise typer.Exit(2)

    if output_file is not None:
        _write_output(output_file, nucleus_json)
        console.print(f"[dim]FlexConnect JSON written to {output_file}[/dim]")

    base_api_url = url.rstrip("/") + "/nucleus/api"
    ssl_ctx = _build_ssl_ctx()

    console.print(
        f"[dim]Uploading to {base_api_url}/projects/{project_id}/scans …[/dim]"
    )
    resp = _upload_scan(
        base_api_url, project_id, resolved_key, nucleus_json, ssl_ctx, console
    )

    job_id = resp.get("job_id")
    if not job_id:
        console.print(
            "[red]Error:[/red] Upload succeeded but no job_id in response.\n"
            f"Full response: {json.dumps(resp)[:500]}"
        )
        raise typer.Exit(2)

    console.print(
        f"[dim]Upload accepted. Polling job {job_id} (timeout: {timeout}s) …[/dim]"
    )

    final_job = _poll_job(
        base_api_url, project_id, job_id, resolved_key, ssl_ctx, timeout, console
    )

    status = final_job.get("status", "UNKNOWN")

    if status == "DONE":
        nucleus_doc = json.loads(nucleus_json)
        asset_name = (nucleus_doc.get("assets") or [{}])[0].get("host_name", "unknown")
        finding_count = len(nucleus_doc.get("findings", []))
        ui_link = f"{url.rstrip('/')}/nucleus/ui/projects/{project_id}/findings"

        console.print(
            Panel(
                f"[bold green]Push complete.[/bold green]\n\n"
                f"[bold]Project ID:[/bold]      {project_id}\n"
                f"[bold]Job ID:[/bold]          {job_id}\n"
                f"[bold]Findings pushed:[/bold] {finding_count}\n"
                f"[bold]Asset:[/bold]           {asset_name}\n\n"
                f"View in Nucleus UI:\n"
                f"[link={ui_link}]{ui_link}[/link]",
                title="Nucleus FlexConnect",
                border_style="green",
            )
        )
    else:
        status_msg = (final_job.get("status_message") or "")[:500]
        console.print(
            f"[red]Nucleus import job ended with status {status!r}.[/red]\n"
            f"  Message: {status_msg}"
        )
        raise typer.Exit(1)
