"""dashboard command — run a scan and serve an interactive attack graph."""

from __future__ import annotations

from pathlib import Path

import typer

from mcp_audit import cli as _cli
from mcp_audit.cli import app, console
from mcp_audit.output.dashboard import generate_html

# ── dashboard ─────────────────────────────────────────────────────────────────


@app.command()
def dashboard(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Scan a specific config file or directory"
    ),
    port: int = typer.Option(  # noqa: B008
        8088, "--port", help="Local port for the dashboard server"
    ),
    connect: bool = typer.Option(  # noqa: B008
        False,
        "--connect",
        help="Connect to live MCP servers during scan",
    ),
    no_open: bool = typer.Option(  # noqa: B008
        False, "--no-open", help="Don't auto-open browser"
    ),
    rules_dir: Path | None = typer.Option(  # noqa: B008
        None,
        "--rules-dir",
        help="Additional directory of YAML rules to apply",
    ),
) -> None:
    """Run a full scan and open an interactive attack-graph dashboard."""
    import http.server  # noqa: PLC0415
    import threading  # noqa: PLC0415
    import webbrowser  # noqa: PLC0415

    extra_paths = [path] if path else None
    from mcp_audit.scanner import (
        _USER_RULES_DIR as _DASH_USER_RULES_DIR,  # noqa: PLC0415
    )

    extra_rules_dirs: list[Path] = []
    if rules_dir is not None:
        if not rules_dir.is_dir():
            console.print(
                f"[red]--rules-dir path is not a directory: {rules_dir}[/red]"
            )
            raise typer.Exit(2)  # noqa: B904
        extra_rules_dirs.append(rules_dir)

    if _DASH_USER_RULES_DIR.is_dir():
        extra_rules_dirs.append(_DASH_USER_RULES_DIR)

    console.print("\n[cyan]Running scan…[/cyan]")
    result = _cli.run_scan(
        extra_paths=extra_paths,
        connect=connect,
        extra_rules_dirs=extra_rules_dirs if extra_rules_dirs else None,
    )

    console.print("[cyan]Generating dashboard…[/cyan]")
    html = generate_html(result, console=console)
    html_bytes = html.encode("utf-8")

    # In-memory HTTP handler — no I/O on every request.
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.end_headers()
            self.wfile.write(html_bytes)

        def log_message(self, *_args: object) -> None:  # type: ignore[override]
            pass  # suppress default request logging

    url = f"http://localhost:{port}"
    try:
        srv = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    except OSError as exc:
        console.print(
            f"[red]Cannot bind port {port}: {exc}.[/red]  "
            "Try [bold]--port[/bold] with a different value."
        )
        raise typer.Exit(2)  # noqa: B904

    console.print(
        f"\n[bold cyan]Dashboard running at {url}[/bold cyan] — press Ctrl+C to stop"
    )

    if not no_open:
        threading.Timer(0.3, webbrowser.open, args=(url,)).start()

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        console.print("\n[dim]Dashboard stopped.[/dim]")
