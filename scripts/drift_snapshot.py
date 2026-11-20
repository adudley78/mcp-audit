#!/usr/bin/env python3
"""Take one drift snapshot: install each package, start it isolated, digest its tools.

This is the weekly form of ``snapshot_run.py`` in
``docs/research/2026-12-launch-drift/scripts/``.
The method is the same; the paths are not fixed to one machine, and the process
that reads the servers' output does not have to be root.

For each (package, version) in the plan (``current_versions.py`` writes it):

1. Install it in its own prefix as the unprivileged probe user. npm runs with
   ``--ignore-scripts``; PyPI installs wheels only (``--only-binary :all:``).
   So no package code runs at install time.
2. Start the server as the probe user under ``unshare --net`` (no network
   interface) with ``env -i`` (an empty environment: no token, no key).
3. Record the lock digests of its tools (``lock/tool_digests.py``).
4. Delete the prefix.

The per-pair files hold the tool text and stay in the output directory, which
is not published. ``--summary`` writes the publishable file: digests only.

Environment:

- ``DRIFT_PROBE_USER`` (default ``probe``).
- ``DRIFT_PROBE_HOME`` (default ``/srv/probe``).
- ``DRIFT_PYTHON``: interpreter for the PyPI packages' venvs (default: this one).
- ``DRIFT_NODE_BIN``: directory that holds ``node`` and ``npm`` (default: from PATH).
- ``DRIFT_LIMIT``: take only the first N pairs (for a test run).
- ``MCP_TIMEOUT`` (seconds per server, default 60), ``MCP_CONC`` (default 4).
- ``SSL_CERT_FILE`` / ``HTTPS_PROXY`` / ``HTTP_PROXY`` are passed to the install
  step only, never to a server.

It needs root for ``unshare`` and ``runuser``. When it does not run as root it
calls them through ``sudo -n``.

Usage::

    python scripts/drift_snapshot.py PLAN.json OUT_DIR --label 2026-11-23 \
        --summary snapshots/2026-11-23.json [--overrides OVERRIDES.json ...]
"""

from __future__ import annotations

import argparse
import asyncio
import configparser
import datetime as dt
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

NPM_NAME = re.compile(r"^(@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$")
PYPI_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")
BIN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PASSED_TO_INSTALL = ("HTTPS_PROXY", "HTTP_PROXY", "SSL_CERT_FILE")


class Settings:
    """Where things are on this machine. Read once from the environment."""

    def __init__(self) -> None:
        self.user = os.environ.get("DRIFT_PROBE_USER", "probe")
        self.home = os.environ.get("DRIFT_PROBE_HOME", "/srv/probe").rstrip("/")
        self.python = os.environ.get("DRIFT_PYTHON", sys.executable)
        node = os.environ.get("DRIFT_NODE_BIN") or os.path.dirname(
            shutil.which("node") or ""
        )
        uv = os.path.dirname(shutil.which("uv") or "")
        if not node or not uv:
            raise SystemExit(
                "error: node and uv must be on PATH (or set DRIFT_NODE_BIN)"
            )
        self.path = ":".join(
            dict.fromkeys([node, uv, "/usr/local/bin", "/usr/bin", "/bin"])
        )
        self.priv = [] if os.geteuid() == 0 else ["sudo", "-n"]
        self.timeout = float(os.environ.get("MCP_TIMEOUT", "60"))
        self.conc = int(os.environ.get("MCP_CONC", "4"))
        self.limit = int(os.environ.get("DRIFT_LIMIT", "0"))
        self.pkgs = f"{self.home}/pkgs"
        self.homes = f"{self.home}/home"

    def install_env(self) -> list[str]:
        env = {
            "HOME": self.home,
            "PATH": self.path,
            "npm_config_cache": f"{self.home}/.npm",
            "UV_CACHE_DIR": f"{self.home}/.uv",
            "UV_NO_CONFIG": "1",
        }
        for name in PASSED_TO_INSTALL:
            if os.environ.get(name):
                env[name] = os.environ[name]
        if env.get("SSL_CERT_FILE"):
            env["npm_config_cafile"] = env["SSL_CERT_FILE"]
        return [f"{k}={v}" for k, v in env.items()]


def slug(kind: str, name: str, version: str) -> str:
    """File-system name for one (package, version) pair."""
    return f"{kind}__{name.replace('/', '__').replace('@', '')}@{version}"


def valid_pair(kind: str, name: str, version: str) -> bool:
    """Reject anything that is not a plain registry name and version.

    The name and the version become command arguments and path components.
    """
    if not VERSION.match(version) or ".." in name or ".." in version:
        return False
    if kind == "npm":
        return bool(NPM_NAME.match(name)) and len(name) <= 214
    if kind == "pypi":
        return bool(PYPI_NAME.match(name))
    return False


async def as_probe(
    cfg: Settings, cmd: list[str], timeout: float = 900
) -> tuple[int, str]:
    """Run *cmd* as the probe user with the install environment."""
    full = [
        *cfg.priv,
        "runuser",
        "-u",
        cfg.user,
        "--",
        "env",
        "-i",
        *cfg.install_env(),
        *cmd,
    ]
    proc = await asyncio.create_subprocess_exec(
        *full, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
    )
    try:
        _, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, f"timed out after {timeout:.0f}s"
    return proc.returncode or 0, err.decode(errors="replace")[-600:]


async def install(
    cfg: Settings, kind: str, name: str, version: str, prefix: str
) -> tuple[int, str]:
    """Install one pair without running any of its code."""
    if kind == "npm":
        return await as_probe(
            cfg,
            [
                "npm",
                "install",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--loglevel=error",
                "--prefix",
                prefix,
                f"{name}@{version}",
            ],
        )
    rc, err = await as_probe(
        cfg, ["uv", "venv", "-q", "--python", cfg.python, f"{prefix}/venv"]
    )
    if rc:
        return rc, err
    return await as_probe(
        cfg,
        [
            "uv",
            "pip",
            "install",
            "-q",
            "--only-binary",
            ":all:",
            "--python",
            f"{prefix}/venv/bin/python",
            f"{name}=={version}",
        ],
    )


def npm_bin(prefix: str, name: str, override: dict[str, Any]) -> str | None:
    """The command an npm package installs, when there is exactly one clear choice."""
    if override.get("bin"):
        return str(override["bin"])
    try:
        with open(f"{prefix}/node_modules/{name}/package.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError):
        return None
    bins = manifest.get("bin")
    unscoped = name.split("/")[-1]
    if isinstance(bins, str):
        return str(manifest.get("name", name)).split("/")[-1]
    if isinstance(bins, dict):
        if len(bins) == 1:
            return str(next(iter(bins)))
        if unscoped in bins:
            return unscoped
    return None


def py_bin(prefix: str, name: str) -> str | None:
    """The console script a PyPI package installs."""
    want = name.lower().replace("_", "-").replace(".", "-")
    pattern = f"{prefix}/venv/lib/python*/site-packages/*.dist-info/entry_points.txt"
    for ep in glob.glob(pattern):
        dist = os.path.basename(os.path.dirname(ep)).removesuffix(".dist-info")
        dist = dist.rsplit("-", 1)[0].lower().replace("_", "-").replace(".", "-")
        if dist != want:
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read(ep, encoding="utf-8")
        except (configparser.Error, OSError):
            return None
        if "console_scripts" not in parser:
            return None
        scripts = list(parser["console_scripts"])
        if want in scripts:
            return want
        mcp = [s for s in scripts if "mcp" in s]
        return (mcp or scripts or [None])[0]
    return None


def launch(
    cfg: Settings, kind: str, name: str, version: str, override: dict[str, Any]
) -> tuple[list[str] | None, str | None]:
    """The isolated command line for one installed pair, and the bin it runs."""
    prefix = f"{cfg.pkgs}/{slug(kind, name, version)}"
    if kind == "npm":
        binary = npm_bin(prefix, name, override)
        path = f"{prefix}/node_modules/.bin/{binary}" if binary else None
    else:
        binary = py_bin(prefix, name)
        path = f"{prefix}/venv/bin/{binary}" if binary else None
    if not binary or not path or not BIN_NAME.match(binary):
        return None, None
    home = f"{cfg.homes}/{slug(kind, name, version)}"
    extra_env = [
        f"{k}={v}"
        for k, v in (override.get("env") or {}).items()
        if ENV_NAME.match(str(k))
    ]
    argv = [
        *cfg.priv,
        "unshare",
        "--net",
        "--",
        "runuser",
        "-u",
        cfg.user,
        "--",
        "env",
        "-i",
        f"HOME={home}",
        f"PATH={cfg.path}",
        *extra_env,
        path,
        *[str(a) for a in override.get("args") or []],
    ]
    return argv, binary


def _run(cfg: Settings, cmd: list[str]) -> None:
    # A fixed command (rm) on a path this script built and checked; no shell.
    subprocess.run(  # noqa: S603
        [*cfg.priv, *cmd],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=300,
    )


def remove_prefix(cfg: Settings, path: str) -> None:
    """Delete one probe-owned directory under the probe home."""
    if path.startswith((cfg.pkgs + "/", cfg.homes + "/")) and ".." not in path:
        _run(cfg, ["rm", "-rf", "--", path])


#: An ISO calendar date. A tool that writes the date of the day into its
#: description (an example query for "today") gets a new definition digest each
#: day with no change by its author.
_ISO_DATE = re.compile(r"(?<![0-9])([0-9]{4})-([0-9]{2})-([0-9]{2})(?![0-9])")

#: A tool with more dates than this gets no ``undated`` record.
MAX_DATES = 200


def without_dates(value: Any, found: list[str]) -> Any:
    """Return *value* with the ISO dates cut out of its strings.

    Each string becomes the list of its pieces between the dates, so a string
    with no date becomes a list of one piece. Each date that is cut out is
    added to *found*, in a fixed order (keys sorted). The result of two
    values is the same only when they are the same value apart from their
    dates: no text can stand for a date, because a date leaves a gap between
    two pieces and nothing else does. Text that is not a real date
    (``1111-22-33``, month 13) stays in its piece. Keys are not changed.
    """
    if isinstance(value, str):
        pieces: list[str] = []
        start = 0
        for match in _ISO_DATE.finditer(value):
            try:
                dt.date(int(match[1]), int(match[2]), int(match[3]))
            except ValueError:
                continue
            pieces.append(value[start : match.start()])
            found.append(match[0])
            start = match.end()
        pieces.append(value[start:])
        return pieces
    if isinstance(value, list):
        return [without_dates(item, found) for item in value]
    if isinstance(value, dict):
        return {key: without_dates(value[key], found) for key in sorted(value)}
    return value


def add_undated(
    digests: dict[str, dict[str, Any]], definitions: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Record the dates of each tool whose definition holds an ISO date.

    Such a tool gets two more fields: ``undated``, the digest of its
    definition with each date cut out (:func:`without_dates`), and ``dates``,
    the dates themselves in order. ``drift_compare.py`` uses them to tell a tool whose
    text changed from a tool whose dates only moved with the calendar. The
    dates are the only part of a tool's text that the snapshot holds. A tool
    with no date, with more than ``MAX_DATES`` dates, or that shares its name
    with another tool of the server gets neither field.
    """
    from mcp_audit.lock.tool_digests import digest

    names = Counter(d["name"] for d in definitions)
    for definition in definitions:
        name = definition["name"]
        if names[name] != 1 or name not in digests:
            continue
        found: list[str] = []
        rest = {key: value for key, value in definition.items() if key != "name"}
        plain = {**without_dates(rest, found), "name": name}
        if found and len(found) <= MAX_DATES:
            digests[name]["undated"] = digest(plain)
            digests[name]["dates"] = found
    return digests


async def one(
    cfg: Settings,
    sem: asyncio.Semaphore,
    key: tuple[str, str, str],
    labels: list[str],
    overrides: dict[str, Any],
    out: Path,
) -> None:
    """Install, run, record and remove one pair."""
    from mcp_audit.lock.tool_digests import tool_definition, tool_digests
    from mcp_audit.mcp_client import connect_and_enumerate
    from mcp_audit.models import ServerConfig, TransportType

    kind, name, version = key
    target = out / (slug(kind, name, version) + ".json")
    if target.exists():
        return
    base = {"type": kind, "package": name, "version": version, "labels": labels}
    if not valid_pair(kind, name, version):
        target.write_text(json.dumps({**base, "error": "name or version not accepted"}))
        return
    prefix = f"{cfg.pkgs}/{slug(kind, name, version)}"
    home = f"{cfg.homes}/{slug(kind, name, version)}"
    override = overrides.get(name, {}) if kind == "npm" else {}
    async with sem:
        try:
            rc, err = await install(cfg, kind, name, version, prefix)
            if rc:
                target.write_text(
                    json.dumps(
                        {**base, "error": "install failed", "install_error": err}
                    )
                )
                print(name, version, "install failed", flush=True)
                return
            argv, binary = launch(cfg, kind, name, version, override)
            if argv is None:
                target.write_text(
                    json.dumps({**base, "error": "no unambiguous entry point"})
                )
                return
            await as_probe(cfg, ["mkdir", "-p", home], timeout=30)
            server = ServerConfig(
                name=name,
                client="corpus",
                config_path=Path("/corpus/mcp.json"),
                transport=TransportType.STDIO,
                command=argv[0],
                args=argv[1:],
                env={},
            )
            started = time.time()
            enum = await connect_and_enumerate(server, timeout=cfg.timeout)
        finally:
            remove_prefix(cfg, prefix)
            remove_prefix(cfg, home)
    definitions = [tool_definition(t) for t in enum.tools]
    record = {
        **base,
        "bin": binary,
        "elapsed": round(time.time() - started, 1),
        "error": enum.error,
        "tools_error": enum.tools_error,
        "definitions": definitions,
        "digests": add_undated(tool_digests(enum.tools), definitions)
        if enum.tools
        else {},
    }
    target.write_text(json.dumps(record, indent=1))
    print(name, version, "tools", len(enum.tools), "err", enum.error, flush=True)


def summarize(out: Path, label: str) -> dict[str, Any]:
    """Collapse the per-pair files into the publishable snapshot (digests only)."""
    from importlib.metadata import version as dist_version

    records = [json.loads(p.read_text()) for p in sorted(out.glob("*.json"))]
    rows = [
        {
            "type": r["type"],
            "package": r["package"],
            "version": r["version"],
            "connected": not r.get("error") and bool(r.get("digests")),
            "error": r.get("error"),
            "tool_count": len(r.get("digests") or {}),
            "digests": r.get("digests") or {},
        }
        for r in records
    ]
    rows.sort(key=lambda r: (r["type"], r["package"], r["version"]))
    failures = Counter(
        (r["error"] or "connected, no tools").split(":")[0][:60]
        for r in rows
        if not r["connected"]
    )
    return {
        "schema_version": 1,
        "label": label,
        "generated_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": f"mcp-audit {dist_version('mcp-audit-scanner')}",
        "runner_python": platform.python_version(),
        "pairs": len(rows),
        "connected": sum(r["connected"] for r in rows),
        "failure_classes": failures.most_common(),
        "rows": rows,
    }


async def run(
    cfg: Settings, plan: list[dict[str, Any]], overrides: dict[str, Any], out: Path
) -> None:
    """Run every pair in the plan, a few at a time."""
    pairs: dict[tuple[str, str, str], list[str]] = {}
    for package in plan:
        for label, entry in (package.get("versions") or {}).items():
            key = (
                str(package.get("type")),
                str(package.get("package")),
                str(entry.get("version")),
            )
            pairs.setdefault(key, []).append(str(label))
    keys = sorted(pairs)
    if cfg.limit:
        keys = keys[: cfg.limit]
    for directory in (cfg.pkgs, cfg.homes):
        await as_probe(cfg, ["mkdir", "-p", directory], timeout=30)
    # This process reads each installed package's manifest to find its command.
    # `useradd --create-home` makes the home 0750, which hides it from us when
    # we are not root (found on the first GitHub runner test: 12 of 12 pairs
    # reported "no unambiguous entry point").
    _run(cfg, ["chmod", "755", cfg.home, cfg.pkgs])
    sem = asyncio.Semaphore(cfg.conc)
    await asyncio.gather(*(one(cfg, sem, k, pairs[k], overrides, out) for k in keys))


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("plan", type=Path, help="Plan from current_versions.py")
    parser.add_argument(
        "out", type=Path, help="Directory for the per-pair files (not published)"
    )
    parser.add_argument(
        "--overrides",
        type=Path,
        nargs="*",
        default=[],
        help="Launch override files, later ones win",
    )
    parser.add_argument("--label", required=True, help="Snapshot date, YYYY-MM-DD")
    parser.add_argument(
        "--summary", type=Path, help="Write the publishable snapshot here"
    )
    args = parser.parse_args(argv)
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", args.label):
        print("error: --label must be YYYY-MM-DD", file=sys.stderr)
        return 2
    plan = json.loads(args.plan.read_text())["packages"]
    overrides: dict[str, Any] = {}
    for path in args.overrides:
        overrides.update(json.loads(path.read_text()))
    args.out.mkdir(parents=True, exist_ok=True)
    cfg = Settings()
    asyncio.run(run(cfg, plan, overrides, args.out))
    snapshot = summarize(args.out, args.label)
    print(
        "pairs",
        snapshot["pairs"],
        "connected",
        snapshot["connected"],
        snapshot["failure_classes"][:6],
    )
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(snapshot, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
