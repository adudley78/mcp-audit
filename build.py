"""Build standalone mcp-audit binaries via PyInstaller."""

import platform
import subprocess
import sys
from pathlib import Path


def build() -> None:
    """Produce a single-file mcp-audit binary for the current platform."""
    root = Path(__file__).parent
    system = platform.system().lower()  # darwin, linux, windows
    arch = platform.machine().lower()  # arm64, x86_64

    name = f"mcp-audit-{system}-{arch}"
    if system == "windows":
        name += ".exe"

    # Data files that must be bundled: (source_path, dest_dir_inside_bundle)
    datas = [
        (str(root / "src" / "mcp_audit" / "data"), "mcp_audit/data"),
    ]
    datas_args: list[str] = []
    for src, dst in datas:
        datas_args.extend(["--add-data", f"{src}:{dst}"])

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        name,
        "--clean",
        "--noconfirm",
        # Hidden imports that PyInstaller static analysis may miss
        "--hidden-import", "mcp_audit.analyzers.poisoning",
        "--hidden-import", "mcp_audit.analyzers.credentials",
        "--hidden-import", "mcp_audit.analyzers.transport",
        "--hidden-import", "mcp_audit.analyzers.supply_chain",
        "--hidden-import", "mcp_audit.analyzers.rug_pull",
        "--hidden-import", "mcp_audit.analyzers.toxic_flow",
        "--hidden-import", "mcp_audit.analyzers.attack_paths",
        "--hidden-import", "mcp_audit.output.terminal",
        "--hidden-import", "mcp_audit.output.sarif",
        "--hidden-import", "mcp_audit.output.nucleus",
        "--hidden-import", "mcp_audit.output.dashboard",
        "--hidden-import", "mcp_audit.watcher",
        *datas_args,
        str(root / "src" / "mcp_audit" / "cli.py"),
    ]

    print(f"Building {name}...")
    subprocess.run(cmd, check=True)  # noqa: S603 — cmd is fully controlled by this script

    output = root / "dist" / name
    size_mb = output.stat().st_size / 1024 / 1024
    print(f"\nBinary built: {output}")
    print(f"Size: {size_mb:.1f} MB")
    print(f"\nTest it: ./dist/{name} scan")


if __name__ == "__main__":
    build()
