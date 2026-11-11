"""Write the pre-STORY-0151 guardrail records this directory holds. Dev only.

Run once, with mcp-audit 0.29.0 (commit a567767, before STORY-0151) on the
path, from the repository root::

    PYTHONPATH=<checkout of v0.29.0>/src python3 \
        tests/fixtures/guardrails_v0290/make_fixture.py

It writes ``files/``: three repository settings files whose permission rules
hold secrets the 0.29.0 record redaction missed (stored under plain names, so
no ``.claude/settings.json`` in this repository holds a secret; the test puts
them back in place with :data:`LAYOUT`) and ``mcp-lock.json`` (what
``mcp-audit lock <repo> --offline`` wrote for them) and ``state.json`` (the
``guardrails.json`` 0.29.0 wrote, its keys made relative to ``repo/``).
``tests/test_guardrail_redaction_upgrade.py`` reads them to prove that
upgrading reports no GUARD-001/002 and no LOCK-014.  The secret values are
synthetic.  Never imported by mcp-audit and not run by the tests.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = HERE / "files"
#: Fixture file name -> where it sits in the repository.
LAYOUT = {
    "claude-settings.json": ".claude/settings.json",
    "gemini-settings.json": ".gemini/settings.json",
    "codex-config.toml": ".codex/config.toml",
    "mcp-lock.json": "mcp-lock.json",
}

PG = "Zq7pW3xLm9"  # noqa: S105 — synthetic
SECRETS = {
    "pg": PG,
    "db": "Rk2vN8sYt4",
    "auth": "aXt5Lq2Wp8Zr",
    "erp": "9f8e7d6c5b4a",
    "bearer": "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0.Vm2kq",
}
LONG = (
    "Bash(PGPASSWORD="
    + SECRETS["db"]
    + " psql "
    + " ".join(f"-c 'select {i}'" for i in range(60))
    + ")"
)
CLAUDE = {
    "permissions": {
        "allow": [
            f"Bash(PGPASSWORD={PG} psql -h db -U app)",
            f"Bash(DB_PASSWD={SECRETS['db']} ./migrate)",
            f"Bash(npm config set //registry.npmjs.org/:_authToken={SECRETS['auth']})",
            "Bash(curl -H 'Authorization: token admin:"
            + SECRETS["erp"]
            + "' https://erp.example)",
            'Bash(curl -H "Authorization: Bearer '
            + SECRETS["bearer"]
            + '" https://api.example)',
            "Bash(PGPASSWORD=$PGPASS psql)",
            'Bash(curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" x)',
            "Bash(npm run build)",
            "Read(./src/**)",
            "WebFetch(domain:docs.example.com)",
            LONG,
        ],
        "ask": [f"Bash(rm PGPASSWORD={PG} *)"],
        "deny": ["Read(./.env)", f"Bash(mysql -pPASSWORD={PG})"],
        "additionalDirectories": ["../shared"],
        "defaultMode": "acceptEdits",
    },
    "sandbox": {
        "enabled": True,
        "excludedCommands": [f"PGPASSWORD={PG} pg_dump", "docker"],
        "network": {"allowedDomains": ["api.example.com", "*.npmjs.org"]},
    },
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "./guard.sh"}]}
        ]
    },
}
GEMINI = {
    "tools": {
        "allowed": [
            f"run_shell_command(PGPASSWORD={PG} psql)",
            "run_shell_command(git status)",
        ]
        # 2,100 entries: past the 2,000-entry cut, so the record has a digest.
        + [f"run_shell_command(task-{i:04d})" for i in range(2100)],
        "exclude": ["run_shell_command(rm -rf /)"],
    },
    "general": {"defaultApprovalMode": "default"},
}
CODEX = (
    'approval_policy = "on-request"\n'
    'sandbox_mode = "workspace-write"\n'
    "[sandbox_workspace_write]\n"
    "network_access = false\n"
    f'writable_roots = ["/tmp/PGPASSWORD={PG}", "/srv/build"]\n'
)


def main() -> int:
    from mcp_audit import __version__, guardrails

    if __version__ != "0.29.0":
        print(f"needs mcp-audit 0.29.0 on the path, found {__version__}")
        return 2
    tmp_root = Path(tempfile.mkdtemp())
    repo = tmp_root / "repo"
    (repo / ".claude").mkdir(parents=True)
    (repo / ".gemini").mkdir()
    (repo / ".codex").mkdir()
    (repo / ".claude" / "settings.json").write_text(json.dumps(CLAUDE, indent=1))
    (repo / ".gemini" / "settings.json").write_text(json.dumps(GEMINI, indent=1))
    (repo / ".codex" / "config.toml").write_text(CODEX)
    state = tmp_root / "guardrails.json"
    errors: list[str] = []
    files = guardrails.project_guardrail_files(repo, errors)
    guardrails.guardrail_drift_findings(files, state, errors)
    raw = json.loads(state.read_text())
    base = os.path.normcase(str(repo.resolve()))
    # The state file keys records by absolute path; keep them relative.
    raw["files"] = {
        Path(os.path.relpath(key, base)).as_posix(): value
        for key, value in raw["files"].items()
    }
    (HERE / "state.json").write_text(json.dumps(raw, indent=1, sort_keys=True) + "\n")
    env = dict(os.environ, HOME=str(tmp_root / "home"))
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_audit.cli", "lock", str(repo), "--offline"],
        check=True,
        env=env,
    )
    FILES.mkdir(exist_ok=True)
    for name, rel in LAYOUT.items():
        shutil.copy(repo / rel, FILES / name)
    shutil.rmtree(tmp_root, ignore_errors=True)
    print("wrote", FILES, HERE / "state.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
