# Fixture: `benign/`

Synthetic (not copied from a real artifact). An ordinary `.vscode/tasks.json`
(build/test tasks, no `runOn: folderOpen`) and `.vscode/settings.json`
(editor preferences and a `${workspaceFolder}`-relative interpreter path
only) — the negative control for `keyv_layout/`. Scanning this directory
under `scan --project` must produce zero TRUST-003 / CFHYG-005 / HOOK-001/002
findings.
