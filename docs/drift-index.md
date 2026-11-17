# The weekly drift index

Each week a workflow records what popular MCP servers tell the agent, and what changed since the week before. The result is a public, dated history on the [`drift-history` branch](https://github.com/adudley78/credenzo/tree/drift-history).

## What it measures

One number each week: **of the servers that started on both dates, how many changed their tools.** A change is a tool added, a tool removed, or a tool whose definition is different. Each record also says how many changes came with a new version and how many did not.

## How it works

`.github/workflows/drift-index.yml` runs each Monday.

1. `current_versions.py` (launch study) resolves the version of each corpus package that is current that day.
2. `scripts/drift_snapshot.py` installs each package and starts it. npm installs use `--ignore-scripts` and PyPI installs use wheels only, so no package code runs at install time. Each server runs as an unprivileged user, with no network interface and an empty environment.
3. The script records the lock digests of each tool (`lock/tool_digests.py`), the same digests that `credenzo lock --connect` writes. It publishes digests and tool names. It does not publish tool text.
4. `scripts/drift_compare.py` compares the new snapshot with the one before it.
5. A second job, which runs no package code, commits the two files.

The corpus is the frozen list of the launch study: the npm top 100, 48 PyPI servers and 200 packages from the official MCP Registry. See [`docs/research/2026-12-launch-drift/README.md`](research/2026-12-launch-drift/README.md).

## Files on the branch

| File | Contents |
|---|---|
| `snapshots/YYYY-MM-DD.json` | One row for each package: version, connected or not, tool count, tool digests |
| `index/YYYY-MM-DD.json` | The comparison with the snapshot before: counts, and one row for each server that changed or got a new version |
| `latest-snapshot.json`, `latest.json` | Copies of the newest two files |

Both formats have `schema_version` 1. A change to a field adds a field; it does not rename one.

## One snapshot for each date

The publish job stops when the branch has a snapshot for the date already. A manual run after the scheduled run of the same date publishes nothing.

The first workflow run was on 2026-11-16, the date of the last snapshot of the launch study, and it replaced that snapshot. The study files were put back by hand. That run is kept in `baseline/` on the branch, and `latest-snapshot.json` is a copy of it, so each weekly comparison is between two runs on a GitHub runner.

The two snapshots of that date came from different machines. 2 of 167 servers were different. One had a new version between the two runs. One (`mongodb-mcp-server` 3.3.0) had the same version and listed four more tools on the runner. So the tool list of a server can depend on the machine, and 1 of 167 is the measured size of that effect for this corpus.

## Limits

- About half of the corpus starts with no network and no credentials. A server that needs a key or a service is not measured.
- A server that builds its tool list from data that it fetches at startup shows a different list offline.
- A change with no new version can come from the server's own dependencies, which npm resolves again at each install. The record counts these separately (`changed_without_bump`); read each one before you draw a conclusion.
- The snapshot shows that a tool changed, not that the change is harmful.
