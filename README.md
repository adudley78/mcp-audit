# Drift history

A dated record of what popular MCP servers tell the agent, and what changed between dates. A workflow adds one snapshot and one comparison each week.

- `snapshots/YYYY-MM-DD.json`: one row for each package: version, connected or not, tool count, tool digests.
- `index/YYYY-MM-DD.json`: the comparison with the snapshot before it.
- `latest-snapshot.json`, `latest.json`: copies of the newest two files.

The three snapshots dated 2026-10-22, 2026-10-29 and 2026-11-16 come from the launch drift study. The method, the corpus and the limits are in `docs/drift-index.md` and `docs/research/2026-12-launch-drift/README.md` on the `main` branch.

## The baseline of 2026-11-16

The weekly workflow ran for the first time on 2026-11-16, the same date as the last snapshot of the launch study. The study snapshot was made on a different machine. The two files in `baseline/` are that first workflow run and its comparison with the study snapshot of the same date:

- `baseline/2026-11-16-github-runner.json`: the snapshot from the GitHub runner. `latest-snapshot.json` is a copy of it, so each weekly comparison is between two runs on the same type of machine.
- `baseline/2026-11-16-same-day-comparison.json`: 2 of 167 servers were different between the two machines on one date. One had a new version in the hours between the runs. One had the same version and listed four more tools on the runner, so its tool list depends on the machine.

This is the measured noise of a change of machine: 1 of 167 servers with the same version. `snapshots/2026-11-16.json` and `index/2026-11-16.json` are the study files.

The files hold digests and tool names. They do not hold tool text. A change means that a tool was added, removed or redefined. It does not mean that the change is harmful.

Licence: Apache 2.0, the same as the repository.
