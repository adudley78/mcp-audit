# Drift history

A dated record of what popular MCP servers tell the agent, and what changed between dates. A workflow adds one snapshot and one comparison each week.

- `snapshots/YYYY-MM-DD.json`: one row for each package: version, connected or not, tool count, tool digests.
- `index/YYYY-MM-DD.json`: the comparison with the snapshot before it.
- `latest-snapshot.json`, `latest.json`: copies of the newest two files.

The three snapshots dated 2026-10-22, 2026-10-29 and 2026-11-16 come from the launch drift study. The method, the corpus and the limits are in `docs/drift-index.md` and `docs/research/2026-12-launch-drift/README.md` on the `main` branch.

The files hold digests and tool names. They do not hold tool text. A change means that a tool was added, removed or redefined. It does not mean that the change is harmful.

Licence: Apache 2.0, the same as the repository.
