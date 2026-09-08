# Fixture provenance: `keyv_layout/`

Models the repository-resident IDE auto-execution layout used by the
**Keyv npm worm** ("Mini Shai-Hulud" campaign), first reported 2026-08-04
(`keyv@6.0.0`). Reconstructed from published incident-response write-ups
(no direct access to the compromised repository's git history — no commit
SHA is claimed or fabricated here). Sources, all accessed 2026-09-08:

- DeepWatch, ["Supply Chain Compromise Involving keyv and Associated npm
  Packages"](https://www.deepwatch.com/labs/ca-26-030-supply-chain-compromise-involving-keyv-cacheable-and-associated-npm-packages/)
- Phoenix Security, ["Mini Shai-Hulud npm Worm Hits keyv and
  cacheable"](https://phoenix.security/mini-shai-hulud-keyv-cacheable-npm-supply-chain-worm/)
- Upwind, ["Keyv Supply Chain Compromise: An npm Worm That Takes Its Orders
  From an Ethereum Smart
  Contract"](https://www.upwind.io/feed/keyv-supply-chain-compromise-an-npm-worm-that-takes-its-orders-from-an-ethereum-smart-contract)
- Kodem, ["keyv npm Supply Chain Attack | IOCs and
  Runbook"](https://www.kodemsecurity.com/resources/keyv-supply-chain-attack-shai-hulud-npm-worm-affected-versions-iocs-and-first-hour-response-runbook)
- hard2bit, ["keyv npm worm: credential theft and IDE auto-run
  hooks"](https://hard2bit.com/en/blog/npm-worm-keyv-mini-shai-hulud-hooks-claude-code-vscode/)

## What real incident-response reports describe

The compromised package tree carried three independent execution triggers,
only one of which involves `npm install`:

1. A `preinstall` script (`node setup.mjs`) — not reproduced here, out of
   scope for this fixture (mcp-audit does not execute install scripts).
2. `.claude/settings.json` registers a `SessionStart` hook that runs
   `node .vscode/setup.mjs`.
3. `.vscode/tasks.json` registers a task labeled `"Environment Setup"` with
   `"runOptions": {"runOn": "folderOpen"}` that runs
   `node .claude/setup.mjs`.

The two IDE-hook files are deliberately **cross-wired** (each invokes a
script inside the *other* directory) so that deleting only one leaves the
other capable of re-triggering the chain.

## What this fixture contains and why

- `.claude/settings.json` and `.vscode/tasks.json` reproduce the *shape*
  of the two IDE-hook triggers above verbatim (command lines, hook event,
  `runOn` value) — this is the exact detection surface TRUST-003 /
  CFHYG-005 target.
- The `setup.mjs` payload scripts themselves are **not included**: they are
  not read or executed by any code path this fixture exercises
  (`discover_project_autoexec_files()` / `ConfigHygieneAnalyzer` only parse
  the two JSON config files), and reproducing malware payload code serves
  no test purpose. Per the project's fixture-hygiene rule, no live hostname
  or working payload appears anywhere in this fixture.
- The referenced commands (`node .vscode/setup.mjs`, `node
  .claude/setup.mjs`) do not themselves reach the network — the network
  egress reportedly happens *inside* the (unreproduced) payload script, not
  in the hook/task command line — so this fixture is expected to produce
  TRUST-003 at **HIGH**, not CRITICAL. The CRITICAL (network-reaching)
  escalation path is covered separately by synthetic unit tests in
  `tests/test_config_hygiene.py` that construct a command line matching
  `_HOOK_NETWORK_RE` directly.

## Expected findings (`scan --project` against this directory)

- `CFHYG-005` (non-empty `hooks` section in `.claude/settings.json`)
- `TRUST-003` (`.vscode/tasks.json` task with `runOn: folderOpen`) — HIGH

See `tests/test_project_scan.py` for the assertions.
