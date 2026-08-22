# Known-Server Registry

mcp-audit ships with a curated registry of known-legitimate MCP servers used
by the supply chain analyzer for typosquatting detection.

## Registry Location

The bundled registry ships at `registry/known-servers.json` in the repo root
and is embedded in both the pip-installable wheel and the PyInstaller standalone
binary.

A user-local cache can be maintained at:

```
~/.config/mcp-audit/registry/known-servers.json
```

## Resolution Order

When the supply chain analyzer loads the registry, it searches in this order:

1. **`--registry PATH`** — explicit path passed to `mcp-audit scan`
2. **User-local cache** — `~/.config/mcp-audit/registry/known-servers.json`
   (written by `mcp-audit update-registry`)
3. **PyInstaller bundle** — `sys._MEIPASS/registry/known-servers.json`
4. **Installed wheel** — located via `importlib.resources` inside the
   `mcp_audit.registry` package
5. **Dev / editable install fallback** — `registry/known-servers.json`
   relative to the repo root

## Updating the Registry

```
mcp-audit update-registry
```

Fetches the latest registry from the mcp-audit GitHub repository and saves it
to the user-local cache. On the next scan, the updated registry is used
automatically.

On failure (network error, malformed JSON), the command prints an error and
exits with code 2. The existing cached registry is never overwritten on failure.

## Using a Custom Registry

```
mcp-audit scan --registry /path/to/my-registry.json
```

Overrides both the bundled and cached registry for a single scan run. Useful
for testing custom entry sets or running offline with a pre-fetched registry.

## Registry Format

`known-servers.json` has this top-level structure:

```json
{
  "schema_version": "1.0",
  "last_updated": "2026-04-15",
  "entry_count": 57,
  "entries": [ ... ]
}
```

Each entry follows this schema:

```json
{
  "name": "@modelcontextprotocol/server-filesystem",
  "source": "npm",
  "repo": "https://github.com/modelcontextprotocol/servers",
  "maintainer": "Anthropic",
  "verified": true,
  "last_verified": "2026-04-15",
  "known_versions": [],
  "tags": ["official", "filesystem", "local"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Exact package name as published (npm, pip, etc.) |
| `source` | enum | `npm` \| `pip` \| `github` \| `docker` |
| `repo` | string \| null | Canonical source repository URL |
| `maintainer` | string | Organisation or `"community"` |
| `verified` | bool | `true` for entries with confirmed publisher identity |
| `last_verified` | ISO date | Date the entry was last reviewed |
| `known_versions` | list | Pinned versions (empty = all versions accepted) |
| `tags` | list | Descriptive labels, e.g. `official`, `database`, `remote` |

## Current Coverage

64 entries as of April 2026, covering:

- **22 official Anthropic/MCP packages** — all `@modelcontextprotocol/server-*`
  npm packages, the Python SDK (`mcp`), and related tooling
- **35 community packages** — high-profile servers from Upstash, Supabase,
  Cloudflare, Stripe, Browserbase, and community-maintained integrations

## Contributing to the Registry

To add a server, open a pull request against the mcp-audit repository editing
`registry/known-servers.json`. Guidelines:

- **Verified entries** (`"verified": true`) require a link to the official
  repository and a named maintainer with a verifiable presence.
- **Community entries** (`"verified": false`) should include the npm/pip
  package name exactly as published. The `repo` field can be `null` if unknown.
- Increment `entry_count` to match the actual number of entries in the array.
- Set `last_verified` to the ISO date of your review.

## Auditing the registry

`scripts/audit_registry.py` re-checks every entry against the live npm / PyPI
registries. **Default is read-only** — it prints a report and writes
`.registry_audit_raw.json` (gitignored). It never adds or removes entries.

```
python scripts/audit_registry.py
python scripts/audit_registry.py --refresh          # ignore the local cache
python scripts/audit_registry.py --stamp            # write field updates
python scripts/audit_registry.py --stamp --date 2026-08-22
```

### Buckets

| Bucket | Meaning |
|--------|---------|
| `OK` | Package exists in its declared ecosystem and the registry `repo` matches the package's own metadata (after URL normalization). |
| `MISSING` | Package does not exist (404). The registry is vouching for a name anyone could register. |
| `UNCLAIMABLE_MISMATCH` | Package exists, but its declared repository does not match ours (or ours is `null` while the package points somewhere identifiable). |
| `THIN` | Package exists but looks like a placeholder (version `0.0.x` and/or very low recent downloads). |
| `UNCHECKED` | Network / rate-limit / ambiguous data. Never guessed. |

`--stamp` sets `last_verified` to today's date **only** on entries this run
classified as `OK`. Non-OK entries are left alone — the field is published as
`entry_updated` on mcp-audit.dev, so it must mean this run actually verified
the package.

### `attestation_expected`

The flag turns a missing Sigstore attestation from a neutral absence into a
MEDIUM finding (`ATTEST-013`). A `true` that the package does not actually
publish is the same class of defect as vouching for a nonexistent name.

On `--stamp`, for every entry currently `attestation_expected: true`:

| Provenance class | Action |
|------------------|--------|
| `HAS_PROVENANCE` | Leave `true` (npm `dist.attestations` SLSA, or PyPI PEP 740 integrity API). |
| `NO_PROVENANCE` | Set to `false`. |
| `UNCHECKED` | Leave `true` and list the name — unverifiable is not the same as false. |

The script **never** sets `attestation_expected: true`. Weak evidence (for
example an npm publish attestation without an SLSA provenance predicate)
classifies as `NO_PROVENANCE`.

Do **not** wire `--stamp` to an unattended CI cron. Packages disappearing is a
real event; a nightly job that mutates the registry without a human looking at
the buckets is its own hazard. A read-only scheduled run that **fails** on
`MISSING` or on `attestation_expected` + `NO_PROVENANCE` is the useful check;
a human then runs `--stamp`.

## Implementation Notes

- `src/mcp_audit/registry/loader.py` — `KnownServerRegistry` class,
  `RegistryEntry` Pydantic model, `load_registry()` convenience function, and
  a standalone `levenshtein()` implementation used for typosquatting distance
  calculations.
- `SupplyChainAnalyzer` accepts `registry=KnownServerRegistry` or
  `registry_path=Path` in its constructor, enabling direct injection in tests
  without touching the filesystem.
- The `pyproject.toml` `[tool.hatch.build.targets.wheel.force-include]` section
  copies `registry/known-servers.json` into the wheel at
  `mcp_audit/registry/known-servers.json` so `importlib.resources` resolves it
  correctly in installed packages.
- Each PyInstaller spec passes `(registry/known-servers.json, "registry")` in
  `datas=` so the file is available as `sys._MEIPASS/registry/known-servers.json`
  in the standalone binary.

## Known Limitations

See GAPS.md (Supply chain coverage section) for:

- Registry size vs. launch target
- Levenshtein threshold false-positive risk for short package names
