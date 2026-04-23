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

57 entries as of April 2026, covering:

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
- `build.py` passes `(registry/known-servers.json, "registry")` to PyInstaller's
  `--add-data` so the file is available as `sys._MEIPASS/registry/known-servers.json`
  in the standalone binary.

## Known Limitations

See GAPS.md (Supply chain coverage section) for:

- Registry size vs. launch target
- Levenshtein threshold false-positive risk for short package names
