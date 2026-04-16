# Contributing to the Known-Server Registry

The mcp-audit known-server registry (`registry/known-servers.json`) is a
community-maintained dataset of legitimate MCP servers. Every entry improves
typosquatting detection for all users.

## When to add an entry

Add a server to the registry if:
- It is a publicly available MCP server package (npm, pip, GitHub, Docker)
- It has a known, identifiable maintainer or organization
- It is not malicious or abandoned

## Entry format

Each entry requires these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Package name as it appears in MCP config (e.g. `@scope/package`) |
| `source` | Yes | One of: `npm`, `pip`, `github`, `docker` |
| `repo` | Required for `verified: true`; recommended for `verified: false` | URL to the source repository (may be `null` for unverified community entries) |
| `maintainer` | Yes | Organization or individual maintaining the package |
| `verified` | Yes | `true` if the maintainer has been confirmed, `false` for community entries |
| `last_verified` | Yes | Date in `YYYY-MM-DD` format |
| `known_versions` | No | List of known stable versions (can be empty list) |
| `tags` | Yes | At least one tag from the vocabulary below |

## Tag vocabulary

Use existing tags where possible to keep the registry consistent:

`official` — published by Anthropic or the MCP project  
`community` — community-maintained  
`filesystem` — file system access  
`database` — database access  
`network` / `remote` — makes network requests or connects to remote services  
`local` — runs entirely on the local machine  
`browser` — browser automation  
`cloud` — cloud provider integration (aws, gcp, azure)  
`search` — search capabilities  
`productivity` — productivity tools (calendar, notes, tasks)  
`monitoring` — observability and monitoring  
`sdk` — SDK or developer tooling  
`demo` — demo or example server  

## How to submit

1. Fork the mcp-audit repository
2. Add your entry to `registry/known-servers.json`
3. Update the `entry_count` field at the top of the file
4. Update `last_updated` to today's date
5. Run `python3 -c "import json; json.load(open('registry/known-servers.json'))"` to confirm valid JSON
6. Open a pull request with the title: `registry: add {package-name}`
7. Maintainer will verify the repo URL and maintainer before merging

## Verification standard

- `verified: true` requires a confirmed link between the package name and
  the repository, and a named maintainer organization
- `verified: false` is acceptable for community entries where the maintainer
  is less clear — these still help typosquatting detection
- `verified: true` entries will not be added without a public source repository
- `verified: false` entries may have `repo: null` if the source is unknown,
  but a repo URL is strongly recommended
