# Contributing to the Known-Server Registry

The mcp-audit known-server registry (`registry/known-servers.json`) is a
community-maintained dataset of legitimate MCP servers. Every entry improves
typosquatting detection for all users.

**Not listed yet?** Check your current status:

```bash
mcp-audit vet @your-scope/your-package
```

If the output shows `unknown`, your package is not in the registry. Adding it
takes ~5 minutes (see [How to submit](#how-to-submit) below) and:
- Turns your `mcp-audit vet` badge from grey to green.
- Protects users from typosquats that mimic your package name.
- Lets mcp-audit suppress false-positive findings on your server.

See [docs/badge.md](badge.md) for badge documentation.

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

`verified: true` means we have evidence that **the person submitting the
entry controls the package**, not just that a package with that name and a
plausible-looking repo exists. Any one of the following counts:
- The npm/PyPI publishing account is on the project's own domain or org
  (e.g. the maintainer email resolves to the package's own domain).
- The submitter demonstrates write access to the repository the package
  declares — for example, a merged PR whose head branch lives in that repo
  rather than a fork.
- The publishing account itself comments on the submission issue.

`verified: true` entries will not be added without a public source repository.

`verified: false` means the entry is listed and typosquat-protected, but
unconfirmed — this is an ordinary, common outcome, not a rejection. Most
community submissions start here and stay here indefinitely; that's fine.
`repo: null` is acceptable here if the source is unknown, but a repo URL is
strongly recommended.

**What does not count as evidence: a git commit author email.** That field
is self-asserted at commit time and anyone can put anything in it — it
proves nothing about who controls the package or the repo. Submitters
often offer it in good faith, and that's appreciated, but it can't move an
entry from `false` to `true` on its own.

### Upgrading a `verified: false` entry

If your entry is already listed as `verified: false`, you don't need to
resubmit — reply on the original issue (or open a new one referencing it)
with evidence matching one of the bullets above. A maintainer will confirm
it independently and flip `verified` to `true` once it checks out.
