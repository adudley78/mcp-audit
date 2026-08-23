# mcp-audit advisory feed

This branch is the published destination for the mcp-audit advisory feed. It
contains **only** the feed — no source, no history from `main` — and is
rewritten in place by `.github/workflows/advisory-feed-publish.yml` on
`main`.

This feed is currently **unsigned**. See
[`docs/advisory-feed.md`](https://github.com/adudley78/mcp-audit/blob/main/docs/advisory-feed.md)
on `main` for the record format, freshness model, and the signing design
that will land here later without changing anything already published.

## Fetch it

```bash
mkdir feed && cd feed
curl -fsSLO https://raw.githubusercontent.com/adudley78/mcp-audit/feed/index.json
# then fetch advisories/<id>.json for each entry index.json lists, and osv/ as needed
```

## Verify it

```bash
mcp-audit feed verify ./feed
```

## Layout

```
index.json           every advisory summarised + freshness (snapshot_version, published_at, expires)
advisories/<id>.json  one OSV 1.6.0 record per advisory
osv/all.json          every record as a flat JSON array
osv/all.zip           every record, zipped
osv/osv-scanner/      osv-scanner offline-database layout (npm/, PyPI/)
```
