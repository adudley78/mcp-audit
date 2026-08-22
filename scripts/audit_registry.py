#!/usr/bin/env python3
"""Audit every entry in registry/known-servers.json against the live npm/PyPI
registries and classify each one into a trust bucket.

Default mode is **report-only**: it never modifies ``registry/known-servers.json``.
Pass ``--stamp`` to write back two field updates after a successful run:

* ``last_verified`` → today's date, **only** for entries this run classified
  as OK. Unverified / THIN / MISSING entries are left alone.
* ``attestation_expected`` → ``false`` for every flagged entry whose latest
  release has **no** Sigstore/SLSA/PEP 740 provenance. HAS_PROVENANCE is left
  true. UNCHECKED (network/API failure) is left true and listed — an
  unverifiable claim is not the same as a false one. This script never sets
  ``attestation_expected: true``.

Why this exists: a batch of ~26 "community" entries with ``repo: null`` was
added to the registry without ever being checked against the real package
registries. mcp-audit *vouches* for every name in this file (the supply-chain
analyzer treats it as "this is a known-legitimate MCP server"), so an
unverified name is not a neutral gap — it is a claim someone could exploit by
registering that exact name with malicious code. ``attestation_expected: true``
is the same class of claim one layer down: it turns a missing Sigstore
attestation into a MEDIUM finding for every user who scans that package.

Re-run this script whenever new entries are added, or periodically as a drift
check on existing ones. Default is read-only. Stamping is opt-in.

Buckets
-------
OK
    Package exists in its declared ecosystem AND the registry's ``repo``
    field matches the package's own declared repository (allowing for
    reasonable normalization: trailing slash, ``.git`` suffix, http vs
    https, github.com case).
MISSING
    Package does not exist in its declared ecosystem (404). This is the most
    serious bucket: the registry is vouching for a name nobody has claimed,
    which anyone (including an attacker) could register.
UNCLAIMABLE_MISMATCH
    Package exists but its declared repository does not match our ``repo``
    field, OR our ``repo`` is null while the package's own metadata points
    somewhere identifiable.
THIN
    Package exists but looks like a placeholder: version 0.0.x, and/or very
    low (or zero) recent download counts.
UNCHECKED
    Could not be determined (network failure, rate-limit block that survived
    the retry, or ambiguous data). Never guessed or fabricated.

Provenance (only entries with ``attestation_expected: true``)
-------------------------------------------------------------
HAS_PROVENANCE
    Latest npm version has ``dist.attestations.provenance`` (SLSA) and/or the
    npm attestations API returns an SLSA provenance predicate; or the PyPI
    integrity API returns PEP 740 ``attestation_bundles`` for a release file.
    The JSON packument on PyPI does **not** expose a ``provenance`` field —
    absence there is not evidence, so we query ``/integrity/.../provenance``.
NO_PROVENANCE
    Latest release was fetched successfully and no SLSA/PEP 740 attestation
    is present (npm attestations API 404 / empty, or PyPI integrity 404).
UNCHECKED
    Network failure or missing version/filename so we could not tell.

Usage
-----
    python scripts/audit_registry.py
    python scripts/audit_registry.py --refresh          # ignore local cache
    python scripts/audit_registry.py --out /tmp/out.json
    python scripts/audit_registry.py --stamp            # opt-in write of field updates

The on-disk cache (``.registry_audit_cache.json`` at the repo root, gitignored)
lets re-runs skip packages already checked within the cache TTL, so repeated
runs during report-writing don't hammer the public registries.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field, fields
from datetime import date
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).parent.parent
REGISTRY_PATH = REPO_ROOT / "registry" / "known-servers.json"
DEFAULT_CACHE_PATH = REPO_ROOT / ".registry_audit_cache.json"
DEFAULT_OUT_PATH = REPO_ROOT / ".registry_audit_raw.json"

USER_AGENT = (
    "mcp-audit-registry-audit/1.0 "
    "(+https://github.com/adudley78/mcp-audit; registry integrity audit script)"
)

REQUEST_DELAY_SECONDS = 0.4
RATE_LIMIT_BACKOFF_SECONDS = 3.0
NETWORK_ERROR_BACKOFF_SECONDS = 2.0
MAX_RETRIES = 1  # one retry after backoff, then give up and mark unchecked
CACHE_TTL_SECONDS = 6 * 3600  # re-check anything older than 6 hours on rerun

THIN_VERSION_RE = re.compile(r"^0\.0\.\d+$")
THIN_DOWNLOAD_THRESHOLD = 50  # monthly downloads below this is a THIN signal

# Tiered so an explicit "Repository"/"Source" project_urls key always wins
# over a generic "Homepage" — PyPI's own convention (see PEP 621) is that
# "Homepage" is a project's marketing/docs page, not necessarily its VCS
# repo, and several real official packages (e.g. the `mcp` SDK) list both
# with different targets. "homepage" is intentionally a separate, lower
# tier, tried only if nothing more specific is present.
_REPO_KEY_HINT_TIERS: tuple[tuple[str, ...], ...] = (
    ("source", "repository", "repo", "code"),
    ("github", "gitlab"),
    ("homepage",),
)


# ── HTTP plumbing ──────────────────────────────────────────────────────────


def _sleep(seconds: float = REQUEST_DELAY_SECONDS) -> None:
    time.sleep(seconds)


def _get_json(url: str, timeout: int = 15) -> tuple[int, Any]:
    """GET *url*, returning ``(status_code, parsed_json_or_None)``.

    Never raises for expected HTTP outcomes (404, 429, 5xx, network errors).
    Retries once on 429 / transient network failure, then gives up.
    """
    # S310: url is always one of this script's own hardcoded https:// registry
    # endpoints (registry.npmjs.org / pypi.org / api.npmjs.org) built from a
    # package name — never user-controlled scheme/host.
    req = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    attempt = 0
    while True:
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                status = resp.getcode()
                body = resp.read()
            data = json.loads(body) if body else None
            return status, data
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return 404, None
            if exc.code == 429 and attempt < MAX_RETRIES:
                attempt += 1
                _sleep(RATE_LIMIT_BACKOFF_SECONDS)
                continue
            return exc.code, None
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt < MAX_RETRIES:
                attempt += 1
                _sleep(NETWORK_ERROR_BACKOFF_SECONDS)
                continue
            return -1, None
        except json.JSONDecodeError:
            return -2, None


# ── Repo URL normalization ─────────────────────────────────────────────────


def normalize_repo_url(url: str | None) -> str | None:
    """Normalize a repository URL for tolerant comparison.

    Strips ``git+`` prefixes, converts ``git://``/``ssh://``/scp-like
    (``git@host:path``) forms to ``https://``, downgrades ``http`` to
    ``https``, strips a trailing ``.git`` suffix and trailing slash, and
    lowercases the host (and, for github.com specifically, the path too,
    since GitHub repo paths are case-insensitive).
    """
    if not url:
        return None
    u = url.strip()
    u = re.sub(r"^git\+", "", u)
    u = re.sub(r"^git://", "https://", u)
    u = re.sub(r"^ssh://git@", "https://", u)
    u = re.sub(r"^git@([^:/]+):", r"https://\1/", u)
    u = re.sub(r"^http://", "https://", u)
    if not re.match(r"^https://", u):
        # Not a recognizable git-ish URL (e.g. a bare npm "homepage" string
        # that isn't a repo at all) — return as-is, lowercased, for comparison.
        return u.rstrip("/").lower()
    u = u.rstrip("/")
    if u.endswith(".git"):
        u = u[: -len(".git")]
    parsed = urllib.parse.urlsplit(u)
    netloc = parsed.netloc.lower()
    path = parsed.path
    if netloc in ("github.com", "www.github.com"):
        netloc = "github.com"
        path = path.lower()
    return f"https://{netloc}{path}"


def repos_match(a: str | None, b: str | None) -> bool:
    """Return True if two repo URLs are equal after normalization.

    Also treats a deep link into a subdirectory of the same repository (e.g.
    ``.../tree/main/src/fetch``) as a match — common for monorepos where a
    package's own metadata points at its specific subfolder rather than the
    repo root the registry cites.
    """
    na, nb = normalize_repo_url(a), normalize_repo_url(b)
    if na is None or nb is None:
        return False
    if na == nb:
        return True
    shorter, longer = sorted((na, nb), key=len)
    return longer.startswith(shorter + "/")


# ── Result data model ───────────────────────────────────────────────────────


@dataclass
class EcosystemCheck:
    ecosystem: str  # "npm" | "pypi"
    name: str
    checked: bool = True
    exists: bool = False
    status_code: int | None = None
    error: str | None = None
    latest_version: str | None = None
    created_or_earliest_release: str | None = None
    maintainers: list[str] = field(default_factory=list)
    author: str | None = None
    repo_url: str | None = None
    description: str | None = None
    monthly_downloads: int | None = None
    dist_attestations: Any = None
    pypi_filenames: list[str] = field(default_factory=list)
    # HAS_PROVENANCE | NO_PROVENANCE | UNCHECKED | NOT_CHECKED
    provenance: str = "NOT_CHECKED"
    provenance_detail: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ── npm ──────────────────────────────────────────────────────────────────


def check_npm(name: str) -> EcosystemCheck:
    """Query registry.npmjs.org for *name* (scoped names are URL-encoded)."""
    encoded = name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded}"
    status, data = _get_json(url)
    _sleep()

    result = EcosystemCheck(ecosystem="npm", name=name, status_code=status)

    if status == 404:
        result.exists = False
        return result
    if status != 200 or data is None:
        result.checked = False
        result.error = f"http_{status}"
        return result

    dist_tags = data.get("dist-tags") or {}
    latest = dist_tags.get("latest")
    result.latest_version = latest

    time_map = data.get("time") or {}
    created = time_map.get("created")
    result.created_or_earliest_release = created[:10] if created else None

    # An npm name with no dist-tags but an "unpublished" time entry was
    # published once and then fully unpublished. npm frees such names for
    # reuse (unless the package had very high download counts in the 24h
    # before unpublish), so it is functionally CLAIMABLE again — same
    # practical risk as a 404, not a live, installable package. Treat it as
    # not-existing rather than silently reporting a stale "exists".
    if not latest and "unpublished" in time_map:
        result.exists = False
        result.error = "unpublished"
        return result

    result.exists = True

    versions = data.get("versions") or {}
    latest_meta = versions.get(latest, {}) if latest else {}

    repo = latest_meta.get("repository") or data.get("repository")
    if isinstance(repo, dict):
        result.repo_url = repo.get("url")
    elif isinstance(repo, str):
        result.repo_url = repo

    result.description = latest_meta.get("description") or data.get("description")

    maint_source = latest_meta.get("maintainers") or data.get("maintainers") or []
    names = sorted(
        {m.get("name") for m in maint_source if isinstance(m, dict) and m.get("name")}
    )
    result.maintainers = names

    # One extra polite call for a download-count THIN signal.
    dl_status, dl_data = _get_json(
        f"https://api.npmjs.org/downloads/point/last-month/{encoded}"
    )
    _sleep()
    if dl_status == 200 and isinstance(dl_data, dict):
        result.monthly_downloads = dl_data.get("downloads")

    result.dist_attestations = latest_meta.get("dist", {}).get("attestations")

    return result


# ── PyPI ─────────────────────────────────────────────────────────────────


def check_pypi(name: str) -> EcosystemCheck:
    """Query pypi.org JSON API for *name*."""
    url = f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
    status, data = _get_json(url)
    _sleep()

    result = EcosystemCheck(ecosystem="pypi", name=name, status_code=status)

    if status == 404:
        result.exists = False
        return result
    if status in (403, 429) or status != 200 or data is None:
        result.checked = False
        result.error = f"http_{status}"
        return result

    result.exists = True
    info = data.get("info") or {}
    result.latest_version = info.get("version")
    result.author = info.get("author") or info.get("maintainer") or None
    if info.get("maintainer") and info.get("maintainer") != result.author:
        result.maintainers = [info["maintainer"]]
    elif info.get("author"):
        result.maintainers = [info["author"]]

    project_urls: dict[str, str] = info.get("project_urls") or {}
    repo_url: str | None = None
    for tier in _REPO_KEY_HINT_TIERS:
        for key, val in project_urls.items():
            if val and any(hint in key.lower() for hint in tier):
                repo_url = val
                break
        if repo_url:
            break
    if not repo_url and info.get("home_page"):
        repo_url = info["home_page"]
    result.repo_url = repo_url
    result.description = (info.get("summary") or "")[:200] or None

    releases = data.get("releases") or {}
    earliest: str | None = None
    for files in releases.values():
        for f in files:
            upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
            if upload_time:
                d = upload_time[:10]
                if earliest is None or d < earliest:
                    earliest = d
    result.created_or_earliest_release = earliest

    urls = data.get("urls") or []
    result.pypi_filenames = [
        u["filename"] for u in urls if isinstance(u, dict) and u.get("filename")
    ]

    return result


# ── Provenance (Sigstore / SLSA / PEP 740) ─────────────────────────────────


def _slsa_predicate(predicate_type: str | None) -> bool:
    return bool(predicate_type) and predicate_type.startswith(
        "https://slsa.dev/provenance/"
    )


def check_npm_provenance(
    name: str, version: str | None, dist_attestations: Any
) -> tuple[str, str]:
    """Classify npm provenance for *name*@*version*.

    Reads ``dist.attestations`` from the packument first (what npm actually
    ships on the version document). If that is absent, queries the
    attestations API. SLSA provenance counts; a publish-only attestation
    without SLSA does not — ``attestation_expected`` means Sigstore
    provenance, not merely ``npm publish --provenance``-adjacent signatures.
    """
    if not version:
        return "UNCHECKED", "no latest version"
    if isinstance(dist_attestations, dict):
        provenance = dist_attestations.get("provenance")
        if isinstance(provenance, dict) and _slsa_predicate(
            provenance.get("predicateType")
        ):
            return "HAS_PROVENANCE", "dist.attestations.provenance"
    encoded = name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/-/npm/v1/attestations/{encoded}@{version}"
    status, data = _get_json(url)
    _sleep()
    if status == 404:
        return "NO_PROVENANCE", "attestations API 404"
    if status != 200 or not isinstance(data, dict):
        return "UNCHECKED", f"attestations API http_{status}"
    predicates = [
        a.get("predicateType")
        for a in (data.get("attestations") or [])
        if isinstance(a, dict)
    ]
    if any(_slsa_predicate(p) for p in predicates):
        return "HAS_PROVENANCE", "attestations API SLSA"
    return "NO_PROVENANCE", "attestations API has no SLSA provenance"


def check_pypi_provenance(
    name: str, version: str | None, filenames: list[str]
) -> tuple[str, str]:
    """Classify PyPI PEP 740 provenance via the integrity API.

    The JSON project API does not expose a ``provenance`` field on files
    (observed 2026-08-22: the key is absent / always null). Absence there is
    not evidence. Query ``/integrity/{name}/{version}/{filename}/provenance``.
    """
    if not version:
        return "UNCHECKED", "no latest version"
    if not filenames:
        return "UNCHECKED", "no release filenames"
    # Wheel first — PEP 740 is typically on every file of a release, but a
    # 404 on the sdist alone is not enough to declare absence.
    ordered = [f for f in filenames if f.endswith(".whl")] + [
        f for f in filenames if not f.endswith(".whl")
    ]
    last_404: str | None = None
    for filename in ordered:
        quoted = urllib.parse.quote(filename)
        url = (
            f"https://pypi.org/integrity/{urllib.parse.quote(name)}/"
            f"{urllib.parse.quote(version)}/{quoted}/provenance"
        )
        status, data = _get_json(url)
        _sleep()
        if status == 404:
            last_404 = filename
            continue
        if status != 200 or not isinstance(data, dict):
            return "UNCHECKED", f"integrity API http_{status} for {filename}"
        bundles = data.get("attestation_bundles") or []
        if bundles and isinstance(bundles[0], dict) and bundles[0].get("attestations"):
            return "HAS_PROVENANCE", f"PEP 740 attestation_bundles on {filename}"
        return "NO_PROVENANCE", f"integrity API 200 but empty bundles for {filename}"
    return "NO_PROVENANCE", f"integrity API 404 for {last_404}"


def fill_provenance(check: EcosystemCheck) -> None:
    """Set ``check.provenance`` from npm or PyPI. Mutates *check*."""
    if check.ecosystem == "npm":
        status, detail = check_npm_provenance(
            check.name, check.latest_version, check.dist_attestations
        )
    elif check.ecosystem == "pypi":
        status, detail = check_pypi_provenance(
            check.name, check.latest_version, check.pypi_filenames
        )
    else:
        status, detail = "UNCHECKED", f"unknown ecosystem {check.ecosystem}"
    check.provenance = status
    check.provenance_detail = detail


# ── Classification ──────────────────────────────────────────────────────────


def _effective_ecosystems(entry: dict) -> list[str]:
    """Determine which ecosystem(s) to check for a registry entry.

    Mirrors ``RegistryEntry.package_ecosystem`` default resolution in
    ``registry/loader.py``: explicit ``package_ecosystem`` wins; otherwise
    ``pip`` source implies ``pypi`` and everything else implies ``npm``.
    ``"any"`` checks both pools.
    """
    eco = entry.get("package_ecosystem")
    if eco == "any":
        return ["npm", "pypi"]
    if eco in ("npm", "pypi"):
        return [eco]
    return ["pypi"] if entry.get("source") == "pip" else ["npm"]


def _plausible_maintainer(pkg_name: str, maintainers: list[str]) -> bool | None:
    """Heuristic: does any maintainer/publisher account name plausibly relate
    to the vendor implied by the package name?

    Returns ``None`` when there isn't enough signal to say either way (no
    maintainers data, or a fully generic name with no vendor token).
    """
    if not maintainers:
        return None
    tokens = [
        t
        for t in re.split(r"[-_.@/]", pkg_name.lower())
        if t and t not in ("mcp", "server", "servers", "com", "the")
    ]
    if not tokens:
        return None
    for m in maintainers:
        m_lower = m.lower()
        for t in tokens:
            if len(t) >= 3 and (t in m_lower or m_lower in t):
                return True
    return False


def classify(entry: dict, checks: list[EcosystemCheck]) -> dict:
    """Classify one registry entry given its ecosystem check result(s).

    Returns a dict with ``bucket``, ``evidence`` (list[str] of citable facts),
    and ``plausible_maintainer`` (bool | None, only meaningful for the
    community/repo-null block).
    """
    evidence: list[str] = []

    performed = [c for c in checks if c is not None]
    any_checked = any(c.checked for c in performed)
    any_exists = any(c.exists for c in performed if c.checked)

    if not any_checked:
        errs = ", ".join(f"{c.ecosystem}:{c.error}" for c in performed)
        return {
            "bucket": "UNCHECKED",
            "evidence": [f"Network/registry error prevented verification ({errs})."],
            "plausible_maintainer": None,
        }

    if not any_exists:
        for c in performed:
            if not c.checked:
                continue
            if c.error == "unpublished":
                evidence.append(
                    f"{c.ecosystem} package {c.name!r} was published once and fully "
                    "unpublished — no installable version remains, and the name is "
                    "free for anyone to re-register. Same practical risk as a 404."
                )
            else:
                evidence.append(
                    f"{c.ecosystem} registry returned 404 for {c.name!r} — "
                    "no such package exists."
                )
        return {"bucket": "MISSING", "evidence": evidence, "plausible_maintainer": None}

    # At least one ecosystem check found the package. Use the first that exists.
    primary = next(c for c in performed if c.checked and c.exists)

    registry_repo = entry.get("repo")
    pkg_repo = primary.repo_url
    plausible = _plausible_maintainer(entry["name"], primary.maintainers)

    mismatch = False
    if registry_repo and pkg_repo:
        if not repos_match(registry_repo, pkg_repo):
            mismatch = True
            evidence.append(
                f"Registry declares repo={registry_repo!r} but {primary.ecosystem} "
                f"metadata for {primary.name!r} declares repo={pkg_repo!r} — mismatch."
            )
    elif not registry_repo and pkg_repo:
        # Only treat as a mismatch if the package's own repo is an
        # identifiable, non-trivial URL (not e.g. a bare domain placeholder).
        mismatch = True
        evidence.append(
            f"Registry has repo=null, but {primary.ecosystem} metadata for "
            f"{primary.name!r} declares repo={pkg_repo!r} (maintainer(s): "
            f"{', '.join(primary.maintainers) or 'unknown'})."
        )

    if mismatch:
        if plausible is False:
            evidence.append(
                f"Publisher account(s) {primary.maintainers} show no plausible "
                f"relationship to the vendor implied by {entry['name']!r} — red flag."
            )
        return {
            "bucket": "UNCLAIMABLE_MISMATCH",
            "evidence": evidence,
            "plausible_maintainer": plausible,
        }

    # No mismatch detected — check THIN signals.
    thin_reasons: list[str] = []
    if primary.latest_version and THIN_VERSION_RE.match(primary.latest_version):
        thin_reasons.append(
            f"latest version is {primary.latest_version!r} (placeholder-shaped)."
        )
    if (
        primary.monthly_downloads is not None
        and primary.monthly_downloads < THIN_DOWNLOAD_THRESHOLD
    ):
        thin_reasons.append(
            f"only {primary.monthly_downloads} downloads in the last month."
        )

    if thin_reasons:
        evidence.append(
            f"{primary.ecosystem} package {primary.name!r} exists (version "
            f"{primary.latest_version}) but " + " ".join(thin_reasons)
        )
        return {
            "bucket": "THIN",
            "evidence": evidence,
            "plausible_maintainer": plausible,
        }

    if registry_repo and pkg_repo:
        evidence.append(
            f"{primary.ecosystem} package {primary.name!r} exists, version "
            f"{primary.latest_version}, repo confirmed matching registry "
            f"({registry_repo!r})."
        )
    elif registry_repo and not pkg_repo:
        evidence.append(
            f"{primary.ecosystem} package {primary.name!r} exists, version "
            f"{primary.latest_version}; the package's own {primary.ecosystem} "
            f"metadata declares no repository field, so the registry's "
            f"repo={registry_repo!r} is unconfirmed (but not contradicted)."
        )
    else:
        evidence.append(
            f"{primary.ecosystem} package {primary.name!r} exists, version "
            f"{primary.latest_version}; registry repo=null and package declares no "
            f"identifiable repo either (nothing to contradict)."
        )
    return {"bucket": "OK", "evidence": evidence, "plausible_maintainer": plausible}


# ── Cache ────────────────────────────────────────────────────────────────


def _load_cache(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(path: Path, cache: dict) -> None:
    path.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")


def _cache_key(ecosystem: str, name: str) -> str:
    return f"{ecosystem}:{name}"


def _check_from_cache(cached: dict) -> EcosystemCheck:
    allowed = {f.name for f in fields(EcosystemCheck)}
    payload = {k: v for k, v in cached.items() if k != "_fetched_at" and k in allowed}
    return EcosystemCheck(**payload)


# ── Main audit loop ─────────────────────────────────────────────────────────


def audit_registry(
    registry_path: Path,
    cache_path: Path,
    refresh: bool,
) -> list[dict]:
    """Run the full audit and return a list of per-entry result dicts."""
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    cache = {} if refresh else _load_cache(cache_path)
    now = time.time()

    results: list[dict] = []

    for i, entry in enumerate(entries, start=1):
        name = entry["name"]
        ecosystems = _effective_ecosystems(entry)
        print(f"[{i}/{len(entries)}] {name} ({'/'.join(ecosystems)})", file=sys.stderr)

        checks: list[EcosystemCheck] = []
        for eco in ecosystems:
            key = _cache_key(eco, name)
            cached = cache.get(key)
            fresh = (
                cached is not None
                and (now - cached.get("_fetched_at", 0)) < CACHE_TTL_SECONDS
            )
            if fresh:
                c = _check_from_cache(cached)
            else:
                c = check_npm(name) if eco == "npm" else check_pypi(name)
                cache[key] = {**c.to_dict(), "_fetched_at": now}
            checks.append(c)

        if entry.get("attestation_expected"):
            primary = next((c for c in checks if c.checked and c.exists), None)
            if primary is None:
                for c in checks:
                    if c.provenance == "NOT_CHECKED":
                        c.provenance = "UNCHECKED"
                        c.provenance_detail = "no existing package to inspect"
            elif primary.provenance == "NOT_CHECKED":
                fill_provenance(primary)
                cache[_cache_key(primary.ecosystem, name)] = {
                    **primary.to_dict(),
                    "_fetched_at": now,
                }

        verdict = classify(entry, checks)
        provenance = "NOT_CHECKED"
        provenance_detail = None
        if entry.get("attestation_expected"):
            primary = next((c for c in checks if c.checked and c.exists), None)
            if primary is not None:
                provenance = primary.provenance
                provenance_detail = primary.provenance_detail
            else:
                provenance = "UNCHECKED"
                provenance_detail = "no existing package to inspect"
        results.append(
            {
                "name": name,
                "declared_source": entry.get("source"),
                "declared_ecosystem": ecosystems,
                "declared_repo": entry.get("repo"),
                "declared_maintainer": entry.get("maintainer"),
                "declared_verified": entry.get("verified"),
                "declared_last_verified": entry.get("last_verified"),
                "declared_attestation_expected": bool(
                    entry.get("attestation_expected")
                ),
                "is_suspect_block": (
                    entry.get("last_verified") == "2026-04-15"
                    and entry.get("maintainer") == "community"
                    and entry.get("repo") is None
                ),
                "checks": [c.to_dict() for c in checks],
                "bucket": verdict["bucket"],
                "evidence": verdict["evidence"],
                "plausible_maintainer": verdict["plausible_maintainer"],
                "provenance": provenance,
                "provenance_detail": provenance_detail,
            }
        )
        _save_cache(
            cache_path, cache
        )  # incremental save so interrupts don't lose progress

    return results


def apply_stamp(
    registry_path: Path,
    results: list[dict],
    stamp_date: str,
) -> dict[str, list[str]]:
    """Write ``last_verified`` and ``attestation_expected`` updates.

    Default callers must not invoke this — it is the only path that mutates
    ``known-servers.json``. Never sets ``attestation_expected`` to True.
    """
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    by_name = {r["name"]: r for r in results}
    cleared: list[str] = []
    kept: list[str] = []
    unchecked: list[str] = []
    stamped: list[str] = []
    skipped_non_ok: list[str] = []

    for entry in data.get("entries", []):
        result = by_name.get(entry["name"])
        if result is None:
            skipped_non_ok.append(entry["name"])
            continue
        if entry.get("attestation_expected"):
            prov = result.get("provenance")
            if prov == "NO_PROVENANCE":
                entry["attestation_expected"] = False
                cleared.append(entry["name"])
            elif prov == "HAS_PROVENANCE":
                kept.append(entry["name"])
            else:
                # UNCHECKED / NOT_CHECKED: leave the claim, list it.
                unchecked.append(entry["name"])
        if result.get("bucket") == "OK":
            entry["last_verified"] = stamp_date
            stamped.append(entry["name"])
        else:
            skipped_non_ok.append(entry["name"])

    data["last_updated"] = stamp_date
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    registry_path.write_text(text, encoding="utf-8")
    return {
        "cleared": cleared,
        "kept": kept,
        "unchecked": unchecked,
        "stamped": stamped,
        "skipped_non_ok": skipped_non_ok,
    }


def _print_provenance_summary(results: list[dict]) -> None:
    flagged = [r for r in results if r.get("declared_attestation_expected")]
    counts: dict[str, int] = {}
    for r in flagged:
        counts[r.get("provenance", "NOT_CHECKED")] = (
            counts.get(r.get("provenance", "NOT_CHECKED"), 0) + 1
        )
    print("\n=== Provenance (attestation_expected=true) ===", file=sys.stderr)
    for label in ("HAS_PROVENANCE", "NO_PROVENANCE", "UNCHECKED", "NOT_CHECKED"):
        print(f"  {label}: {counts.get(label, 0)}", file=sys.stderr)
    print(f"  flagged: {len(flagged)}", file=sys.stderr)
    for r in flagged:
        if r.get("provenance") == "UNCHECKED":
            print(
                f"  UNCHECKED {r['name']}: {r.get('provenance_detail')}",
                file=sys.stderr,
            )


def _print_stamp_summary(stats: dict[str, list[str]], wrote: bool) -> None:
    print("\n=== Stamp ===", file=sys.stderr)
    if not wrote:
        print("  --stamp not given; registry not written", file=sys.stderr)
        return
    print(
        f"  attestation_expected cleared (NO_PROVENANCE): {len(stats['cleared'])}",
        file=sys.stderr,
    )
    for name in stats["cleared"]:
        print(f"    - {name}", file=sys.stderr)
    print(
        f"  attestation_expected kept (HAS_PROVENANCE): {len(stats['kept'])}",
        file=sys.stderr,
    )
    for name in stats["kept"]:
        print(f"    - {name}", file=sys.stderr)
    print(
        f"  attestation_expected left (UNCHECKED): {len(stats['unchecked'])}",
        file=sys.stderr,
    )
    for name in stats["unchecked"]:
        print(f"    - {name}", file=sys.stderr)
    print(f"  last_verified stamped (OK): {len(stats['stamped'])}", file=sys.stderr)
    print(
        f"  last_verified skipped (non-OK): {len(stats['skipped_non_ok'])}",
        file=sys.stderr,
    )
    for name in stats["skipped_non_ok"]:
        print(f"    - {name}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--registry",
        type=Path,
        default=REGISTRY_PATH,
        help="Path to known-servers.json",
    )
    parser.add_argument(
        "--cache", type=Path, default=DEFAULT_CACHE_PATH, help="Local cache file path"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT_PATH,
        help="Where to write the raw JSON results",
    )
    parser.add_argument(
        "--refresh", action="store_true", help="Ignore cache, re-fetch everything"
    )
    parser.add_argument(
        "--stamp",
        action="store_true",
        help=(
            "Write last_verified (OK entries only) and clear "
            "attestation_expected on NO_PROVENANCE. Default is report-only."
        ),
    )
    parser.add_argument(
        "--date",
        default=date.today().isoformat(),
        help="ISO date used by --stamp (default: today). Tests pass an explicit value.",
    )
    args = parser.parse_args()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
        parser.error("--date must be YYYY-MM-DD")

    results = audit_registry(args.registry, args.cache, args.refresh)

    args.out.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")

    counts: dict[str, int] = {}
    for r in results:
        counts[r["bucket"]] = counts.get(r["bucket"], 0) + 1

    print("\n=== Summary ===", file=sys.stderr)
    for bucket in ("OK", "MISSING", "UNCLAIMABLE_MISMATCH", "THIN", "UNCHECKED"):
        print(f"  {bucket}: {counts.get(bucket, 0)}", file=sys.stderr)
    print(f"  TOTAL: {len(results)}", file=sys.stderr)
    non_ok = [r for r in results if r["bucket"] != "OK"]
    if non_ok:
        print("\n=== Non-OK (do not stamp last_verified) ===", file=sys.stderr)
        for r in non_ok:
            print(f"  {r['bucket']}: {r['name']}", file=sys.stderr)

    _print_provenance_summary(results)

    if args.stamp:
        stats = apply_stamp(args.registry, results, args.date)
        _print_stamp_summary(stats, wrote=True)
        print(f"\nWrote {args.registry}", file=sys.stderr)
    else:
        _print_stamp_summary(
            {
                "cleared": [],
                "kept": [],
                "unchecked": [],
                "stamped": [],
                "skipped_non_ok": [],
            },
            wrote=False,
        )

    print(f"\nRaw results written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
