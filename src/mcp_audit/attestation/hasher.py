"""Hash computation and verification for MCP server package tarballs.

Layer 1 of supply chain attestation: static, offline-equivalent integrity
verification.  Computes SHA-256 digests of published npm/pip package tarballs
and compares them against pinned values in the known-server registry.

No external dependencies — uses Python stdlib ``hashlib`` and ``urllib.request``.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass
class HashResult:
    """Result of a package hash verification attempt."""

    package_name: str
    version: str | None
    computed_hash: str  # "sha256:<hex>"
    expected_hash: str | None  # from registry, or None if not pinned
    match: bool | None  # None if no expected hash to compare against
    source_url: str | None  # URL the package was downloaded from, or error note


def compute_hash_from_file(path: Path) -> str:
    """Compute SHA-256 of a local file.

    Args:
        path: Path to the file to hash.

    Returns:
        Hash string in ``"sha256:<hex>"`` format.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def compute_hash_from_url(url: str) -> str:
    """Download *url* to a temp file, compute SHA-256, return ``"sha256:<hex>"``.

    The temporary file is always cleaned up on completion or error.

    Args:
        url: HTTP/HTTPS URL of the resource to download and hash.

    Returns:
        Hash string in ``"sha256:<hex>"`` format.

    Raises:
        urllib.error.URLError: On any network-level failure.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as tmp:
        tmp_path = Path(tmp.name)

    if not url.startswith("https://"):
        raise ValueError(
            f"Only HTTPS URLs are permitted for hash verification; got: {url!r}"
        )

    try:
        urllib.request.urlretrieve(url, tmp_path)  # noqa: S310  # nosec B310 -- HTTPS scheme validated above
        return compute_hash_from_file(tmp_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def resolve_npm_tarball_url(package_name: str, version: str) -> str:
    """Return the npm registry tarball URL for *package_name* at *version*.

    Handles scoped packages (``@scope/name``) by stripping the scope prefix
    from the tarball filename while keeping it in the registry path segment.

    Args:
        package_name: Full npm package name, e.g. ``@scope/name`` or ``my-pkg``.
        version: Exact version string, e.g. ``"0.6.2"``.

    Returns:
        Full HTTPS tarball URL.  No network request is made.
    """
    if package_name.startswith("@"):
        # Scoped: @scope/name → basename is just "name"
        basename = package_name.split("/", 1)[1]
    else:
        basename = package_name
    return f"https://registry.npmjs.org/{package_name}/-/{basename}-{version}.tgz"


def resolve_pip_tarball_url(package_name: str, version: str) -> str:
    """Return the PyPI JSON API URL for *package_name* at *version*.

    Args:
        package_name: PyPI package name, e.g. ``"mcp"``.
        version: Exact version string, e.g. ``"1.6.0"``.

    Returns:
        PyPI JSON API URL.  No network request is made.
    """
    return f"https://pypi.org/pypi/{package_name}/{version}/json"


def fetch_pip_tarball_url(package_name: str, version: str) -> str:
    """Fetch the PyPI JSON API and return the ``.tar.gz`` sdist URL.

    Args:
        package_name: PyPI package name.
        version: Exact version string.

    Returns:
        Direct HTTPS URL to the sdist ``.tar.gz`` tarball.

    Raises:
        ValueError: If the version is not found on PyPI or has no sdist.
        urllib.error.URLError: On network failure.
    """
    api_url = resolve_pip_tarball_url(package_name, version)
    with urllib.request.urlopen(api_url, timeout=30) as resp:  # noqa: S310  # nosec B310 -- api_url is always https://pypi.org/ (see resolve_pip_tarball_url)
        data = json.loads(resp.read().decode())

    urls = data.get("urls", [])
    for entry in urls:
        if entry.get("packagetype") == "sdist" and entry.get("filename", "").endswith(
            ".tar.gz"
        ):
            return entry["url"]

    raise ValueError(f"No sdist (.tar.gz) found for {package_name}=={version} on PyPI.")


def verify_package_hash(
    package_name: str,
    version: str,
    source: str,
    expected_hash: str,
) -> HashResult:
    """Download the package tarball, compute its hash, compare against *expected_hash*.

    On network failure, returns a ``HashResult`` with ``match=None`` and a
    description of the error in ``source_url``.

    Args:
        package_name: Package name as it appears in the registry.
        version: Exact version string to verify.
        source: Package ecosystem — ``"npm"`` or ``"pip"``.
        expected_hash: Expected hash string in ``"sha256:<hex>"`` format.

    Returns:
        :class:`HashResult` with ``match=True`` (clean), ``False`` (tampered),
        or ``None`` (could not verify due to network error).
    """
    try:
        if source == "npm":
            url = resolve_npm_tarball_url(package_name, version)
        elif source == "pip":
            url = fetch_pip_tarball_url(package_name, version)
        else:
            return HashResult(
                package_name=package_name,
                version=version,
                computed_hash="",
                expected_hash=expected_hash,
                match=None,
                source_url=f"Unsupported source: {source!r}",
            )

        computed = compute_hash_from_url(url)
        return HashResult(
            package_name=package_name,
            version=version,
            computed_hash=computed,
            expected_hash=expected_hash,
            match=(computed == expected_hash),
            source_url=url,
        )
    except urllib.error.URLError as exc:
        return HashResult(
            package_name=package_name,
            version=version,
            computed_hash="",
            expected_hash=expected_hash,
            match=None,
            source_url=f"Network error: {exc}",
        )
    except ValueError as exc:
        return HashResult(
            package_name=package_name,
            version=version,
            computed_hash="",
            expected_hash=expected_hash,
            match=None,
            source_url=f"Lookup error: {exc}",
        )
