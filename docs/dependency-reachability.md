# Dependency reachability

Dependabot alerts on `uv.lock` transitives. 32 of those were dismissed in
August 2026 as `not_used` because mcp-audit never calls the vulnerable
function. Those arguments are correct only while the usage described here
holds. If you change a call site listed below, re-open the matching alerts
and re-triage — do not assume the dismissal still applies.

`mcp-audit sbom` inventories **scanned MCP servers**, not mcp-audit's own
dependencies and not the frozen binaries. Use `uv tree` and a PyInstaller
PYZ listing (`PYZ-00.toc`) for those surfaces.

## pillow (core, also frozen via reportlab)

Ships in the wheel and in all four binaries. The only image mcp-audit
opens is the bundled `header_dark.png`, via `reportlab.lib.utils.ImageReader`
in `output/pdf.py`. None of the 13 CVEs (CMS transform, JPEG2000, PDF
parse, `paste`/`crop` with attacker coords, TGA encode, RankFilter,
WindowsViewer, GD/BDF/PCF/McIdas/EPS) are on that path.

**Invalidated by:** passing a user-supplied or remotely-fetched image to
reportlab/Pillow (custom PDF header, screenshot embed, font file, etc.).

## cryptography (`[attestation]` extra; also pulled by `[mcp]` → pyjwt)

`--verify-signatures` uses sigstore, which verifies chains with OpenSSL
`X509Store`, not `cryptography.x509.verification.PolicyBuilder`. mcp-audit
itself only reads OIDC extensions off an already-parsed cert. It never
calls `pkcs7_decrypt_*`. The OpenSSL-in-wheels issue (CVE-2026-34180)
requires a >2 GB ASN.1 primitive; Sigstore bundles from npm/PyPI are
kilobytes.

**Invalidated by:** switching sigstore verification onto
`PolicyBuilder.build_server_verifier` / `build_chain_inner`; decrypting
PKCS#7 EnvelopedData; feeding multi-gigabyte ASN.1 into `d2i_*`.

The four PyInstaller specs exclude `sigstore`. cryptography can still
appear in a release binary via `urllib3.contrib.pyopenssl` — that does
not change the unused-API argument above.

## pyasn1 (`[attestation]` via sigstore)

`sigstore.verify.policy._SingleX509ExtPolicyV2` calls
`pyasn1.codec.der.decoder.decode`. mcp-audit passes `UnsafeNoOp()`, which
never decodes. See `attestation/sigstore_client.py`.

**Invalidated by:** replacing `UnsafeNoOp()` with `Identity` or any
`_SingleX509ExtPolicyV2` subclass.

## mcp, starlette, python-multipart, pydantic-settings (`[mcp]` extra)

mcp-audit is an MCP **client** (`ClientSession`, `sse_client`,
`stdio_client`). The CVEs are server-side (WebSocket Host/Origin,
session principal, experimental task handlers, `request.form()`,
`StaticFiles`, `HTTPEndpoint`, `parse_form`,
`NestedSecretsSettingsSource`). The extra is pip-install-only, same
policy as `sigstore`; the specs should exclude it from the standalone
binary.

**Invalidated by:** shipping an MCP/Starlette **server**, or freezing
the `[mcp]` extra into the binary without re-triaging those CVEs.

## setuptools (dev group + PyInstaller)

MANIFEST.in NFC/NFD bypass is sdist packaging. mcp-audit builds with
hatchling. setuptools never packs a user-facing sdist.

**Invalidated by:** switching the build backend to setuptools, or
invoking `setup.py`/`setuptools.setup` on attacker-controlled
`MANIFEST.in`.
