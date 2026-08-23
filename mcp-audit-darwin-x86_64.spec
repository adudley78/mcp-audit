# -*- mode: python ; coding: utf-8 -*-

import os

# SPECPATH is already the absolute directory containing this spec file (the
# repo root for these portable specs).  Earlier revisions wrapped it in
# os.path.dirname(...), which yielded the *parent* of the repo root and made
# every bundled path point one level too high.  Keep the abspath for clarity.
root = os.path.abspath(SPECPATH)

a = Analysis(
    [os.path.join(root, 'src/mcp_audit/cli/__main__.py')],
    pathex=[os.path.join(root, 'src')],
    binaries=[],
    datas=[
        (os.path.join(root, 'src/mcp_audit/data'), 'mcp_audit/data'),
        (os.path.join(root, 'registry/known-servers.json'), 'registry'),
        (os.path.join(root, 'registry/known-extension-vulns.json'), 'registry'),
        (os.path.join(root, 'rules/community'), 'rules/community'),
        (os.path.join(root, 'semgrep-rules'), 'semgrep-rules'),
        (os.path.join(root, 'src/mcp_audit/advisory/osv_schema'),
         'mcp_audit/advisory/osv_schema'),
    ],
    hiddenimports=[
        'mcp_audit.analyzers.poisoning',
        'mcp_audit.analyzers.credentials',
        'mcp_audit.analyzers.transport',
        'mcp_audit.analyzers.supply_chain',
        'mcp_audit.analyzers.rug_pull',
        'mcp_audit.analyzers.toxic_flow',
        'mcp_audit.analyzers.attack_paths',
        'mcp_audit.output.terminal',
        'mcp_audit.output.sarif',
        'mcp_audit.output.nucleus',
        'mcp_audit.output.dashboard',
        'mcp_audit.watcher',
        'mcp_audit.registry.loader',
        'mcp_audit.rules.engine',
        'mcp_audit.fleet.merger',
        'mcp_audit.governance.evaluator',
        'mcp_audit.governance.loader',
        'mcp_audit.governance.models',
        'mcp_audit.baselines.manager',
        'mcp_audit.attestation.hasher',
        'mcp_audit.attestation.verifier',
        'mcp_audit.extensions.analyzer',
        'mcp_audit.extensions.discovery',
        'mcp_audit.sast.runner',
        'mcp_audit.sast.bundler',
        'mcp_audit.cli.baseline',
        'mcp_audit.cli.dashboard',
        'mcp_audit.cli.extensions',
        'mcp_audit.cli.fleet',
        'mcp_audit.cli.policy',
        'mcp_audit.cli.registry',
        'mcp_audit.cli.rules',
        'mcp_audit.cli.sast',
        'mcp_audit.cli.advise',
        'mcp_audit.advisory.canonical', 'mcp_audit.advisory.classify',
        'mcp_audit.advisory.feed',
        'mcp_audit.advisory.freshness',
        'mcp_audit.advisory.schema', 'mcp_audit.advisory.sign',
        'mcp_audit.advisory.validate',
        'mcp_audit.cli.scan', 'mcp_audit.cli.sbom', 'mcp_audit.cli.version',
        'mcp_audit._network', 'mcp_audit.output.base', 'mcp_audit.vulnerability.models', 'mcp_audit.vulnerability.resolver', 'mcp_audit.vulnerability.depsdev', 'mcp_audit.vulnerability.osv', 'mcp_audit.vulnerability.scanner',
        'mcp_audit.output.pdf',
        'reportlab', 'reportlab.lib', 'reportlab.lib.colors', 'reportlab.lib.enums',
        'reportlab.lib.pagesizes', 'reportlab.lib.styles', 'reportlab.lib.units',
        'reportlab.platypus', 'reportlab.platypus.doctemplate',
        'reportlab.platypus.flowables', 'reportlab.platypus.paragraph',
        'reportlab.platypus.tables', 'reportlab.pdfgen', 'reportlab.pdfbase',
        'reportlab.pdfbase.pdfmetrics', 'reportlab.pdfbase.ttfonts',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'cyclonedx', 'packageurl', 'py_serializable', 'boolean',
        'license_expression', 'defusedxml',
        # Optional [attestation] stack is intentionally not shipped in the
        # binary (keeps size under budget, avoids the sigstore-protobuf-specs
        # pre-release dependency chain).  The `--verify-signatures` code path
        # guards for ImportError and prints an install hint.
        'sigstore', 'sigstore_protobuf_specs', 'betterproto',
        'mcp_audit.attestation.sigstore_client',
        'mcp_audit.attestation.sigstore_findings',
        # Optional [mcp] extra is pip-install-only, same policy as
        # [attestation].  `--connect` guards for ImportError.  Release
        # builds with `uv sync --all-extras`, so without this exclude the
        # MCP SDK and its server-side transitives (starlette, uvicorn,
        # python-multipart, pydantic-settings) would be frozen in.
        'mcp',
        'starlette', 'sse_starlette', 'python_multipart', 'pydantic_settings',
        'uvicorn', 'httpx',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='mcp-audit-darwin-x86_64',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
