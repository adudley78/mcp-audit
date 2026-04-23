# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['/Users/MacBookAir/Projects/mcp-audit/src/mcp_audit/cli/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[('/Users/MacBookAir/Projects/mcp-audit/src/mcp_audit/data', 'mcp_audit/data'), ('/Users/MacBookAir/Projects/mcp-audit/registry/known-servers.json', 'registry'), ('/Users/MacBookAir/Projects/mcp-audit/registry/known-extension-vulns.json', 'registry'), ('/Users/MacBookAir/Projects/mcp-audit/rules/community', 'rules/community'), ('/Users/MacBookAir/Projects/mcp-audit/semgrep-rules', 'semgrep-rules')],
    hiddenimports=['mcp_audit.analyzers.poisoning', 'mcp_audit.analyzers.credentials', 'mcp_audit.analyzers.transport', 'mcp_audit.analyzers.supply_chain', 'mcp_audit.analyzers.rug_pull', 'mcp_audit.analyzers.toxic_flow', 'mcp_audit.analyzers.attack_paths', 'mcp_audit.output.terminal', 'mcp_audit.output.sarif', 'mcp_audit.output.nucleus', 'mcp_audit.output.dashboard', 'mcp_audit.watcher', 'mcp_audit.registry.loader', 'mcp_audit.rules.engine', 'mcp_audit.licensing', 'mcp_audit.fleet.merger', 'mcp_audit.governance.evaluator', 'mcp_audit.governance.loader', 'mcp_audit.governance.models', 'mcp_audit.baselines.manager', 'mcp_audit.attestation.hasher', 'mcp_audit.attestation.verifier', 'mcp_audit.extensions.analyzer', 'mcp_audit.extensions.discovery', 'mcp_audit.sast.runner', 'mcp_audit.sast.bundler', 'mcp_audit.cli.baseline', 'mcp_audit.cli.dashboard', 'mcp_audit.cli.extensions', 'mcp_audit.cli.fleet', 'mcp_audit.cli.license', 'mcp_audit.cli.policy', 'mcp_audit.cli.registry', 'mcp_audit.cli.rules', 'mcp_audit.cli.sast', 'mcp_audit.cli.scan', 'cryptography.hazmat.primitives.asymmetric.ed25519', 'cryptography.hazmat.primitives.serialization', 'cryptography.exceptions'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
