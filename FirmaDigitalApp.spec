# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['flask_pdf_signer.py'],
    pathex=[],
    binaries=[],
    datas=[('templates', 'templates'), ('users.db', '.'), ('key_store.db', '.'), ('master.key', '.')],
    hiddenimports=['pyhanko', 'pyhanko.sign', 'pyhanko.sign.fields', 'pyhanko.sign.signers', 'pyhanko.pdf_utils', 'pyhanko.pdf_utils.images', 'pyhanko.stamp'],
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
    name='FirmaDigitalApp',
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
