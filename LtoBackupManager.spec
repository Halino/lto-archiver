# -*- mode: python ; coding: utf-8 -*-

import os
import sys


project_root = os.path.abspath(SPECPATH)
source_root = os.path.join(project_root, 'src')
tcl_root = os.path.join(sys.base_prefix, 'tcl')
gui_datas = [
    (os.path.join(tcl_root, 'tcl8.6'), '_tcl_data'),
    (os.path.join(tcl_root, 'tk8.6'), '_tk_data'),
]

gui_analysis = Analysis(
    [os.path.join(source_root, 'lto_backup_gui_entry.py')],
    pathex=[source_root],
    binaries=[],
    datas=gui_datas,
    hiddenimports=[],
    hookspath=[os.path.join(project_root, 'hooks')],
    hooksconfig={},
    runtime_hooks=[os.path.join(project_root, 'src', 'pyi_rth_tkinter_local.py')],
    excludes=[],
    noarchive=False,
    optimize=0,
)
gui_pyz = PYZ(gui_analysis.pure)
gui_exe = EXE(
    gui_pyz,
    gui_analysis.scripts,
    gui_analysis.binaries,
    gui_analysis.datas,
    [],
    name='LtoBackupManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=os.path.join(project_root, 'packaging', 'version_info.txt'),
    uac_admin=True,
)

cli_analysis = Analysis(
    [os.path.join(source_root, 'lto_backup_entry.py')],
    pathex=[source_root],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
cli_pyz = PYZ(cli_analysis.pure)
cli_exe = EXE(
    cli_pyz,
    cli_analysis.scripts,
    cli_analysis.binaries,
    cli_analysis.datas,
    [],
    name='LtoBackupManagerCli',
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
    version=os.path.join(project_root, 'packaging', 'version_info_cli.txt'),
)
