# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('C:\\Django_projects\\Tracker33\\desktop_app\\icon.png', '.'), ('C:\\Django_projects\\Tracker33\\desktop_app\\config.ini', '.')]
binaries = [('C:\\Users\\DFYZ330188\\AppData\\Local\\Programs\\Python\\Python313\\Lib\\site-packages\\PyQt5/Qt5/plugins/platforms/*', 'platforms'), ('C:\\Users\\DFYZ330188\\AppData\\Local\\Programs\\Python\\Python313\\Lib\\site-packages\\PyQt5/Qt5/plugins/styles/*', 'styles'), ('C:\\Users\\DFYZ330188\\AppData\\Local\\Programs\\Python\\Python313\\Lib\\site-packages\\PyQt5/Qt5/plugins/imageformats/*', 'imageformats')]
hiddenimports = ['PyQt5', 'PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets', 'PyQt5.QtNetwork', 'PyQt5.sip']
tmp_ret = collect_all('PyQt5.sip')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['C:\\Django_projects\\Tracker33\\desktop_app\\main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['PyQt5.Qt3DCore', 'PyQt5.Qt3DRender', 'PyQt5.Qt3DInput', 'PyQt5.Qt3DLogic', 'PyQt5.Qt3DAnimation', 'PyQt5.Qt3DExtras', 'PyQt5.QtWebEngine', 'PyQt5.QtMultimedia', 'PyQt5.QtQuick'],
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
    name='TimeTracker',
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
    icon=['C:\\Django_projects\\Tracker33\\desktop_app\\icon.png'],
)
