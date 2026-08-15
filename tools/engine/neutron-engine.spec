# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import importlib.util

from PyInstaller.utils.hooks import collect_all

project_root = Path(SPECPATH).parents[1]
engine_source = project_root / "src" / "engine.py"
engine_icon = project_root / "assets" / "neutron.ico"

hidden_imports = [
    "pefile",
    "yara",
    "watchdog.observers.api",
    "watchdog.observers.read_directory_changes",
    "watchdog.observers.winapi",
]

required_ml_packages = ["lightgbm", "thrember"]
missing_ml_packages = [name for name in required_ml_packages if importlib.util.find_spec(name) is None]
if missing_ml_packages:
    raise SystemExit(
        "ML build paketleri eksik: " + ", ".join(missing_ml_packages)
        + ". Yalnız build ortamında requirements-ml-build.txt kullanılmalıdır."
    )

ml_datas = []
ml_binaries = []
for package_name in required_ml_packages:
    package_datas, package_binaries, package_hidden_imports = collect_all(package_name)
    ml_datas += package_datas
    ml_binaries += package_binaries
    hidden_imports += package_hidden_imports

analysis = Analysis(
    [str(engine_source)],
    pathex=[str(project_root / "src")],
    binaries=ml_binaries,
    datas=ml_datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "py7zr", "rarfile"],
    noarchive=False,
    optimize=1,
)

python_archive = PYZ(analysis.pure)

executable = EXE(
    python_archive,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="neutron-engine",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(engine_icon),
)

bundle = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="neutron-engine",
)
