# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import hashlib
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

# thrember is deliberately NOT collected. src/ember_features.py is a verbatim
# copy of its features.py -- the only part a scan touches -- so the package's
# __init__, which imports the training (model.py) and dataset-download
# (download.py) halves, never runs here. Collecting it dragged in polars
# (176 MB), huggingface_hub and hf_xet for code Neutron cannot reach: it does
# not train models, it downloads finished ones over its own Feature Update
# channel. Keeping thrember out is worth about 200 MB of installer.
required_ml_packages = ["lightgbm"]

# The shipped LightGBM models were trained against exactly the feature
# computations in src/ember_features.py. An edit there would change what the
# models are asked to score without changing anything visible -- the engine
# would still start, still scan, and quietly produce meaningless ML output.
# So the build refuses to continue rather than shipping that.
vendored_features = project_root / "src" / "ember_features.py"
VENDORED_FEATURES_SHA256 = "6daf019a6cb7966158cb7390c5b9a7e10e8321aa9f1f2f77432a2970aebc1a73"
if not vendored_features.is_file():
    raise SystemExit(f"Vendored özellik çıkarıcı bulunamadı: {vendored_features}")
actual_features_sha256 = hashlib.sha256(vendored_features.read_bytes()).hexdigest()
if actual_features_sha256 != VENDORED_FEATURES_SHA256:
    raise SystemExit(
        "src/ember_features.py değiştirilmiş. Bu dosya thrember 0.1.0 features.py'nin birebir "
        "kopyası olmak zorunda; aksi halde paketlenen modeller eğitildiklerinden farklı "
        "özelliklerle puanlanır.\n"
        f"  beklenen: {VENDORED_FEATURES_SHA256}\n"
        f"  bulunan : {actual_features_sha256}\n"
        "Kasıtlı bir sürüm yükseltmesiyse dosyayı yeni sürümden komple değiştir, "
        "tools/engine/neutron-engine.spec içindeki hash'i güncelle ve modelleri yeniden doğrula."
    )
missing_ml_packages = [name for name in required_ml_packages if importlib.util.find_spec(name) is None]
if missing_ml_packages:
    raise SystemExit(
        "ML build paketleri eksik: " + ", ".join(missing_ml_packages)
        + ". Yalnız build ortamında requirements-ml-build.txt kullanılmalıdır."
    )

# What the vendored feature extractor actually needs at scan time. It is
# reached through importlib, so PyInstaller cannot see the import itself.
# Everything else thrember used to pull in is training-only.
hidden_imports += ["ember_features", "signify", "signify.authenticode", "sklearn.feature_extraction"]

# Never reachable from a scan. Listing them keeps PyInstaller from following a
# transitive import back into the training stack and quietly restoring the
# 200 MB. If a scan ever raises ModuleNotFoundError for one of these, the fix
# is to find out what pulled it in -- not to delete it from this list.
unused_heavy_packages = [
    "polars",
    "huggingface_hub",
    "hf_xet",
    "datasets",
    "matplotlib",
    "PIL",
    "tqdm",
    "thrember",
]

ml_datas = []
ml_binaries = []
for package_name in required_ml_packages:
    package_datas, package_binaries, package_hidden_imports = collect_all(package_name)
    ml_datas += package_datas
    ml_binaries += package_binaries
    hidden_imports += package_hidden_imports


def _is_unused_heavy_module(module_name):
    return str(module_name).split(".")[0] in unused_heavy_packages


def _is_unused_heavy_destination(destination):
    # collect_all yields (source, destination) pairs whose destination may be
    # "." for top-level files, and Path(".").parts is empty -- indexing it
    # blindly would abort the build.
    parts = Path(str(destination)).parts
    return bool(parts) and parts[0] in unused_heavy_packages


# collect_all("lightgbm") reports lightgbm.plotting's matplotlib among the
# hidden imports. Leaving it in while also excluding it makes PyInstaller warn
# on every build, so the collected list is filtered rather than fought with.
hidden_imports = [name for name in hidden_imports if not _is_unused_heavy_module(name)]
ml_datas = [entry for entry in ml_datas if not _is_unused_heavy_destination(entry[1])]
ml_binaries = [entry for entry in ml_binaries if not _is_unused_heavy_destination(entry[1])]

analysis = Analysis(
    [str(engine_source)],
    pathex=[str(project_root / "src")],
    binaries=ml_binaries,
    datas=ml_datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "py7zr", "rarfile", *unused_heavy_packages],
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
