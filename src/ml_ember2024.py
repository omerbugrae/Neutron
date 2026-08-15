"""Optional EMBER2024 LightGBM adapter.

This module is fail-open and observation-only.  It never downloads or installs
dependencies, and it refuses model artifacts whose SHA-256 does not match the
local signed catalog.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CATALOG_MAX_BYTES = 128 * 1024
MODEL_MAX_BYTES = 16 * 1024 * 1024
MAX_BINARY_CLASSIFIERS = 8
SAMPLE_MAX_BYTES = 128 * 1024 * 1024
SUPPORTED_CONTEXTS = frozenset({"pe", "win32", "win64", "dotnet", "driver"})
TRUSTED_MODEL_HASHES = {
    "EMBER2024_PE.model": "4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99",
    "EMBER2024_Win32.model": "b1e9fc174e4fcc6c0aba3ff29eb6d96ee9e240057f76940a8a1d6009ac0a4267",
    "EMBER2024_Win64.model": "8eddddc26eb346d74810a0dfcc672342eca5709ece4da259934d6d3c77ca971b",
    "EMBER2024_Dot_Net.model": "cbd91b4a823d5dac3f56f38640a5599836501ccbd4fcce273d28c9aed0afc24c",
    "EMBER2024_all.model": "af4ec038685797c586142d177965fe451cac96f424f631aeb66f8d116c161d07",
}


@dataclass(frozen=True)
class EmberScore:
    model_id: str
    category: str
    family: str
    model_version: str
    weight: float
    probability: float


@dataclass(frozen=True)
class _Runtime:
    lightgbm: Any
    thrember: Any


_RUNTIME_CHECKED = False
_RUNTIME: _Runtime | None = None
_MODEL_CACHE: dict[str, tuple[int, int, Any | None]] = {}
_HASH_CACHE: dict[str, tuple[int, int, str]] = {}


def _optional_runtime() -> _Runtime | None:
    global _RUNTIME_CHECKED, _RUNTIME
    if _RUNTIME_CHECKED:
        return _RUNTIME
    _RUNTIME_CHECKED = True
    try:
        _RUNTIME = _Runtime(
            lightgbm=importlib.import_module("lightgbm"),
            thrember=importlib.import_module("thrember"),
        )
    except Exception:
        # Optional native runtimes can fail with loader-specific exception
        # types. Shadow mode must remain fail-open in every such case.
        _RUNTIME = None
    return _RUNTIME


def _artifact_matches(path: Path, expected_sha256: str) -> bool:
    try:
        stat = path.stat()
        if stat.st_size <= 0 or stat.st_size > MODEL_MAX_BYTES:
            return False
        key = str(path)
        cached = _HASH_CACHE.get(key)
        signature = (int(stat.st_mtime_ns), int(stat.st_size))
        if cached and cached[:2] == signature:
            return cached[2] == expected_sha256
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        actual = digest.hexdigest()
        _HASH_CACHE[key] = (*signature, actual)
        return actual == expected_sha256
    except OSError:
        return False


def _load_booster(runtime: _Runtime, path: Path) -> Any | None:
    try:
        stat = path.stat()
        key = str(path)
        signature = (int(stat.st_mtime_ns), int(stat.st_size))
        cached = _MODEL_CACHE.get(key)
        if cached and cached[:2] == signature:
            return cached[2]
        booster = runtime.lightgbm.Booster(model_file=str(path))
        _MODEL_CACHE[key] = (*signature, booster)
        return booster
    except Exception:
        return None


def _read_catalog(directory: Path) -> tuple[str, list[dict[str, Any]]] | None:
    path = directory / "ensemble.json"
    try:
        stat = path.stat()
        if stat.st_size <= 0 or stat.st_size > CATALOG_MAX_BYTES:
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        version = str(payload.get("ensemble_version") or "").strip()
        members = payload.get("members")
        if (
            payload.get("feature_schema") != "ember-v3"
            or not version or len(version) > 80
            or not isinstance(members, list)
            or not 1 <= len(members) <= MAX_BINARY_CLASSIFIERS
        ):
            return None
        return version, members
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError):
        return None


def score_pe_models(
    directory: Path,
    sample_path: Path,
    sample_bytes: bytes | None,
    contexts: frozenset[str],
) -> tuple[str, tuple[EmberScore, ...]] | None:
    """Return verified binary-classifier scores, or None when unavailable."""
    catalog = _read_catalog(directory)
    runtime = _optional_runtime()
    if catalog is None or runtime is None or not contexts.issubset(SUPPORTED_CONTEXTS):
        return None
    version, raw_members = catalog
    resolved_directory = directory.resolve()
    selected: list[tuple[dict[str, Any], Path]] = []
    seen_ids: set[str] = set()
    for item in raw_members:
        if not isinstance(item, dict) or item.get("enabled", True) is not True:
            continue
        model_id = str(item.get("id") or "")
        filename = str(item.get("file") or "")
        expected_hash = str(item.get("sha256") or "").lower()
        applies_to = item.get("applies_to")
        if (
            not model_id or model_id in seen_ids or len(model_id) > 48
            or not filename or Path(filename).name != filename
            or len(expected_hash) != 64 or any(char not in "0123456789abcdef" for char in expected_hash)
            or TRUSTED_MODEL_HASHES.get(filename) != expected_hash
            or item.get("model_type") != "lightgbm-ember-v3"
            or item.get("category") != "static-pe"
            or item.get("family") != "ember2024"
            or not isinstance(applies_to, list) or not contexts.intersection(applies_to)
        ):
            continue
        model_path = (directory / filename).resolve()
        if model_path.parent != resolved_directory or not _artifact_matches(model_path, expected_hash):
            continue
        seen_ids.add(model_id)
        selected.append((item, model_path))
    if not selected:
        return None
    try:
        bytez = sample_bytes
        if bytez is None:
            if sample_path.stat().st_size > SAMPLE_MAX_BYTES:
                return None
            bytez = sample_path.read_bytes()
        extractor = runtime.thrember.PEFeatureExtractor()
        feature_vector = extractor.feature_vector(bytez)
        scores: list[EmberScore] = []
        for item, model_path in selected:
            booster = _load_booster(runtime, model_path)
            if booster is None:
                continue
            result = booster.predict([feature_vector])
            probability = float(result[0])
            weight = float(item.get("weight", 1.0))
            if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
                continue
            if not math.isfinite(weight) or not 0.0 < weight <= 10.0:
                continue
            scores.append(EmberScore(
                model_id=str(item["id"]), category="static-pe", family="ember2024",
                model_version=f"ember2024-{model_path.stem}", weight=weight,
                probability=probability,
            ))
        return (version, tuple(scores)) if scores else None
    except Exception:
        return None
