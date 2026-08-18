"""PE machine-learning adapter used in observation-only shadow mode.

The model output in this module is deliberately not a security verdict.  It is
kept separate from signature/YARA/reputation decisions so a malformed, stale
or poorly calibrated model can never quarantine a file during rollout.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ml_ember2024 import score_pe_models


FEATURE_SCHEMA_VERSION = 1
MODEL_MAX_BYTES = 128 * 1024
MAX_ENSEMBLE_MEMBERS = 12
MODEL_CONTEXTS = frozenset({"pe", "win32", "win64", "dotnet", "driver"})
MODEL_CATEGORY_BY_TYPE = {"logistic-regression-json": "static-pe"}

# Model categories whose agreement is allowed to count as *independent*
# evidence of each other.
#
# Today every shipped model -- the legacy logistic regression and all fourteen
# EMBER2024 classifiers -- reads the same PE structure, so they are all one
# category and `high-consensus` is unreachable by construction. That is
# correct, and it must stay correct by accident-proof means: without this
# allowlist, adding a single entry to MODEL_CATEGORY_BY_TYPE would silently
# unlock the strongest consensus state in the engine for a model nobody had
# measured. Arming a category is therefore a deliberate, separate edit, and
# plan.md item 3 is the checklist for what has to be true first.
ARMED_MODEL_CATEGORIES = frozenset({"static-pe"})
FEATURE_NAMES = (
    "file_size_log2",
    "section_count",
    "import_count_log2",
    "executable_section_count",
    "writable_executable_count",
    "high_entropy_executable_count",
    "packer_marker_count",
    "max_section_entropy_normalized",
    "overlay_ratio",
    "entrypoint_outside_sections",
    "entrypoint_non_executable",
    "injection_api_match_count",
    "credential_api_match_count",
    "persistence_api_match_count",
    "network_api_match_count",
    "missing_import_table",
    "has_embedded_signature",
    "trusted_signature",
    "invalid_signature",
    "is_dll",
    "is_driver",
    "is_64_bit",
)


@dataclass(frozen=True)
class ShadowPrediction:
    model_id: str
    category: str
    family: str
    model_version: str
    weight: float
    probability: float

    @property
    def score(self) -> int:
        return max(0, min(100, round(self.probability * 100)))


@dataclass(frozen=True)
class LinearModel:
    version: str
    bias: float
    weights: dict[str, float]


_MODEL_CACHE: dict[str, tuple[int, int, LinearModel | None]] = {}


@dataclass(frozen=True)
class EnsemblePrediction:
    ensemble_version: str
    members: tuple[ShadowPrediction, ...]
    score: int
    disagreement: int
    independent_families: int
    independent_categories: int
    high_confidence_categories: int
    consensus_state: str
    # How many members actually scored this sample, and how far apart they
    # landed. `disagreement` above measures the spread *between categories*,
    # which is identically zero while EMBER is the only category -- so it says
    # nothing about whether the individual models agreed with each other. Not
    # every member sees every file either: applies_to means a 64-bit PE is
    # scored by a different subset than a .NET assembly. A caller that wants
    # to act on the score needs both of these to tell a genuine multi-model
    # agreement from one model dragging the average up.
    member_count: int = 0
    member_spread: int = 0
    # Categories that scored this sample but are not on ARMED_MODEL_CATEGORIES.
    # Recorded rather than hidden so a shadow report can show what an unarmed
    # adapter *would* have said, which is the evidence needed to arm it later.
    unarmed_categories: tuple[str, ...] = ()

    def as_payload(self) -> dict[str, object]:
        return {
            "ensemble_version": self.ensemble_version,
            "score": self.score,
            "disagreement": self.disagreement,
            "independent_families": self.independent_families,
            "independent_categories": self.independent_categories,
            "high_confidence_categories": self.high_confidence_categories,
            "consensus_state": self.consensus_state,
            "member_count": self.member_count,
            "member_spread": self.member_spread,
            "unarmed_categories": list(self.unarmed_categories),
            "members": [
                {
                    "model_id": member.model_id,
                    "category": member.category,
                    "family": member.family,
                    "model_version": member.model_version,
                    "weight": member.weight,
                    "score": member.score,
                }
                for member in self.members
            ],
        }


def build_feature_vector(**values: float | int | bool) -> dict[str, float]:
    """Return a finite, fixed-order vector and reject schema drift early."""
    unknown = set(values).difference(FEATURE_NAMES)
    missing = set(FEATURE_NAMES).difference(values)
    if unknown or missing:
        raise ValueError(f"PE ML özellik şeması uyuşmuyor; eksik={sorted(missing)}, fazla={sorted(unknown)}")
    vector: dict[str, float] = {}
    for name in FEATURE_NAMES:
        value = float(values[name])
        if not math.isfinite(value):
            raise ValueError(f"PE ML özelliği sonlu değil: {name}")
        vector[name] = value
    return vector


def _load_linear_model(path: Path) -> LinearModel | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    cache_key = str(path)
    signature = (int(stat.st_mtime_ns), int(stat.st_size))
    cached = _MODEL_CACHE.get(cache_key)
    if cached and cached[:2] == signature:
        return cached[2]
    model: LinearModel | None = None
    try:
        if stat.st_size <= 0 or stat.st_size > MODEL_MAX_BYTES:
            raise ValueError("model boyutu geçersiz")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise ValueError("özellik şeması sürümü desteklenmiyor")
        if payload.get("model_type") != "logistic-regression":
            raise ValueError("model türü desteklenmiyor")
        version = str(payload.get("model_version") or "").strip()
        raw_weights = payload.get("weights")
        if not version or not isinstance(raw_weights, dict) or set(raw_weights) != set(FEATURE_NAMES):
            raise ValueError("model metadatası eksik")
        bias = float(payload.get("bias"))
        weights = {name: float(raw_weights[name]) for name in FEATURE_NAMES}
        if not math.isfinite(bias) or abs(bias) > 100:
            raise ValueError("model bias değeri geçersiz")
        if any(not math.isfinite(value) or abs(value) > 100 for value in weights.values()):
            raise ValueError("model ağırlığı geçersiz")
        model = LinearModel(version=version[:80], bias=bias, weights=weights)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        model = None
    _MODEL_CACHE[cache_key] = (*signature, model)
    return model


def predict_shadow(
    path: Path, features: Mapping[str, float], *, model_id: str = "legacy",
    category: str = "legacy", family: str = "legacy", weight: float = 1.0,
) -> ShadowPrediction | None:
    """Score a validated model artifact without turning it into a verdict."""
    if set(features) != set(FEATURE_NAMES):
        return None
    model = _load_linear_model(path)
    if model is None:
        return None
    logit = model.bias + sum(model.weights[name] * float(features[name]) for name in FEATURE_NAMES)
    probability = 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, logit))))
    return ShadowPrediction(
        model_id=model_id, category=category, family=family, model_version=model.version,
        weight=weight, probability=probability,
    )


def _safe_name(value: object, maximum: int = 80) -> str | None:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in text):
        return None
    return text


def _ensemble_result(version: str, members: list[ShadowPrediction]) -> EnsemblePrediction:
    family_members: dict[tuple[str, str], list[ShadowPrediction]] = {}
    for member in members:
        family_members.setdefault((member.category, member.family), []).append(member)
    category_families: dict[str, list[tuple[float, float]]] = {}
    for (category, _family), grouped in family_members.items():
        total_weight = sum(member.weight for member in grouped)
        probability = sum(member.probability * member.weight for member in grouped) / total_weight
        category_families.setdefault(category, []).append((probability, max(member.weight for member in grouped)))
    category_scores: list[tuple[float, float]] = []
    for grouped in category_families.values():
        total_weight = sum(weight for _score, weight in grouped)
        probability = sum(score * weight for score, weight in grouped) / total_weight
        category_scores.append((probability, max(weight for _score, weight in grouped)))
    total_category_weight = sum(weight for _score, weight in category_scores)
    probability = sum(score * weight for score, weight in category_scores) / total_category_weight
    score = max(0, min(100, round(probability * 100)))
    disagreement = round((max(value for value, _weight in category_scores) - min(value for value, _weight in category_scores)) * 100)
    high_categories = sum(1 for category_score, _weight in category_scores if category_score >= 0.90)
    # Only armed categories may establish independence. An unarmed category
    # still contributes its score to the ensemble average -- it is an opinion
    # worth hearing -- but it cannot be the second leg that unlocks
    # high-consensus, because nothing has validated it as independent yet.
    armed_categories = sum(1 for category in category_families if category in ARMED_MODEL_CATEGORIES)
    unarmed_categories = sorted(category for category in category_families if category not in ARMED_MODEL_CATEGORIES)
    if armed_categories >= 2 and high_categories >= 2 and score >= 90 and disagreement <= 20:
        state = "high-consensus"
    elif score >= 65:
        state = "review"
    elif armed_categories < 2:
        state = "insufficient-diversity"
    else:
        state = "observe"
    member_probabilities = [member.probability for member in members]
    member_spread = round((max(member_probabilities) - min(member_probabilities)) * 100)
    return EnsemblePrediction(
        ensemble_version=version, members=tuple(members), score=score,
        disagreement=disagreement, independent_families=len(family_members),
        # Reports armed categories only: this number is consumed as "how many
        # independent opinions are behind this score", so counting an unarmed
        # category here would misstate exactly what it is meant to convey.
        independent_categories=armed_categories,
        high_confidence_categories=high_categories, consensus_state=state,
        member_count=len(members), member_spread=member_spread,
        unarmed_categories=tuple(unarmed_categories),
    )


def merge_ensemble_predictions(
    version: str, *predictions: EnsemblePrediction | None,
) -> EnsemblePrediction | None:
    members = [member for prediction in predictions if prediction is not None for member in prediction.members]
    return _ensemble_result(version, members) if members else None


def predict_ember2024(
    directory: Path, sample_path: Path, sample_bytes: bytes | None,
    *, contexts: frozenset[str],
) -> EnsemblePrediction | None:
    result = score_pe_models(directory, sample_path, sample_bytes, contexts)
    if result is None:
        return None
    version, scores = result
    members = [ShadowPrediction(
        model_id=score.model_id, category=score.category, family=score.family,
        model_version=score.model_version, weight=score.weight,
        probability=score.probability,
    ) for score in scores]
    # score_pe_models can legitimately return no scores -- applies_to may rule
    # every member out for this sample. _ensemble_result takes max()/min() over
    # the members, so an empty list raises rather than returning "no opinion".
    return _ensemble_result(version, members) if members else None


def predict_ensemble(
    directory: Path, features: Mapping[str, float], *, contexts: frozenset[str] | None = None,
) -> EnsemblePrediction | None:
    """Evaluate bounded local models; output remains observation-only."""
    if set(features) != set(FEATURE_NAMES):
        return None
    manifest_path = directory / "ensemble.json"
    try:
        stat = manifest_path.stat()
        if stat.st_size <= 0 or stat.st_size > MODEL_MAX_BYTES:
            return None
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        version = _safe_name(manifest.get("ensemble_version"))
        raw_members = manifest.get("members")
        if (
            manifest.get("feature_schema_version") != FEATURE_SCHEMA_VERSION
            or not version or not isinstance(raw_members, list)
            or not 1 <= len(raw_members) <= MAX_ENSEMBLE_MEMBERS
        ):
            return None
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError):
        legacy = predict_shadow(directory / "pe-shadow-model.json", features)
        return _ensemble_result("legacy", [legacy]) if legacy is not None else None

    members: list[ShadowPrediction] = []
    seen_ids: set[str] = set()
    resolved_directory = directory.resolve()
    for item in raw_members:
        if not isinstance(item, dict) or item.get("enabled", True) is not True:
            continue
        model_id = _safe_name(item.get("id"), 48)
        family = _safe_name(item.get("family"), 48)
        model_type = _safe_name(item.get("model_type"), 48)
        category = _safe_name(item.get("category"), 48)
        filename = _safe_name(item.get("file"), 100)
        raw_contexts = item.get("applies_to", ["pe"])
        try:
            weight = float(item.get("weight", 1.0))
        except (TypeError, ValueError):
            continue
        if (
            not model_id or model_id in seen_ids or not family or not category or not filename
            or model_type not in MODEL_CATEGORY_BY_TYPE
            or category != MODEL_CATEGORY_BY_TYPE[model_type]
            or not isinstance(raw_contexts, list) or not 1 <= len(raw_contexts) <= len(MODEL_CONTEXTS)
            or any(value not in MODEL_CONTEXTS for value in raw_contexts)
            or not math.isfinite(weight) or weight <= 0 or weight > 10
        ):
            continue
        active_contexts = contexts or frozenset({"pe"})
        if not active_contexts.intersection(raw_contexts):
            continue
        model_path = (directory / filename).resolve()
        if model_path.parent != resolved_directory:
            continue
        prediction = predict_shadow(
            model_path, features, model_id=model_id, category=category,
            family=family, weight=weight,
        )
        if prediction is not None:
            seen_ids.add(model_id)
            members.append(prediction)
    return _ensemble_result(version, members) if members else None


def model_cache_token(path: Path) -> str:
    """Return a cache namespace token for a model file or ensemble directory."""
    if path.is_dir():
        paths = [path / "ensemble.json", path / "pe-shadow-model.json"]
        try:
            manifest = json.loads((path / "ensemble.json").read_text(encoding="utf-8"))
            for member in list(manifest.get("members") or [])[:MAX_ENSEMBLE_MEMBERS]:
                filename = _safe_name(member.get("file"), 100) if isinstance(member, dict) else None
                if filename:
                    candidate = (path / filename).resolve()
                    if candidate.parent == path.resolve():
                        paths.append(candidate)
        except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError):
            pass
        parts: list[str] = []
        for candidate in paths:
            try:
                stat = candidate.stat()
                parts.append(f"{candidate.name}:{stat.st_mtime_ns}:{stat.st_size}")
            except OSError:
                continue
        if not parts:
            return "none"
        return hashlib.sha256("|".join(sorted(set(parts))).encode("utf-8")).hexdigest()[:20]
    try:
        stat = path.stat()
    except OSError:
        return "none"
    model = _load_linear_model(path)
    if model is None:
        return f"invalid-{stat.st_mtime_ns}-{stat.st_size}"
    return f"{model.version}-{stat.st_mtime_ns}-{stat.st_size}"
