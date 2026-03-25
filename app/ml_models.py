import json
import os
import threading
import sys
from dataclasses import dataclass
from typing import Any, Optional

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
import joblib

from config import Config, ML_BASE_DIR, ML_MODEL_DIR, logger


ROLE_MODEL_PATH = os.path.join(ML_MODEL_DIR, "role_based_model.joblib")
ROLE_META_PATH = os.path.join(ML_MODEL_DIR, "role_based_metadata.json")
DISPOSABLE_MODEL_PATH = os.path.join(ML_MODEL_DIR, "disposable_model.joblib")
DISPOSABLE_META_PATH = os.path.join(ML_MODEL_DIR, "disposable_metadata.json")
SPOOF_MODEL_PATH = os.path.join(ML_MODEL_DIR, "spoof_catboost.cbm")
SPOOF_META_PATH = os.path.join(ML_MODEL_DIR, "spoof_metadata.json")
PROVIDER_MODEL_PATH = os.path.join(ML_MODEL_DIR, "provider_catboost.cbm")
PROVIDER_META_PATH = os.path.join(ML_MODEL_DIR, "provider_metadata.json")
DELIVERABILITY_MODEL_PATH = os.path.join(ML_MODEL_DIR, "deliverability_catboost.cbm")
DELIVERABILITY_META_PATH = os.path.join(ML_MODEL_DIR, "deliverability_metadata.json")


@dataclass
class BinaryPrediction:
    label: bool
    score: float
    threshold: float


@dataclass
class MultiClassPrediction:
    label: str
    confidence: float
    probabilities: dict[str, float] | None = None


class MLModelService:
    def __init__(self) -> None:
        self._loaded = False
        self._lock = threading.Lock()
        self._available = False
        self._load_error: Optional[str] = None
        self.role_model = None
        self.role_meta: dict[str, Any] = {}
        self.disposable_model = None
        self.disposable_meta: dict[str, Any] = {}
        self.spoof_model = None
        self.spoof_meta: dict[str, Any] = {}
        self.provider_model = None
        self.provider_meta: dict[str, Any] = {}
        self.deliverability_model = None
        self.deliverability_meta: dict[str, Any] = {}

    @property
    def available(self) -> bool:
        self._ensure_loaded()
        return self._available

    def _read_json(self, path: str) -> dict[str, Any]:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _load_catboost(self, path: str) -> CatBoostClassifier:
        model = CatBoostClassifier()
        model.load_model(path)
        return model

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            if not Config.ML_ENABLED:
                self._load_error = "ML integration disabled by configuration."
                self._loaded = True
                self._available = False
                return
            try:
                if ML_BASE_DIR not in sys.path and os.path.isdir(ML_BASE_DIR):
                    sys.path.insert(0, ML_BASE_DIR)
                self.role_model = joblib.load(ROLE_MODEL_PATH)
                self.role_meta = self._read_json(ROLE_META_PATH)
                self.disposable_model = joblib.load(DISPOSABLE_MODEL_PATH)
                self.disposable_meta = self._read_json(DISPOSABLE_META_PATH)
                self.spoof_model = self._load_catboost(SPOOF_MODEL_PATH)
                self.spoof_meta = self._read_json(SPOOF_META_PATH)
                self.provider_model = self._load_catboost(PROVIDER_MODEL_PATH)
                self.provider_meta = self._read_json(PROVIDER_META_PATH)
                self.deliverability_model = self._load_catboost(DELIVERABILITY_MODEL_PATH)
                self.deliverability_meta = self._read_json(DELIVERABILITY_META_PATH)
                self._available = True
                logger.info("ML model artifacts loaded successfully from %s", ML_MODEL_DIR)
            except Exception as exc:
                self._load_error = str(exc)
                self._available = False
                logger.error("Failed to load ML models from %s: %s", ML_MODEL_DIR, exc, exc_info=True)
            finally:
                self._loaded = True

    def warmup(self) -> None:
        self._ensure_loaded()

    def _predict_binary_text(self, model: Any, meta: dict[str, Any], value: str) -> Optional[BinaryPrediction]:
        self._ensure_loaded()
        if not self._available or not value:
            return None
        score = float(model.predict_proba([value])[0][1])
        threshold = float(meta.get("threshold", 0.5))
        return BinaryPrediction(label=score >= threshold, score=score, threshold=threshold)

    def predict_role_based(self, local_part: str) -> Optional[BinaryPrediction]:
        return self._predict_binary_text(self.role_model, self.role_meta, str(local_part).lower())

    def predict_disposable(self, domain: str) -> Optional[BinaryPrediction]:
        return self._predict_binary_text(self.disposable_model, self.disposable_meta, str(domain).lower())

    def _build_common_features(
        self,
        *,
        email: str,
        domain: str,
        mx_host: str,
        smtp_code: str,
        force_live: bool,
        temp_error: bool,
        source: str,
        provider: str = "Unknown Provider",
        accept_all: str = "No",
        duration_s: float = 0.0,
    ) -> dict[str, Any]:
        local_part = email.split("@", 1)[0].lower() if "@" in email else str(email).lower()
        domain = (domain or "").lower()
        return {
            "domain": domain,
            "mx_host": str(mx_host or "").lower(),
            "smtp_code": str(smtp_code or ""),
            "force_live": str(bool(force_live)),
            "temp_error": str(bool(temp_error)),
            "source": str(source),
            "provider": str(provider or "Unknown Provider"),
            "accept_all": str(accept_all or "No"),
            "duration_s": float(duration_s or 0.0),
            "local_len": len(local_part),
            "domain_len": len(domain),
            "digit_ratio": (sum(ch.isdigit() for ch in local_part) / max(len(local_part), 1)),
            "dot_count": local_part.count("."),
            "tld": domain.split(".")[-1] if "." in domain else domain,
        }

    def predict_provider(
        self,
        *,
        email: str,
        domain: str,
        mx_host: str,
        smtp_code: str,
        force_live: bool,
        temp_error: bool,
        source: str,
    ) -> Optional[MultiClassPrediction]:
        self._ensure_loaded()
        if not self._available:
            return None
        row = self._build_common_features(
            email=email,
            domain=domain,
            mx_host=mx_host,
            smtp_code=smtp_code,
            force_live=force_live,
            temp_error=temp_error,
            source=source,
        )
        features = self.provider_meta.get("feature_columns", [])
        frame = pd.DataFrame([{feature: row.get(feature, "") for feature in features}])
        proba = self.provider_model.predict_proba(frame)[0]
        label = str(self.provider_model.predict(frame)[0][0])
        probabilities = {
            str(class_name): float(score)
            for class_name, score in zip(self.provider_model.classes_, proba)
        }
        return MultiClassPrediction(label=label, confidence=float(np.max(proba)), probabilities=probabilities)

    def predict_deliverability(
        self,
        *,
        email: str,
        domain: str,
        mx_host: str,
        smtp_code: str,
        force_live: bool,
        temp_error: bool,
        source: str,
        provider: str,
        accept_all: bool,
        duration_s: float,
    ) -> Optional[MultiClassPrediction]:
        self._ensure_loaded()
        if not self._available:
            return None
        row = self._build_common_features(
            email=email,
            domain=domain,
            mx_host=mx_host,
            smtp_code=smtp_code,
            force_live=force_live,
            temp_error=temp_error,
            source=source,
            provider=provider,
            accept_all="Yes" if accept_all else "No",
            duration_s=duration_s,
        )
        features = self.deliverability_meta.get("feature_columns", [])
        frame = pd.DataFrame([{feature: row.get(feature, "") for feature in features}])
        proba = self.deliverability_model.predict_proba(frame)[0]
        label = str(self.deliverability_model.predict(frame)[0][0])
        probabilities = {
            str(class_name): float(score)
            for class_name, score in zip(self.deliverability_model.classes_, proba)
        }
        return MultiClassPrediction(label=label, confidence=float(np.max(proba)), probabilities=probabilities)

    def predict_spoof(self, label: str, brand: str) -> Optional[BinaryPrediction]:
        self._ensure_loaded()
        if not self._available or not label or not brand:
            return None
        features = self.spoof_meta.get("feature_columns", [])
        row = build_spoof_features(label.lower(), brand.lower())
        frame = pd.DataFrame([{feature: row.get(feature, 0) for feature in features}])
        score = float(self.spoof_model.predict_proba(frame)[0][1])
        threshold = float(self.spoof_meta.get("threshold", 0.5))
        return BinaryPrediction(label=score >= threshold, score=score, threshold=threshold)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def jaro_winkler(s1: str, s2: str, prefix_scale: float = 0.1) -> float:
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0
    match_distance = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    transpositions //= 2
    jaro = (matches / len1 + matches / len2 + (matches - transpositions) / matches) / 3.0

    prefix = 0
    for c1, c2 in zip(s1, s2):
        if c1 == c2:
            prefix += 1
        else:
            break
    prefix = min(4, prefix)
    return jaro + prefix * prefix_scale * (1 - jaro)


def build_spoof_features(domain_label: str, brand: str) -> dict[str, Any]:
    prefix_len = 0
    for c1, c2 in zip(domain_label, brand):
        if c1 == c2:
            prefix_len += 1
        else:
            break
    return {
        "len_label": len(domain_label),
        "len_brand": len(brand),
        "len_diff": abs(len(domain_label) - len(brand)),
        "edit_distance": levenshtein(domain_label, brand),
        "jaro_winkler": jaro_winkler(domain_label, brand),
        "prefix_len": prefix_len,
        "digit_count": sum(ch.isdigit() for ch in domain_label),
        "hyphen": 1 if "-" in domain_label else 0,
    }


_service = MLModelService()


def get_ml_models() -> MLModelService:
    return _service
