"""Model registry: loads trained bundles from disk and produces calibrated probabilities.

If a bundle does not exist the registry reports `available=False`; callers must then show
a MODEL NOT TRAINED / DEMO MODE warning. No random or fabricated probabilities are ever returned.
"""
from __future__ import annotations

import json
import logging
import threading

import joblib
import numpy as np

from config import settings
from ml.email_features import compose_message
from ml.url_features import feature_vector

log = logging.getLogger("phishing.models")
DEFAULT_THRESHOLDS = {"alpha": 0.0, "t_safe": 0.25, "t_phish": 0.55}   # rules-only fallback heuristics (UNTUNED)


class ModelRegistry:
    def __init__(self):
        self._bundles: dict[str, dict | None] = {}
        self._lock = threading.Lock()

    def load(self, task: str, force: bool = False) -> dict | None:
        with self._lock:
            if task in self._bundles and not force:
                return self._bundles[task]
            path = settings.models_dir / f"{task}_model.joblib"
            bundle = None
            if path.exists():
                try:
                    bundle = joblib.load(path)
                    log.info("Loaded %s model: %s", task, bundle.get("model_name"))
                except Exception:      # corrupted / incompatible pickle
                    log.exception("Could not load %s model", task)
            self._bundles[task] = bundle
            return bundle

    def status(self) -> dict:
        out = {}
        for t in ("url", "email"):
            b = self.load(t)
            out[t] = {"trained": b is not None, "model_name": b.get("model_name") if b else None,
                      "trained_at": b.get("trained_at") if b else None, "hybrid": b.get("hybrid") if b else None}
        return out

    # ---- URL
    def predict_url(self, features: dict) -> dict:
        b = self.load("url")
        if not b:
            return {"available": False}
        x_raw = np.array([feature_vector(features)])
        x = b["scaler"].transform(x_raw)
        p = float(b["calibrated"].predict_proba(x)[0, 1])
        raw_p = float(b["model"].predict_proba(x)[0, 1])
        return {"available": True, "probability": p, "uncalibrated_probability": raw_p, "model_name": b["model_name"],
                "x_scaled": x, "x_raw": x_raw}

    # ---- email
    def predict_email(self, subject: str, body: str) -> dict:
        b = self.load("email")
        if not b:
            return {"available": False}
        text = compose_message(subject, body)
        x = b["prep"].transform([text])
        p = float(b["calibrated"].predict_proba(x)[0, 1])
        raw_p = float(b["model"].predict_proba(x)[0, 1])
        return {"available": True, "probability": p, "uncalibrated_probability": raw_p, "model_name": b["model_name"],
                "x": x, "text": text}

    def thresholds(self, task: str) -> dict:
        b = self.load(task)
        return dict(b["hybrid"]) if b else dict(DEFAULT_THRESHOLDS)


def load_metrics(task: str) -> dict | None:
    p = settings.models_dir / f"{task}_metrics.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        log.exception("bad metrics file %s", p)
        return None


registry = ModelRegistry()
