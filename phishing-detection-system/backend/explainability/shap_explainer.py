"""SHAP explanations computed from the real trained model and the real input.

* Tree models (Random Forest / Decision Tree) → shap.TreeExplainer (exact)
* Logistic Regression                          → shap.LinearExplainer (exact, with background data)

SHAP explains the underlying classifier BEFORE Platt calibration, so its contributions describe the
raw model score; the calibrated probability shown elsewhere is a monotonic re-mapping of it.
Any failure returns {"available": False, "reason": ...} — values are never fabricated.
"""
from __future__ import annotations

import logging

import numpy as np
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from ml.url_features import FEATURE_DESCRIPTIONS

log = logging.getLogger("phishing.shap")
_CACHE: dict[int, object] = {}


def _explainer(model, background):
    key = id(model)
    if key not in _CACHE:
        if isinstance(model, (RandomForestClassifier, DecisionTreeClassifier)):
            _CACHE[key] = ("tree", shap.TreeExplainer(model))
        elif isinstance(model, LogisticRegression):
            _CACHE[key] = ("linear", shap.LinearExplainer(model, background))
        else:
            raise TypeError(f"SHAP is not configured for {type(model).__name__}")
    return _CACHE[key]


def _compute(model, x_dense: np.ndarray, background) -> tuple[np.ndarray, float, str]:
    kind, ex = _explainer(model, background)
    if kind == "tree":
        sv = ex.shap_values(x_dense, check_additivity=False)
        if isinstance(sv, list):
            sv = sv[1]
        sv = np.asarray(sv)
        if sv.ndim == 3:
            sv = sv[:, :, 1]
        base = ex.expected_value
        base = float(base[1] if np.ndim(base) else base)
        unit = "probability"
    else:
        sv = np.asarray(ex.shap_values(x_dense))
        if sv.ndim == 3:
            sv = sv[:, :, 1]
        base = float(np.ravel(ex.expected_value)[0])
        unit = "log-odds"
    return sv[0], base, unit


def _pack(items: list[dict], base: float, unit: str, model_name: str, top_n: int) -> dict:
    items = sorted(items, key=lambda d: -abs(d["shap_value"]))[:top_n]
    return {
        "available": True, "method": "SHAP", "model": model_name, "unit": unit, "base_value": base,
        "features": items,
        "note": ("Positive values push the prediction toward PHISHING; negative values push toward LEGITIMATE. "
                 "SHAP explains the underlying classifier before probability calibration."),
    }


def explain_url(bundle: dict, features: dict, x_scaled: np.ndarray, top_n: int = 12) -> dict:
    try:
        vals, base, unit = _compute(bundle["model"], x_scaled, bundle["background_scaled"])
        names = bundle["feature_names"]
        items = [{
            "feature": n, "description": FEATURE_DESCRIPTIONS.get(n, n), "value": float(features[n]),
            "shap_value": float(v), "direction": "increases risk" if v > 0 else "decreases risk",
        } for n, v in zip(names, vals) if abs(v) > 1e-9]
        return _pack(items, base, unit, bundle["model_name"], top_n)
    except Exception as exc:
        log.exception("SHAP (url) failed")
        return {"available": False, "method": "SHAP", "reason": f"SHAP could not be computed: {exc}"}


def explain_email(bundle: dict, x_sparse, top_n: int = 12) -> dict:
    try:
        x = x_sparse.toarray()
        vals, base, unit = _compute(bundle["model"], x, bundle["background"])
        names = bundle["feature_names"]
        items = []
        for i in np.argsort(-np.abs(vals))[: top_n * 3]:
            if abs(vals[i]) < 1e-9:
                continue
            present = bool(x[0, i] > 0)
            items.append({
                "feature": names[i], "value": float(x[0, i]), "present": present, "shap_value": float(vals[i]),
                "direction": "increases risk" if vals[i] > 0 else "decreases risk",
                "description": "present in this message" if present else "absent from this message (its absence shifts the score)",
            })
        return _pack(items, base, unit, bundle["model_name"], top_n)
    except Exception as exc:
        log.exception("SHAP (email) failed")
        return {"available": False, "method": "SHAP", "reason": f"SHAP could not be computed: {exc}"}
