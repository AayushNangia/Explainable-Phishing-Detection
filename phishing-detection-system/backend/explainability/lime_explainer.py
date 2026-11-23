"""LIME local explanations of the CALIBRATED model probability for one input.

* URL   → LimeTabularExplainer over the numeric URL features (training sample stored in the bundle)
* Email → LimeTextExplainer over the raw message text (perturbs words, re-runs the full NLP pipeline)

Failures return {"available": False, "reason": ...}; weights are never invented.
LIME is a local linear approximation built from random perturbations, so results can vary slightly;
we fix the random seed for reproducibility.
"""
from __future__ import annotations

import logging

import numpy as np
from lime.lime_tabular import LimeTabularExplainer
from lime.lime_text import LimeTextExplainer

from ml.url_features import ML_FEATURES, FEATURE_DESCRIPTIONS

log = logging.getLogger("phishing.lime")
_TAB: dict[int, LimeTabularExplainer] = {}
NOTE = ("LIME fits a simple local model around this single input. Positive weights push toward PHISHING, "
        "negative toward LEGITIMATE. It is an approximation and may vary between runs.")


def explain_url(bundle: dict, x_raw: np.ndarray, top_n: int = 10, num_samples: int = 1500) -> dict:
    try:
        key = id(bundle)
        if key not in _TAB:
            _TAB[key] = LimeTabularExplainer(
                bundle["lime_train_raw"], feature_names=ML_FEATURES, class_names=["legitimate", "phishing"],
                mode="classification", discretize_continuous=True, random_state=42)
        scaler, cal = bundle["scaler"], bundle["calibrated"]
        fn = lambda a: cal.predict_proba(scaler.transform(a))
        exp = _TAB[key].explain_instance(x_raw[0], fn, num_features=top_n, num_samples=num_samples, labels=(1,))
        items = []
        for rule, w in exp.as_list(label=1):
            fname = next((f for f in sorted(ML_FEATURES, key=len, reverse=True) if f in rule), rule)
            items.append({"feature": rule, "base_feature": fname, "description": FEATURE_DESCRIPTIONS.get(fname, ""),
                          "weight": float(w), "direction": "increases risk" if w > 0 else "decreases risk"})
        return {"available": True, "method": "LIME", "kind": "tabular", "local_prediction": float(exp.local_pred[0]) if hasattr(exp, "local_pred") else None,
                "features": items, "note": NOTE}
    except Exception as exc:
        log.exception("LIME (url) failed")
        return {"available": False, "method": "LIME", "reason": f"LIME could not be computed: {exc}"}


def explain_email(bundle: dict, text: str, top_n: int = 10, num_samples: int = 600) -> dict:
    try:
        text = text[:3000]
        if len(text.split()) < 3:
            return {"available": False, "method": "LIME", "reason": "Message is too short for a meaningful word-level LIME explanation."}
        prep, cal = bundle["prep"], bundle["calibrated"]
        fn = lambda texts: cal.predict_proba(prep.transform(list(texts)))
        explainer = LimeTextExplainer(class_names=["legitimate", "phishing"], random_state=42, bow=True)
        exp = explainer.explain_instance(text, fn, num_features=top_n, num_samples=num_samples, labels=(1,))
        items = [{"feature": w, "weight": float(v), "direction": "increases risk" if v > 0 else "decreases risk"}
                 for w, v in exp.as_list(label=1)]
        return {"available": True, "method": "LIME", "kind": "text", "features": items, "note": NOTE}
    except Exception as exc:
        log.exception("LIME (email) failed")
        return {"available": False, "method": "LIME", "reason": f"LIME could not be computed: {exc}"}
