"""Train and compare URL phishing classifiers.

Run from the backend folder:
    python -m ml.download_datasets --url          # once
    python -m ml.train_url_model

Outputs: models/url_model.joblib and models/url_metrics.json (genuine, computed metrics).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from config import settings
from ml.common import (RANDOM_STATE, calibrate, evaluate_hybrid, evaluate_models, select_best, split_3way, tune_hybrid)
from ml.url_features import ML_FEATURES, URLValidationError, extract_url_features, feature_vector
from security.rules import aggregate_rule_risk, run_url_rules


def main(dataset: str | None = None):
    path = dataset or str(settings.datasets_dir / "urls.csv")
    print(f"Loading {path}")
    df = pd.read_csv(path).dropna(subset=["url", "label"]).drop_duplicates("url")
    df["label"] = df["label"].astype(int)
    assert set(df.label.unique()) <= {0, 1}, "labels must be 0 (legitimate) / 1 (phishing)"

    print("Extracting features + rule risk (static analysis, no network) ...")
    rows, rule_risk, keep = [], [], []
    for i, u in enumerate(df.url.tolist()):
        try:
            f = extract_url_features(u)
        except URLValidationError:
            continue
        rows.append(feature_vector(f))
        rule_risk.append(aggregate_rule_risk(run_url_rules(f)))
        keep.append(i)
    df = df.iloc[keep].reset_index(drop=True)
    X, y, rule = np.array(rows), df.label.values, np.array(rule_risk)
    print(f"  {len(df)} usable rows  (phishing={int(y.sum())}, legitimate={int((y == 0).sum())})")

    tr, va, te = split_3way(np.arange(len(df)), y)
    scaler = StandardScaler().fit(X[tr])                      # fit on TRAIN ONLY
    Xs = scaler.transform(X)

    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=2000, C=1.0, random_state=RANDOM_STATE),
        "Decision Tree": DecisionTreeClassifier(max_depth=14, min_samples_leaf=5, random_state=RANDOM_STATE),
        "Random Forest": RandomForestClassifier(n_estimators=200, min_samples_leaf=2, n_jobs=-1, random_state=RANDOM_STATE),
    }
    print("Training and evaluating ...")
    results, fitted = evaluate_models(candidates, Xs[tr], y[tr], Xs[va], y[va], Xs[te], y[te])
    best_name = select_best(results)
    print(f"Selected on validation F2: {best_name}")

    best = fitted[best_name]
    cal = calibrate(best, Xs[va], y[va])
    p_va, p_te = cal.predict_proba(Xs[va])[:, 1], cal.predict_proba(Xs[te])[:, 1]

    hyb = tune_hybrid(y[va], p_va, rule[va])
    hyb["test"] = evaluate_hybrid(y[te], p_te, rule[te], hyb)
    print(f"Hybrid: alpha={hyb['alpha']}  t_safe={hyb['t_safe']}  t_phish={hyb['t_phish']}")
    print("  test hybrid:", {k: round(v, 4) for k, v in hyb["test"]["hybrid_phishing@t_phish"].items()})

    rng = np.random.default_rng(RANDOM_STATE)
    bg_idx = rng.choice(tr, size=min(200, len(tr)), replace=False)
    lime_idx = rng.choice(tr, size=min(3000, len(tr)), replace=False)
    importance = None
    if hasattr(best, "feature_importances_"):
        importance = best.feature_importances_
    elif hasattr(best, "coef_"):
        importance = np.abs(best.coef_[0])
    fi = sorted(zip(ML_FEATURES, importance.tolist()), key=lambda t: -t[1])[:15] if importance is not None else []

    bundle = {
        "task": "url", "feature_names": ML_FEATURES, "scaler": scaler, "model": best, "calibrated": cal,
        "model_name": best_name, "background_scaled": Xs[bg_idx], "lime_train_raw": X[lime_idx],
        "hybrid": {k: hyb[k] for k in ("alpha", "t_safe", "t_phish")},
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    settings.models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, settings.models_dir / "url_model.joblib", compress=3)

    prov = json.loads((settings.datasets_dir / "provenance.json").read_text()).get("urls", {}) if (settings.datasets_dir / "provenance.json").exists() else {}
    metrics = {
        "task": "url", "dataset_name": "Phishing.Database (phishing) + faizann24 'good' URLs (legitimate)",
        "dataset": {**prov, "usable_rows": int(len(df)), "n_train": int(len(tr)), "n_val": int(len(va)), "n_test": int(len(te))},
        "split": "stratified 65% train / 15% validation / 20% test (random_state=42)",
        "ml_features": ML_FEATURES, "models": results, "selected_model": best_name,
        "selection_criterion": "highest validation F2 (recall-weighted), tie-break validation ROC-AUC",
        "calibration": "sigmoid (Platt) on validation set; hybrid uses calibrated probability",
        "hybrid": hyb, "feature_importance": [{"feature": f, "importance": v} for f, v in fi],
        "evaluation_date": datetime.now(timezone.utc).isoformat(),
        "notes": ["Training metrics are shown for over-fitting diagnosis only; use TEST metrics for reporting.",
                  "Legitimate and phishing URLs come from different collections - test scores are optimistic vs. real traffic."],
    }
    (settings.models_dir / "url_metrics.json").write_text(json.dumps(metrics, indent=2))
    print("Saved models/url_model.joblib and models/url_metrics.json")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", help="CSV with columns url,label (1=phishing)")
    main(ap.parse_args().dataset)
