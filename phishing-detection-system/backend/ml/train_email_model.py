"""Train and compare e-mail classifiers (TF-IDF + linguistic indicators).

Run from the backend folder:
    python -m ml.download_datasets --email          # Enron-Spam (spam vs ham), or use --email-csv
    python -m ml.train_email_model
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from config import settings
from ml.common import (RANDOM_STATE, calibrate, evaluate_hybrid, evaluate_models, select_best, split_3way, tune_hybrid)
from ml.email_features import build_preprocessor, compose_message, selected_feature_names
from security.rules import aggregate_rule_risk, run_email_rules


def main(dataset: str | None = None):
    path = dataset or str(settings.datasets_dir / "emails.csv")
    print(f"Loading {path}")
    df = pd.read_csv(path).dropna(subset=["text", "label"])
    df["subject"] = df.get("subject", "").fillna("") if "subject" in df else ""
    df["label"] = df["label"].astype(int)
    texts = [compose_message(s, b) for s, b in zip(df.subject, df.text)]
    y = df.label.values

    print("Computing rule-based risk for every message ...")
    rule = np.array([aggregate_rule_risk(run_email_rules(s, b)[0]) for s, b in zip(df.subject, df.text)])

    tr, va, te = split_3way(np.arange(len(df)), y)
    T = np.array(texts, dtype=object)
    prep = build_preprocessor()
    print("Fitting TF-IDF + feature selection on TRAIN only ...")
    Xtr = prep.fit_transform(T[tr], y[tr])
    Xva, Xte = prep.transform(T[va]), prep.transform(T[te])
    print(f"  selected {Xtr.shape[1]} features")

    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=3000, C=3.0, solver="liblinear", random_state=RANDOM_STATE),
        "Decision Tree": DecisionTreeClassifier(max_depth=25, min_samples_leaf=3, random_state=RANDOM_STATE),
        "Random Forest": RandomForestClassifier(n_estimators=150, min_samples_leaf=2, max_features="sqrt", n_jobs=-1, random_state=RANDOM_STATE),
    }
    print("Training and evaluating ...")
    results, fitted = evaluate_models(candidates, Xtr, y[tr], Xva, y[va], Xte, y[te])
    best_name = select_best(results)
    print(f"Selected on validation F2: {best_name}")
    best = fitted[best_name]
    cal = calibrate(best, Xva, y[va])
    p_va, p_te = cal.predict_proba(Xva)[:, 1], cal.predict_proba(Xte)[:, 1]

    hyb = tune_hybrid(y[va], p_va, rule[va])
    hyb["test"] = evaluate_hybrid(y[te], p_te, rule[te], hyb)
    print(f"Hybrid: alpha={hyb['alpha']}  t_safe={hyb['t_safe']}  t_phish={hyb['t_phish']}")
    print("  test hybrid:", {k: round(v, 4) for k, v in hyb["test"]["hybrid_phishing@t_phish"].items()})

    names = selected_feature_names(prep)
    rng = np.random.default_rng(RANDOM_STATE)
    bg = Xtr[rng.choice(Xtr.shape[0], size=min(150, Xtr.shape[0]), replace=False)].toarray()
    imp = best.feature_importances_ if hasattr(best, "feature_importances_") else np.abs(best.coef_[0])
    top = np.argsort(-imp)[:20]
    fi = [{"feature": names[i], "importance": float(imp[i])} for i in top]

    bundle = {"task": "email", "prep": prep, "model": best, "calibrated": cal, "model_name": best_name,
              "feature_names": names, "background": bg, "class_names": ["legitimate", "phishing"],
              "hybrid": {k: hyb[k] for k in ("alpha", "t_safe", "t_phish")},
              "trained_at": datetime.now(timezone.utc).isoformat()}
    settings.models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, settings.models_dir / "email_model.joblib", compress=3)

    prov = {}
    pf = settings.datasets_dir / "provenance.json"
    if pf.exists():
        prov = json.loads(pf.read_text()).get("emails", {})
    metrics = {
        "task": "email", "dataset_name": "Enron-Spam (spam vs ham)" if "enron" in str(prov.get("source", "")).lower() else str(prov.get("source", path)),
        "dataset": {**prov, "usable_rows": int(len(df)), "n_train": int(len(tr)), "n_val": int(len(va)), "n_test": int(len(te))},
        "split": "stratified 65% train / 15% validation / 20% test (random_state=42); TF-IDF and chi2 selection fitted on train only",
        "models": results, "selected_model": best_name,
        "selection_criterion": "highest validation F2 (recall-weighted), tie-break validation ROC-AUC",
        "calibration": "sigmoid (Platt) on validation set; hybrid uses calibrated probability",
        "hybrid": hyb, "feature_importance": fi, "evaluation_date": datetime.now(timezone.utc).isoformat(),
        "notes": ["The positive class of Enron-Spam is spam/scam mail, not curated phishing. Re-train with a phishing corpus for a phishing-specific model.",
                  "Training metrics are for over-fitting diagnosis only; report TEST metrics."],
    }
    (settings.models_dir / "email_metrics.json").write_text(json.dumps(metrics, indent=2))
    print("Saved models/email_model.joblib and models/email_metrics.json")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", help="CSV with columns subject,text,label (1=phishing/spam)")
    main(ap.parse_args().dataset)
