"""Shared training utilities: metrics, calibration, and tuning of the hybrid engine.

Data protocol (identical for URL and email models)
  * Stratified split: 65% train / 15% validation / 20% test.
  * Preprocessing / feature selection is FIT ON TRAIN ONLY.
  * Model selection, probability calibration and hybrid parameters (alpha, thresholds) use the
    VALIDATION set only.
  * The TEST set is used once at the end for the final, unbiased numbers shown in the UI.
"""
from __future__ import annotations

import time
from typing import Callable

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve, fbeta_score)
from sklearn.model_selection import train_test_split

RANDOM_STATE = 42


def split_3way(idx: np.ndarray, y: np.ndarray):
    """Stratified 65/15/20 split returning index arrays."""
    tr_val, te = train_test_split(idx, test_size=0.20, stratify=y[idx], random_state=RANDOM_STATE)
    tr, va = train_test_split(tr_val, test_size=0.15 / 0.80, stratify=y[tr_val], random_state=RANDOM_STATE)
    return tr, va, te


def binary_metrics(y, proba, threshold: float = 0.5) -> dict:
    y = np.asarray(y)
    pred = (np.asarray(proba) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "f2": float(fbeta_score(y, pred, beta=2, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, proba)),
        "pr_auc": float(average_precision_score(y, proba)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "n": int(len(y)),
        "threshold": float(threshold),
    }


def roc_points(y, proba, n: int = 60) -> list[dict]:
    fpr, tpr, _ = roc_curve(y, proba)
    idx = np.unique(np.linspace(0, len(fpr) - 1, n).astype(int))
    return [{"fpr": float(fpr[i]), "tpr": float(tpr[i])} for i in idx]


def evaluate_models(candidates: dict[str, object], Xtr, ytr, Xva, yva, Xte, yte,
                    log: Callable[[str], None] = print) -> tuple[list[dict], dict]:
    """Fit every candidate on TRAIN, report train/validation/test metrics, return fitted models."""
    results, fitted = [], {}
    for name, model in candidates.items():
        t0 = time.time()
        model.fit(Xtr, ytr)
        secs = time.time() - t0
        p_tr, p_va, p_te = (model.predict_proba(X)[:, 1] for X in (Xtr, Xva, Xte))
        res = {
            "name": name,
            "fit_seconds": round(secs, 1),
            "train": binary_metrics(ytr, p_tr),
            "validation": binary_metrics(yva, p_va),
            "test": binary_metrics(yte, p_te),
            "roc_test": roc_points(yte, p_te),
        }
        results.append(res)
        fitted[name] = model
        log(f"  {name:<20} val F1={res['validation']['f1']:.4f} recall={res['validation']['recall']:.4f} "
            f"| test F1={res['test']['f1']:.4f} AUC={res['test']['roc_auc']:.4f}  ({secs:.0f}s)")
    return results, fitted


def select_best(results: list[dict]) -> str:
    """Selection uses VALIDATION metrics only. Security context: missing a phishing item (false
    negative) is costlier than a false alarm, so we maximise F2 (recall-weighted), tie-break ROC-AUC."""
    best = max(results, key=lambda r: (round(r["validation"]["f2"], 4), r["validation"]["roc_auc"]))
    return best["name"]


def calibrate(fitted_model, Xva, yva):
    """Sigmoid (Platt) calibration of an already-fitted model on the validation set."""
    cal = CalibratedClassifierCV(fitted_model, method="sigmoid", cv="prefit")
    cal.fit(Xva, yva)
    return cal


def tune_hybrid(y_val, ml_val, rule_val, max_missed: float = 0.02, alpha_max: float = 0.9) -> dict:
    """Choose alpha, t_safe and t_phish on VALIDATION data.

    alpha   : grid 0..1 (step 0.05) maximising PR-AUC of  alpha*ML + (1-alpha)*Rule.
    t_phish : score threshold maximising F1 for the PHISHING decision.
    t_safe  : highest threshold such that at most `max_missed` (2%) of true phishing items fall
              below it (i.e. would be called SAFE). Items between t_safe and t_phish are SUSPICIOUS.
    These are validation-optimal choices under stated criteria, not claims of global optimality.
    """
    y = np.asarray(y_val)
    grid = []
    for a in np.round(np.arange(0, 1.0001, 0.05), 2):
        s = a * ml_val + (1 - a) * rule_val
        grid.append({"alpha": float(a), "pr_auc": float(average_precision_score(y, s)), "roc_auc": float(roc_auc_score(y, s))})
    unconstrained = max(grid, key=lambda g: (round(g["pr_auc"], 5), g["alpha"]))
    # Design constraint: rules keep >= (1-alpha_max) weight as a domain-knowledge prior, because the
    # training corpora under-represent credential-phishing wording. The unconstrained optimum is reported.
    best = max([g for g in grid if g["alpha"] <= alpha_max], key=lambda g: (round(g["pr_auc"], 5), g["alpha"]))
    alpha = best["alpha"]
    s = alpha * ml_val + (1 - alpha) * rule_val

    ths = np.linspace(0.05, 0.95, 181)
    f1s = [f1_score(y, (s >= t).astype(int), zero_division=0) for t in ths]
    t_phish = float(ths[int(np.argmax(f1s))])

    pos = s[y == 1]
    t_safe = 0.0
    for t in ths:
        if (pos < t).mean() <= max_missed:
            t_safe = float(t)
    if t_safe >= t_phish:
        t_safe = round(t_phish / 2, 3)
    return {
        "alpha": alpha, "alpha_max": alpha_max, "unconstrained_best_alpha": unconstrained["alpha"], "t_safe": round(t_safe, 3), "t_phish": round(t_phish, 3),
        "alpha_grid": grid, "max_missed_phishing_below_t_safe": max_missed,
        "criteria": {
            "alpha": f"maximise PR-AUC of the blended score on the validation set, constrained to alpha <= {alpha_max}",
            "t_phish": "maximise F1 of the PHISHING decision on the validation set",
            "t_safe": f"largest threshold with <= {max_missed:.0%} of validation phishing items scored below it",
        },
    }


def evaluate_hybrid(y, ml, rule, hyb: dict) -> dict:
    """Test-set comparison: ML only, rules only, hybrid (flagged = SUSPICIOUS+PHISHING, and PHISHING only)."""
    y = np.asarray(y)
    a = hyb["alpha"]
    s = a * ml + (1 - a) * rule

    def m(score, thr):
        pred = (score >= thr).astype(int)
        return {
            "precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)), "accuracy": float(accuracy_score(y, pred)),
        }
    out = {
        "ml_only@0.5": m(ml, 0.5),
        "rules_only@t_phish": m(rule, hyb["t_phish"]),
        "hybrid_phishing@t_phish": {**m(s, hyb["t_phish"]), "roc_auc": float(roc_auc_score(y, s))},
        "hybrid_flagged@t_safe": m(s, hyb["t_safe"]),
        "rules_only_roc_auc": float(roc_auc_score(y, rule)),
        "ml_only_roc_auc": float(roc_auc_score(y, ml)),
    }
    # 3-class distribution on the test set
    cls = np.where(s >= hyb["t_phish"], 2, np.where(s >= hyb["t_safe"], 1, 0))
    out["three_class_breakdown"] = {
        name: {"true_phishing": int(((cls == c) & (y == 1)).sum()), "true_legitimate": int(((cls == c) & (y == 0)).sum())}
        for c, name in enumerate(["SAFE", "SUSPICIOUS", "PHISHING"])
    }
    return out
