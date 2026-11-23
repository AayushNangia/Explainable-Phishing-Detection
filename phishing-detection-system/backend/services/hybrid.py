"""Hybrid detection engine: ML probability + explicit security rules → classification + advisory."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from config import settings
from explainability import lime_explainer, shap_explainer
from ml.email_features import compose_message
from ml.prediction import registry
from ml.url_features import FEATURE_DESCRIPTIONS, ML_FEATURES, extract_url_features
from security.rules import (Finding, aggregate_rule_risk, run_email_rules, run_url_rules)

DISCLAIMER = ("Automated classification is not a guarantee of safety. A SAFE result means no strong phishing "
              "indicators were found by this system; it does not prove that a link or message is trustworthy.")
FORMULA = "Final risk = α × ML probability + (1 − α) × Rule risk"


def classify(score: float, t_safe: float, t_phish: float) -> str:
    return "PHISHING" if score >= t_phish else "SUSPICIOUS" if score >= t_safe else "SAFE"


def combine(ml_prob: float | None, rule_risk: float, thr: dict) -> float:
    if ml_prob is None:
        return rule_risk                       # rules-only (DEMO mode); alpha is 0 by definition
    a = thr["alpha"]
    return a * ml_prob + (1 - a) * rule_risk


# ----------------------------------------------------------------------------- advisory
def build_advisory(classification: str, findings: list[Finding], input_type: str) -> dict:
    ids = {f.rule_id for f in findings}
    obj = "link" if input_type == "url" else "message"
    if classification == "PHISHING":
        headline = "High phishing risk — do not interact with this " + obj + "."
        actions = [
            f"Do not click the link{'s' if input_type == 'email' else ''} or open any attachments." if input_type == "email" else "Do not open this link or visit the site.",
            "Do not enter your password, OTP or banking details.",
            "Verify the sender or organisation through an official channel (type the official address yourself or call a number from their website).",
            "Report it: forward to your IT/security team, or report as phishing in your mail provider. In India you can report at cybercrime.gov.in or call 1930.",
        ]
    elif classification == "SUSPICIOUS":
        headline = "Some phishing indicators were found — verify before trusting this " + obj + "."
        actions = [
            "Verify the sender and the domain independently before doing anything.",
            "Avoid sharing sensitive information until authenticity is confirmed.",
            "Do not proceed to log in via this " + obj + "; open the official site by typing its address yourself.",
        ]
    else:
        headline = "No major phishing indicators were detected."
        actions = [
            "Still verify the source before sharing sensitive information.",
            "Keep your browser, mail client and anti-malware software up to date.",
        ]
    extra = []
    if "MSG_CREDENTIAL_REQUEST" in ids:
        extra.append("Genuine organisations never ask for passwords or OTPs by e-mail/SMS — never share them.")
    if "MSG_FINANCIAL_REQUEST" in ids:
        extra.append("Do not send card, bank or tax details in reply; contact your bank using the number on your card.")
    if "SENDER_IMPERSONATION" in ids or "URL_BRAND_MISUSE" in ids:
        extra.append("The " + obj + " imitates a well-known brand. Go to the brand's official website directly instead.")
    if "MSG_URGENCY" in ids or "MSG_THREAT" in ids:
        extra.append("Pressure and threats are manipulation tactics. Take time to verify before acting.")
    if "URL_IP_HOST" in ids:
        extra.append("Links that point to a raw IP address instead of a domain name are rarely legitimate.")
    if "URL_SHORTENER" in ids:
        extra.append("Shortened links hide the destination; ask the sender for the full address.")
    if "URL_NO_HTTPS" in ids:
        extra.append("The page does not use HTTPS, so anything you type could be intercepted.")
    if "MSG_SUSPICIOUS_LINKS" in ids:
        extra.append("Hover over links to inspect the real address before clicking (do not click).")
    if classification != "SAFE" and input_type == "email":
        extra.append("If you already clicked or replied, change the affected passwords and contact your bank/IT team.")
    return {"headline": headline, "actions": actions, "contextual": extra, "disclaimer": DISCLAIMER}


# ----------------------------------------------------------------------------- shared assembly
def _ml_findings_from_shap(shap_res: dict, limit: int = 5) -> list[dict]:
    if not shap_res.get("available"):
        return []
    pos = [f for f in shap_res["features"] if f["shap_value"] > 0][:limit]
    return [{"source": "ml", "feature": f["feature"], "description": f.get("description", ""),
             "value": f["value"], "contribution": f["shap_value"]} for f in pos]


def _summary(classification, ml_prob, rule_risk, findings, shap_res, mode):
    parts = []
    if ml_prob is not None:
        parts.append(f"The ML model estimated a {ml_prob:.0%} calibrated phishing probability.")
    else:
        parts.append("No trained model is available, so the result is based on security rules only (DEMO MODE).")
    if findings:
        top = ", ".join(f.title for f in sorted(findings, key=lambda f: -f.weight)[:3])
        parts.append(f"Rules raised {len(findings)} alert(s) (rule risk {rule_risk:.0%}); strongest: {top}.")
    else:
        parts.append("No security rules were triggered.")
    if shap_res.get("available"):
        up = [f["feature"] for f in shap_res["features"] if f["shap_value"] > 0][:3]
        if up:
            parts.append("Features that most increased ML risk: " + ", ".join(up) + ".")
    return f"Classified {classification}. " + " ".join(parts)


def _mode(ml_available: bool) -> dict:
    return {"ml_available": ml_available,
            "label": "HYBRID (ML + rules)" if ml_available else "DEMO MODE — MODEL NOT TRAINED (rules only)",
            "warning": None if ml_available else
            "No trained model was found. Run the training scripts (see README). Results below use security rules only and are NOT machine-learning predictions."}


def mask_url_for_storage(url: str) -> str:
    p = urlsplit(url)
    s = (p.hostname or "") + (p.path or "")
    if p.query:
        s += "?[query hidden]"
    return s[:300]


# ----------------------------------------------------------------------------- URL
def analyze_url(raw_url: str) -> dict:
    feats = extract_url_features(raw_url)               # validates + normalises; raises URLValidationError
    meta = feats["_meta"]
    findings = run_url_rules(feats)
    rule_risk = aggregate_rule_risk(findings)
    pred = registry.predict_url(feats)
    thr = registry.thresholds("url")
    ml_prob = pred["probability"] if pred["available"] else None
    score = combine(ml_prob, rule_risk, thr)
    cls = classify(score, thr["t_safe"], thr["t_phish"])

    shap_res = {"available": False, "method": "SHAP", "reason": "No trained model — SHAP requires a model."}
    lime_res = {"available": False, "method": "LIME", "reason": "No trained model — LIME requires a model."}
    if pred["available"]:
        b = registry.load("url")
        shap_res = shap_explainer.explain_url(b, feats, pred["x_scaled"])
        lime_res = lime_explainer.explain_url(b, pred["x_raw"])

    adv = build_advisory(cls, findings, "url")
    shown = {k: {"value": feats[k], "description": FEATURE_DESCRIPTIONS[k], "used_by_ml": k in ML_FEATURES}
             for k in list(ML_FEATURES) + ["has_https"]}
    return {
        "scan_id": uuid.uuid4().hex, "input_type": "url", "input_summary": mask_url_for_storage(meta["normalized_url"]),
        "display_input": meta["normalized_url"], "created_at": datetime.now(timezone.utc).isoformat(),
        "classification": cls, "risk_score": round(score * 100, 1), "mode": _mode(pred["available"]),
        "ml": {"available": pred["available"], "probability": ml_prob, "model_name": pred.get("model_name"),
               "probability_type": "calibrated probability (Platt scaling on validation data)",
               "uncalibrated_probability": pred.get("uncalibrated_probability"), "findings": _ml_findings_from_shap(shap_res)},
        "rules": {"risk": rule_risk, "findings": [f.to_dict() for f in sorted(findings, key=lambda f: -f.weight)]},
        "hybrid": {"alpha": thr["alpha"], "t_safe": thr["t_safe"], "t_phish": thr["t_phish"], "formula": FORMULA,
                   "ml_component": (thr["alpha"] * ml_prob) if ml_prob is not None else 0.0,
                   "rule_component": ((1 - thr["alpha"]) * rule_risk) if ml_prob is not None else rule_risk,
                   "tuned_on_validation": ml_prob is not None},
        "features": shown, "url_parts": {k: meta[k] for k in ("host", "registered_domain", "subdomain", "tld", "scheme")},
        "explanations": {"shap": shap_res, "lime": lime_res},
        "explanation_summary": _summary(cls, ml_prob, rule_risk, findings, shap_res, None),
        "advisory": adv,
    }


# ----------------------------------------------------------------------------- email
def analyze_email(subject: str, body: str, sender: str | None) -> dict:
    findings, spans, links = run_email_rules(subject, body, sender)
    rule_risk = aggregate_rule_risk(findings)
    pred = registry.predict_email(subject, body)
    thr = registry.thresholds("email")
    ml_prob = pred["probability"] if pred["available"] else None
    score = combine(ml_prob, rule_risk, thr)
    cls = classify(score, thr["t_safe"], thr["t_phish"])

    shap_res = {"available": False, "method": "SHAP", "reason": "No trained model — SHAP requires a model."}
    lime_res = {"available": False, "method": "LIME", "reason": "No trained model — LIME requires a model."}
    if pred["available"]:
        b = registry.load("email")
        shap_res = shap_explainer.explain_email(b, pred["x"])
        lime_res = lime_explainer.explain_email(b, pred["text"])

    nlp = {
        "word_count": len(body.split()), "link_count": len(links),
        "linguistic_note": ("Spelling or grammar mistakes alone do not prove phishing; they are weak signals "
                            "and are only considered together with other evidence."),
    }
    from security.rules import lexicon_counts
    nlp["indicator_counts"] = lexicon_counts(compose_message(subject, body))
    sender_domain = sender.split("@")[-1].strip(" >").lower() if sender and "@" in sender else None
    return {
        "scan_id": uuid.uuid4().hex, "input_type": "email", "input_summary": (subject.strip() or "(no subject)")[:200],
        "created_at": datetime.now(timezone.utc).isoformat(), "sender_domain": sender_domain,
        "classification": cls, "risk_score": round(score * 100, 1), "mode": _mode(pred["available"]),
        "ml": {"available": pred["available"], "probability": ml_prob, "model_name": pred.get("model_name"),
               "probability_type": "calibrated probability (Platt scaling on validation data)",
               "uncalibrated_probability": pred.get("uncalibrated_probability"), "findings": _ml_findings_from_shap(shap_res)},
        "rules": {"risk": rule_risk, "findings": [f.to_dict() for f in sorted(findings, key=lambda f: -f.weight)]},
        "hybrid": {"alpha": thr["alpha"], "t_safe": thr["t_safe"], "t_phish": thr["t_phish"], "formula": FORMULA,
                   "ml_component": (thr["alpha"] * ml_prob) if ml_prob is not None else 0.0,
                   "rule_component": ((1 - thr["alpha"]) * rule_risk) if ml_prob is not None else rule_risk,
                   "tuned_on_validation": ml_prob is not None},
        "highlights": spans, "highlight_text": compose_message(subject, body), "links": links, "nlp": nlp,
        "explanations": {"shap": shap_res, "lime": lime_res},
        "explanation_summary": _summary(cls, ml_prob, rule_risk, findings, shap_res, None),
        "advisory": build_advisory(cls, findings, "email"),
    }
