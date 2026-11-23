from ml.email_features import clean_text, indicator_vector, INDICATOR_NAMES
from security.rules import (aggregate_rule_risk, run_email_rules, run_url_rules, highlight_spans, analyze_sender, Finding)
from ml.url_features import extract_url_features
from services.hybrid import classify, combine


def test_clean_text_strips_html_urls_numbers():
    out = clean_text("<p>Visit http://evil.com NOW!! Call 12345 or mail a@b.com</p>")
    assert "urltoken" in out and "emailtoken" in out and "12345" not in out and "<" not in out


def test_indicator_vector_shape_and_values():
    v = indicator_vector("URGENT! Verify your password immediately. http://1.2.3.4/x")
    assert len(v) == len(INDICATOR_NAMES)
    assert v[INDICATOR_NAMES.index("credential_terms")] >= 1 and v[INDICATOR_NAMES.index("has_ip_url")] == 1


def test_url_rules_fire_on_ip_host():
    ids = {f.rule_id for f in run_url_rules(extract_url_features("http://10.0.0.5/login"))}
    assert "URL_IP_HOST" in ids


def test_url_rules_quiet_on_plain_https_site():
    assert run_url_rules(extract_url_features("https://www.wikipedia.org/")) == []


def test_email_rules_detect_otp_request_and_highlight():
    f, spans, _ = run_email_rules("Action required", "Please share your OTP and password immediately.", None)
    ids = {x.rule_id for x in f}
    assert {"MSG_CREDENTIAL_REQUEST", "MSG_URGENCY"} <= ids
    assert any(s["category"] == "credential" for s in spans)


def test_benign_email_has_no_findings():
    f, _, _ = run_email_rules("Lunch", "Hi Sam, shall we have lunch on Friday? Thanks, Ravi", "ravi@company.com")
    assert f == []


def test_sender_impersonation():
    ids = {x.rule_id for x in analyze_sender("PayPal Support <help@paypa1-secure.top>")}
    assert "SENDER_IMPERSONATION" in ids
    assert not analyze_sender("PayPal <service@paypal.com>")


def test_noisy_or_aggregation():
    fs = [Finding("a", "a", "low", 0.5, ""), Finding("b", "b", "low", 0.5, "")]
    assert abs(aggregate_rule_risk(fs) - 0.75) < 1e-9
    assert aggregate_rule_risk([]) == 0.0


def test_risk_combination_and_thresholds():
    thr = {"alpha": 0.7, "t_safe": 0.2, "t_phish": 0.5}
    assert abs(combine(0.8, 0.4, thr) - (0.7 * 0.8 + 0.3 * 0.4)) < 1e-9
    assert combine(None, 0.4, thr) == 0.4            # demo mode: rules only
    assert classify(0.1, 0.2, 0.5) == "SAFE" and classify(0.3, 0.2, 0.5) == "SUSPICIOUS" and classify(0.5, 0.2, 0.5) == "PHISHING"
