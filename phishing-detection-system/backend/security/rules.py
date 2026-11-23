"""Explicit, human-readable security rules (the 'rule-based' half of the hybrid engine).

Each rule returns a Finding with a weight in (0, 1]. Independent evidence is combined with a
noisy-OR:  rule_risk = 1 - prod(1 - w_i)  so more evidence raises risk, but never above 1.
Weights are expert-chosen heuristics (documented in the README); they are NOT learned.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from math import prod

from ml.url_features import (
    BRANDS, SHORTENERS, SUSPICIOUS_TLDS, extract_url_features, URLValidationError,
)

# ----------------------------------------------------------------------------- lexicons
LEXICON: dict[str, list[str]] = {
    "urgency": [
        "urgent", "immediately", "right away", "as soon as possible", "asap", "act now",
        "within 24 hours", "within 48 hours", "last warning", "final notice", "final warning",
        "expires today", "expire soon", "limited time", "time sensitive", "don't delay",
        "failure to respond", "respond now", "action required", "immediate action",
    ],
    "threat": [
        "account will be suspended", "account has been suspended", "account suspended",
        "account will be closed", "account will be locked", "account has been locked",
        "account is locked", "account limited", "permanently disabled", "permanently closed",
        "legal action", "unauthorized access", "unusual activity", "suspicious activity",
        "security breach", "your account is at risk", "will be terminated", "deactivated",
        "unauthorised login", "unauthorized login", "compromised",
    ],
    "credential": [
        "password", "passcode", "otp", "one-time password", "one time password",
        "verification code", "security code", "pin number", "your pin", "login details",
        "login credentials", "username and password", "sign in to verify", "confirm your identity",
        "verify your identity", "verify your account", "confirm your account", "cvv",
        "security question", "mother's maiden name", "enter your credentials",
    ],
    "financial": [
        "credit card", "debit card", "card number", "bank account", "account number",
        "routing number", "ssn", "social security", "wire transfer", "bank details",
        "billing information", "payment details", "update your payment", "refund", "ifsc",
        "net banking", "netbanking", "upi pin", "tax refund", "gift card", "bitcoin",
    ],
    "reward": [
        "you have won", "you've won", "winner", "congratulations", "prize", "lottery",
        "claim your", "free gift", "reward", "cash prize", "selected to receive",
        "you are eligible", "inheritance", "unclaimed funds", "jackpot",
    ],
    "generic_greeting": [
        "dear customer", "dear user", "dear account holder", "dear valued customer",
        "dear member", "dear client", "dear sir/madam", "dear sir or madam", "dear friend",
    ],
    "click_bait": [
        "click here", "click the link", "click below", "follow the link", "open the attachment",
        "download the attachment", "see attached", "tap the link", "log in here", "sign in here",
    ],
}

EMAIL_BRANDS = {
    "paypal": ["paypal.com"], "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "apple": ["apple.com", "icloud.com"], "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com"],
    "google": ["google.com", "gmail.com"], "netflix": ["netflix.com"], "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"], "linkedin": ["linkedin.com"], "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"], "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"], "sbi": ["sbi.co.in", "onlinesbi.com"], "paytm": ["paytm.com"],
    "fedex": ["fedex.com"], "dhl": ["dhl.com"], "chase": ["chase.com"], "wells fargo": ["wellsfargo.com"],
}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me",
             "protonmail.com", "mail.com", "gmx.com", "yandex.com", "rediffmail.com"}

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"')\]]+")
EMAIL_ADDR_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


# ----------------------------------------------------------------------------- data model
@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str            # low | medium | high
    weight: float
    description: str
    evidence: list[str] = field(default_factory=list)
    source: str = "rule"

    def to_dict(self) -> dict:
        return asdict(self)


def _sev(w: float) -> str:
    return "high" if w >= 0.4 else "medium" if w >= 0.2 else "low"


def aggregate_rule_risk(findings: list[Finding]) -> float:
    """Noisy-OR aggregation of rule weights into a 0..1 risk."""
    if not findings:
        return 0.0
    return float(1.0 - prod(1.0 - f.weight for f in findings))


def _f(rule_id, title, w, desc, evidence=None) -> Finding:
    return Finding(rule_id, title, _sev(w), w, desc, evidence or [])


# ----------------------------------------------------------------------------- URL rules
def run_url_rules(features: dict) -> list[Finding]:
    meta = features["_meta"]
    out: list[Finding] = []
    host = meta["host"]

    if features["has_ip_host"]:
        out.append(_f("URL_IP_HOST", "IP address used instead of a domain name", 0.55,
                      "Legitimate services almost always use registered domain names. IP-based links hide the real owner.",
                      [host]))
    if features["has_at_symbol"]:
        out.append(_f("URL_AT_SYMBOL", "'@' symbol inside the URL", 0.40,
                      "Browsers ignore everything before '@', so attackers use it to disguise the real destination.", ["@"]))
    if features["is_shortener"]:
        out.append(_f("URL_SHORTENER", "URL-shortening service", 0.25,
                      "The real destination is hidden behind a short link and cannot be inspected statically.", [meta["registered_domain"]]))
    if features["num_subdomains"] >= 3:
        out.append(_f("URL_MANY_SUBDOMAINS", "Unusually many sub-domains", 0.30,
                      "Deeply nested sub-domains are used to make a malicious host look like a trusted brand.",
                      [meta["subdomain"]]))
    elif features["num_subdomains"] == 2:
        out.append(_f("URL_SUBDOMAINS", "Several sub-domain levels", 0.08,
                      "Multiple sub-domain levels are sometimes used to imitate a trusted site.", [meta["subdomain"]]))
    if meta["scheme"] == "http":
        out.append(_f("URL_NO_HTTPS", "Connection is not encrypted (HTTP)", 0.12,
                      "HTTPS is not proof of safety, but credentials sent over plain HTTP can be intercepted.", ["http://"]))
    kws = meta["keywords_found"]
    if len(kws) >= 2:
        out.append(_f("URL_KEYWORDS", "Multiple credential/security keywords in the URL", 0.30,
                      "Words such as 'login', 'verify' and 'secure' are commonly stuffed into phishing URLs.", kws[:6]))
    elif len(kws) == 1:
        out.append(_f("URL_KEYWORD", "Sensitive keyword in the URL", 0.10,
                      "A single keyword is weak evidence on its own; many legitimate pages contain such words.", kws))
    if features["has_unusual_port"]:
        out.append(_f("URL_UNUSUAL_PORT", "Non-standard port number", 0.35,
                      "Ordinary websites use ports 80/443. Other ports are unusual for user-facing login pages.", [str(meta["port"])]))
    if features["num_encoded_chars"] >= 3:
        out.append(_f("URL_ENCODING", "Heavy percent-encoding / obfuscation", 0.20,
                      "Many %XX sequences can hide the real content of the URL from users and filters.",
                      [f"{features['num_encoded_chars']} encoded characters"]))
    if features["has_punycode"]:
        out.append(_f("URL_PUNYCODE", "Internationalised (punycode) domain", 0.35,
                      "Look-alike Unicode characters can imitate well-known domains (homograph attack).", [host]))
    if features["suspicious_tld"]:
        out.append(_f("URL_SUSPICIOUS_TLD", "Frequently abused top-level domain", 0.22,
                      "Some low-cost TLDs are over-represented in phishing campaigns. This alone is weak evidence.", [f".{meta['tld']}"]))
    if features["brand_in_subdomain_or_path"]:
        out.append(_f("URL_BRAND_MISUSE", "Well-known brand name outside the registered domain", 0.50,
                      "The URL mentions a famous brand in the sub-domain/path, but the registered domain is different — a classic impersonation pattern.",
                      [f"{b} (real domain: {meta['registered_domain']})" for b in meta["brands_found"][:3]]))
    if features["url_length"] > 120:
        out.append(_f("URL_LONG", "Very long URL", 0.12, "Long URLs can hide the real domain among many characters.",
                      [f"{features['url_length']} characters"]))
    if features["hyphens_in_domain"] >= 3:
        out.append(_f("URL_HYPHENS", "Many hyphens in the domain name", 0.18,
                      "Hyphen-heavy domains (e.g. secure-login-update-account.com) often imitate legitimate wording.", [host]))
    if features["domain_entropy"] > 3.9 and features["domain_length"] > 18:
        out.append(_f("URL_RANDOM_DOMAIN", "Domain name looks randomly generated", 0.15,
                      "High character randomness is typical of automatically generated throw-away domains.",
                      [f"entropy {features['domain_entropy']:.2f}"]))
    if features["has_double_slash_in_path"]:
        out.append(_f("URL_DOUBLE_SLASH", "'//' inside the path", 0.12,
                      "A double slash after the host can indicate a redirect trick or embedded second URL.", ["//"]))
    if features["digits_in_domain"] >= 5 and not features["has_ip_host"]:
        out.append(_f("URL_DIGITS_DOMAIN", "Many digits in the domain", 0.12,
                      "Digit-heavy domains are uncommon for established brands.", [host]))
    return out


# ----------------------------------------------------------------------------- email rules
def _find_spans(text: str, category: str) -> list[dict]:
    low = text.lower()
    spans = []
    for phrase in LEXICON[category]:
        pat = r"(?<![a-z])" + re.escape(phrase) + r"(?![a-z])"
        for m in re.finditer(pat, low):
            spans.append({"start": m.start(), "end": m.end(), "text": text[m.start():m.end()], "category": category})
    return spans


def highlight_spans(text: str) -> list[dict]:
    """Non-overlapping, sorted phrase spans for UI highlighting."""
    spans: list[dict] = []
    for cat in LEXICON:
        spans.extend(_find_spans(text, cat))
    spans.sort(key=lambda s: (s["start"], -(s["end"] - s["start"])))
    merged, last_end = [], -1
    for s in spans:
        if s["start"] >= last_end:
            merged.append(s)
            last_end = s["end"]
    return merged


def lexicon_counts(text: str) -> dict[str, int]:
    return {cat: len(_find_spans(text, cat)) for cat in LEXICON}


def extract_links(text: str, limit: int = 15) -> list[str]:
    links = []
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?")
        if u not in links:
            links.append(u)
        if len(links) >= limit:
            break
    return links


def analyze_sender(sender: str | None) -> list[Finding]:
    if not sender or not sender.strip():
        return []
    sender = sender.strip()
    m = EMAIL_ADDR_RE.search(sender)
    if not m:
        return [_f("SENDER_INVALID", "Sender address is not a valid e-mail address", 0.15,
                   "A missing or malformed sender address is a common spoofing trait.", [sender[:80]])]
    domain = m.group(1).lower()
    display = sender[: m.start()].lower()
    out: list[Finding] = []
    # brand named in display name or domain label, but domain is not the brand's real domain
    for brand, legit_domains in EMAIL_BRANDS.items():
        label = brand.replace(" ", "")
        in_display = brand in display or label in display
        in_domain = label in domain.replace("-", "").replace(".", "")
        is_real = any(domain == d or domain.endswith("." + d) for d in legit_domains)
        if (in_display or in_domain) and not is_real:
            out.append(_f("SENDER_IMPERSONATION", f"Sender appears to impersonate {brand.title()}", 0.50,
                          "The sender name or domain references a well-known brand, but the domain does not belong to it.",
                          [f"{domain}"]))
            break
    if domain in FREE_MAIL and any(w in display for w in ("support", "security", "bank", "service", "billing", "admin", "helpdesk")):
        out.append(_f("SENDER_FREEMAIL_OFFICIAL", "Official-sounding name sent from a free mail provider", 0.30,
                      "Organisations rarely send account-security messages from free webmail addresses.", [sender[:80]]))
    tld = domain.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        out.append(_f("SENDER_TLD", "Sender domain uses a frequently abused TLD", 0.18,
                      "Weak evidence on its own, but over-represented in phishing.", [domain]))
    if domain.count("-") >= 2 or sum(c.isdigit() for c in domain) >= 4:
        out.append(_f("SENDER_ODD_DOMAIN", "Unusual sender domain pattern", 0.15,
                      "Hyphen- or digit-heavy domains are commonly used for look-alike senders.", [domain]))
    return out


def run_email_rules(subject: str, body: str, sender: str | None = None) -> tuple[list[Finding], list[dict], list[dict]]:
    """Returns (findings, highlighted_spans over subject+body, link_reports)."""
    text = f"{subject}\n{body}"
    out: list[Finding] = []
    counts = lexicon_counts(text)
    spans = highlight_spans(text)

    def ev(cat):  # distinct phrases that matched
        return sorted({s["text"].lower() for s in spans if s["category"] == cat})[:6]

    if counts["credential"]:
        out.append(_f("MSG_CREDENTIAL_REQUEST", "Requests passwords, OTPs or identity verification", 0.55,
                      "Legitimate organisations do not ask you to disclose passwords or one-time codes by e-mail or message.",
                      ev("credential")))
    if counts["financial"]:
        out.append(_f("MSG_FINANCIAL_REQUEST", "Mentions financial / payment information", 0.35 if counts["financial"] > 1 else 0.22,
                      "Requests for card, bank or tax details are a standard phishing goal. Context matters — this term alone is not proof.",
                      ev("financial")))
    if counts["threat"]:
        out.append(_f("MSG_THREAT", "Threatening or account-suspension language", 0.38,
                      "Fear of losing access is a pressure tactic used to stop recipients from thinking carefully.", ev("threat")))
    if counts["urgency"]:
        out.append(_f("MSG_URGENCY", "Urgency / deadline pressure", 0.25 if counts["urgency"] > 1 else 0.18,
                      "Artificial deadlines push people to act before verifying the message.", ev("urgency")))
    if counts["reward"]:
        out.append(_f("MSG_REWARD", "Prize, reward or windfall claim", 0.30,
                      "Unexpected prizes and refunds are common lures.", ev("reward")))
    if counts["generic_greeting"]:
        out.append(_f("MSG_GENERIC_GREETING", "Generic greeting instead of your name", 0.10,
                      "Mass-mailed messages often avoid personal details. Weak evidence on its own.", ev("generic_greeting")))
    if counts["click_bait"]:
        out.append(_f("MSG_CALL_TO_ACTION", "Prompts you to click a link or open an attachment", 0.12,
                      "Calls to action are normal in legitimate mail too; they matter when combined with other indicators.", ev("click_bait")))

    letters = [c for c in text if c.isalpha()]
    caps_ratio = sum(c.isupper() for c in letters) / max(len(letters), 1)
    if (caps_ratio > 0.45 and len(letters) > 40) or "!!" in text:
        out.append(_f("MSG_STYLE", "Aggressive formatting (ALL CAPS / repeated '!')", 0.08,
                      "Stylistic cues are weak signals. Poor grammar or formatting alone does NOT prove a message is phishing.",
                      [f"{caps_ratio:.0%} upper-case letters"]))

    # links
    link_reports = []
    risky_links = []
    for link in extract_links(text):
        try:
            feats = extract_url_features(link)
            lf = [x for x in run_url_rules(feats) if x.rule_id != "URL_NO_HTTPS"]
            risk = aggregate_rule_risk(lf)
            link_reports.append({"url": link, "rule_risk": round(risk, 3), "findings": [x.title for x in lf]})
            if risk >= 0.40:
                risky_links.append(link)
        except URLValidationError:
            link_reports.append({"url": link, "rule_risk": 0.0, "findings": ["could not be parsed"]})
    if risky_links:
        out.append(_f("MSG_SUSPICIOUS_LINKS", "Message contains suspicious link(s)", 0.40,
                      "One or more links trigger URL security rules (see link analysis). Links were analysed statically and never opened.",
                      [l[:90] for l in risky_links[:3]]))
    elif len(link_reports) >= 4:
        out.append(_f("MSG_MANY_LINKS", "Many links in a single message", 0.08, "Unusually many links can indicate bulk or lure content.",
                      [f"{len(link_reports)} links"]))

    out.extend(analyze_sender(sender))
    return out, spans, link_reports
