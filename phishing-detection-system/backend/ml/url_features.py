"""Reusable, STATIC URL feature extraction.

Security: this module only parses the URL string. It never performs DNS lookups,
HTTP requests or redirects. Every submitted URL is treated as untrusted input.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit, unquote

import tldextract

# Offline extractor: uses the bundled public-suffix snapshot, never the network.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink", "t.ly", "lnkd.in", "s.id",
}
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account", "update", "secure",
    "security", "banking", "bank", "confirm", "password", "passwd", "credential", "wallet",
    "paypal", "ebay", "amazon", "apple", "microsoft", "office365", "webscr", "suspend",
    "unlock", "recover", "billing", "invoice", "payment", "helpdesk", "alert",
    "authenticate", "validate", "otp", "reward", "prize", "bonus", "gift",
]
BRANDS = [
    "paypal", "apple", "amazon", "microsoft", "google", "facebook", "netflix", "instagram",
    "whatsapp", "linkedin", "dropbox", "docusign", "chase", "wellsfargo", "citibank",
    "hdfc", "icici", "sbi", "paytm", "outlook", "office365", "dhl", "fedex", "usps",
]
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim",
    "work", "loan", "men", "download", "review", "stream", "science", "party", "icu", "cyou",
    "buzz", "rest", "monster",
}
SPECIAL_CHARS = set("@?=&%#$!*~+;:,|\\^[]{}<>")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HEX_IP_RE = re.compile(r"^0x[0-9a-f]+$", re.I)
ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
STANDARD_PORTS = {None, 80, 443}


class URLValidationError(ValueError):
    """Raised when the submitted string cannot be safely parsed as an http(s) URL."""


def normalize_url(raw: str, max_length: int = 2048) -> str:
    """Validate and normalise untrusted input. Does NOT contact the URL."""
    if raw is None:
        raise URLValidationError("URL is empty.")
    url = raw.strip()
    if not url:
        raise URLValidationError("URL is empty.")
    if len(url) > max_length:
        raise URLValidationError(f"URL is longer than {max_length} characters.")
    if any(ord(c) < 32 or ord(c) == 127 for c in url) or re.search(r"\s", url):
        raise URLValidationError("URL contains whitespace or control characters.")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        scheme = url.split("://", 1)[0].lower()
        if scheme not in {"http", "https"}:
            raise URLValidationError(
                f"Scheme '{scheme}://' is not supported. Only http/https URLs can be analysed.")
    else:
        m = re.match(r"^(javascript|data|vbscript|file|mailto|tel|blob):", url, re.I)
        if m:
            raise URLValidationError(
                f"Scheme '{m.group(1).lower()}:' is not supported. Only http/https URLs can be analysed.")
        url = "http://" + url
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises ValueError on an invalid port
    except ValueError as exc:
        raise URLValidationError(f"URL could not be parsed: {exc}") from exc
    if not parts.hostname:
        raise URLValidationError("URL has no host name.")
    return url


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def split_scheme(url: str) -> tuple[str, str]:
    if "://" in url:
        scheme, rest = url.split("://", 1)
        return scheme.lower(), rest
    return "", url


# Features fed to the ML model. `has_https` is deliberately excluded because the training
# corpora are stored without a scheme; it is still extracted and used by the rule engine.
ML_FEATURES = [
    "url_length", "domain_length", "path_length", "query_length", "num_dots", "num_hyphens",
    "num_underscores", "num_slashes", "num_digits", "digit_ratio", "num_special_chars",
    "has_ip_host", "has_at_symbol", "is_shortener", "num_subdomains", "keyword_count",
    "has_unusual_port", "num_encoded_chars", "has_punycode", "suspicious_tld",
    "domain_entropy", "url_entropy", "path_depth", "num_params", "brand_in_subdomain_or_path",
    "hyphens_in_domain", "digits_in_domain", "longest_token_length", "has_double_slash_in_path",
    "has_file_extension_php_html",
]

FEATURE_DESCRIPTIONS = {
    "url_length": "Total number of characters in the URL",
    "domain_length": "Length of the host name",
    "path_length": "Length of the path component",
    "query_length": "Length of the query string",
    "num_dots": "Number of dots in the URL",
    "num_hyphens": "Number of hyphens in the URL",
    "num_underscores": "Number of underscores in the URL",
    "num_slashes": "Number of slashes in the URL",
    "num_digits": "Number of digits in the URL",
    "digit_ratio": "Share of characters that are digits",
    "num_special_chars": "Count of special characters (@ ? = & % # ...)",
    "has_ip_host": "Host is an IP address instead of a domain name",
    "has_at_symbol": "URL contains an '@' symbol",
    "is_shortener": "Domain is a known URL-shortening service",
    "num_subdomains": "Number of sub-domain labels before the registered domain",
    "keyword_count": "Number of suspicious keywords (login, verify, secure ...)",
    "has_unusual_port": "Uses a non-standard port",
    "num_encoded_chars": "Number of %XX percent-encoded characters",
    "has_punycode": "Host uses punycode / internationalised characters (xn--)",
    "suspicious_tld": "Top-level domain is frequently abused",
    "domain_entropy": "Randomness (Shannon entropy) of the host name",
    "url_entropy": "Randomness (Shannon entropy) of the whole URL",
    "path_depth": "Number of path segments",
    "num_params": "Number of query parameters",
    "brand_in_subdomain_or_path": "A well-known brand name appears outside the registered domain",
    "hyphens_in_domain": "Hyphens inside the host name",
    "digits_in_domain": "Digits inside the host name",
    "longest_token_length": "Longest alphanumeric token in the URL",
    "has_double_slash_in_path": "A '//' appears inside the path (possible redirect trick)",
    "has_file_extension_php_html": "Path points to a .php/.html/.asp style page",
    "has_https": "URL uses HTTPS (rules only; not an ML input)",
}


def extract_url_features(url: str) -> dict:
    """Return numeric features plus a `_meta` dict of descriptive fields for the UI."""
    url = normalize_url(url)
    scheme, _ = split_scheme(url)
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    query = parts.query or ""
    port = parts.port

    ext = _EXTRACT(host)
    registered = ext.registered_domain or host
    subdomain = ext.subdomain or ""
    suffix = (ext.suffix or "").lower()
    is_ip = bool(IPV4_RE.match(host)) or bool(HEX_IP_RE.match(host)) or ":" in host
    sub_labels = [s for s in subdomain.split(".") if s] if not is_ip else []

    # Features are computed on the scheme-less form so they match the training data.
    bare = url.split("://", 1)[1]
    low = bare.lower()
    decoded = unquote(low)

    kw_hits = sorted({k for k in SUSPICIOUS_KEYWORDS if k in decoded})
    tokens = re.findall(r"[a-z0-9]+", low)
    non_domain_text = (subdomain + "." + path + "?" + query).lower() if not is_ip else (path + query).lower()
    reg_label = ext.domain.lower() if ext.domain else ""
    brand_hits = [b for b in BRANDS if b in non_domain_text and b not in reg_label]

    f = {
        "url_length": len(bare),
        "domain_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": bare.count("."),
        "num_hyphens": bare.count("-"),
        "num_underscores": bare.count("_"),
        "num_slashes": bare.count("/"),
        "num_digits": sum(c.isdigit() for c in bare),
        "digit_ratio": round(sum(c.isdigit() for c in bare) / max(len(bare), 1), 4),
        "num_special_chars": sum(c in SPECIAL_CHARS for c in bare),
        "has_ip_host": int(is_ip),
        "has_at_symbol": int("@" in bare),
        "is_shortener": int(registered in SHORTENERS),
        "num_subdomains": len(sub_labels),
        "keyword_count": len(kw_hits),
        "has_unusual_port": int(port not in STANDARD_PORTS),
        "num_encoded_chars": len(ENCODED_RE.findall(bare)),
        "has_punycode": int("xn--" in host),
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS),
        "domain_entropy": round(_entropy(host), 4),
        "url_entropy": round(_entropy(low), 4),
        "path_depth": len([p for p in path.split("/") if p]),
        "num_params": len([p for p in query.split("&") if p]),
        "brand_in_subdomain_or_path": int(bool(brand_hits)),
        "hyphens_in_domain": host.count("-"),
        "digits_in_domain": sum(c.isdigit() for c in host),
        "longest_token_length": max((len(t) for t in tokens), default=0),
        "has_double_slash_in_path": int("//" in path),
        "has_file_extension_php_html": int(bool(re.search(r"\.(php|html?|aspx?|jsp|cgi)(\?|$)", path.lower()))),
        # rule-engine only:
        "has_https": int(scheme == "https"),
    }
    f["_meta"] = {
        "normalized_url": url, "host": host, "registered_domain": registered,
        "subdomain": subdomain, "tld": suffix, "port": port, "scheme": scheme,
        "keywords_found": kw_hits, "brands_found": brand_hits,
    }
    return f


def feature_vector(features: dict) -> list[float]:
    return [float(features[k]) for k in ML_FEATURES]
