import pytest
from ml.url_features import URLValidationError, extract_url_features, normalize_url


def test_basic_features():
    f = extract_url_features("https://www.example.com/path/page.html?a=1&b=2")
    assert f["has_https"] == 1 and f["has_ip_host"] == 0 and f["num_params"] == 2
    assert f["path_depth"] == 2 and f["num_subdomains"] == 1


def test_ip_host_and_at_symbol():
    assert extract_url_features("http://192.168.0.1/login")["has_ip_host"] == 1
    assert extract_url_features("http://paypal.com@evil.example.org/")["has_at_symbol"] == 1


def test_subdomains_and_port_and_encoding():
    f = extract_url_features("http://a.b.c.example.com:8081/%61%62%63")
    assert f["num_subdomains"] == 3 and f["has_unusual_port"] == 1 and f["num_encoded_chars"] == 3


def test_brand_misuse():
    f = extract_url_features("http://paypal.com.verify.example.top/login")
    assert f["brand_in_subdomain_or_path"] == 1 and f["suspicious_tld"] == 1


def test_scheme_less_gets_http():
    assert normalize_url("example.com/x").startswith("http://")


@pytest.mark.parametrize("bad", ["", "   ", "javascript:alert(1)", "data:text/html,hi", "ftp://x.com/a",
                                 "http://exa mple.com", "http://x.com:99999", "http://", "a" * 3000])
def test_rejects_unsafe_input(bad):
    with pytest.raises(URLValidationError):
        normalize_url(bad)
