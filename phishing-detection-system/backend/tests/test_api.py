import pytest
from fastapi.testclient import TestClient

from config import settings


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "local_store_dir", tmp_path)
    monkeypatch.setattr(settings, "mongodb_uri", "")
    import database.store as st
    st._store = None
    from main import app
    with TestClient(app) as c:
        yield c
    st._store = None


def test_health(client):
    j = client.get("/api/health").json()
    assert j["status"] == "ok" and j["storage"]["mode"] == "local_file" and j["storage"]["persistent"] is False


def test_url_validation_errors(client):
    assert client.post("/api/analyze/url", json={"url": "javascript:alert(1)"}).status_code == 422
    assert client.post("/api/analyze/url", json={"url": ""}).status_code == 422
    assert client.post("/api/analyze/url", json={}).status_code == 422
    assert client.post("/api/analyze/url", json={"url": "x" * 5000}).status_code == 422


def test_email_validation(client):
    assert client.post("/api/analyze/email", json={"subject": "s", "body": "   "}).status_code == 422
    assert client.post("/api/analyze/email", json={"subject": "s"}).status_code == 422


def test_url_analysis_history_roundtrip_and_privacy(client):
    r = client.post("/api/analyze/url", json={"url": "http://10.1.1.1/login?token=SECRET123"})
    assert r.status_code == 200
    j = r.json()
    assert j["classification"] in {"SAFE", "SUSPICIOUS", "PHISHING"} and 0 <= j["risk_score"] <= 100
    assert "SECRET123" not in j["input_summary"]
    assert any(f["rule_id"] == "URL_IP_HOST" for f in j["rules"]["findings"])
    h = client.get("/api/history").json()
    assert h["total"] == 1
    d = client.get(f"/api/history/{j['scan_id']}").json()
    assert "raw_input" not in d and "SECRET123" not in str(d)
    assert client.get("/api/history?classification=SAFE&input_type=email").json()["total"] == 0
    assert client.delete(f"/api/history/{j['scan_id']}").status_code == 200
    assert client.get(f"/api/history/{j['scan_id']}").status_code == 404


def test_email_body_not_stored_by_default(client):
    body = "Please confirm your password immediately. Secret-phrase-xyz."
    j = client.post("/api/analyze/email", json={"subject": "Hello", "body": body}).json()
    d = client.get(f"/api/history/{j['scan_id']}").json()
    assert "Secret-phrase-xyz" not in str(d)


def test_dashboard_stats_reflect_real_records(client):
    assert client.get("/api/dashboard/stats").json()["total_urls"] == 0
    client.post("/api/analyze/url", json={"url": "https://www.wikipedia.org"})
    client.post("/api/analyze/email", json={"subject": "hi", "body": "Hello, lunch tomorrow?"})
    s = client.get("/api/dashboard/stats").json()
    assert s["total_urls"] == 1 and s["total_emails"] == 1
    assert client.delete("/api/history").json()["deleted_count"] == 2


def test_models_performance_endpoint(client):
    j = client.get("/api/models/performance").json()
    assert set(j) == {"url", "email"}
