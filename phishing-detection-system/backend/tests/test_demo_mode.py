import pytest
from fastapi.testclient import TestClient

from config import settings


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "local_store_dir", tmp_path)
    monkeypatch.setattr(settings, "models_dir", tmp_path / "no_models")
    import database.store as st
    from ml.prediction import registry
    st._store = None
    registry._bundles.clear()
    from main import app
    with TestClient(app) as c:
        yield c
    st._store = None
    registry._bundles.clear()


def test_untrained_models_show_demo_mode_and_no_fake_ml(client):
    assert client.get("/api/health").json()["demo_mode"] is True
    j = client.post("/api/analyze/url", json={"url": "http://10.0.0.1/login"}).json()
    assert j["mode"]["ml_available"] is False and "MODEL NOT TRAINED" in j["mode"]["label"]
    assert j["ml"]["probability"] is None and j["explanations"]["shap"]["available"] is False
    assert j["explanations"]["lime"]["available"] is False and j["rules"]["findings"]
    e = client.post("/api/analyze/email", json={"subject": "x", "body": "Send your OTP now"}).json()
    assert e["ml"]["probability"] is None and e["mode"]["warning"]
