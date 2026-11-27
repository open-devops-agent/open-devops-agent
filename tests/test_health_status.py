"""/health reveals nothing; runtime status needs a token (#225)."""
import pytest
from fastapi.testclient import TestClient

from api import server

SENSITIVE = ("auto_apply", "emergency_stop", "storage_provider", "org_id", "queue_worker")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", "platform-admin")
    monkeypatch.setenv("API_ORG_TOKENS", "acme:viewer=acme-viewer,contoso:viewer=contoso-viewer")
    monkeypatch.setenv("ORG_ID", "acme")
    monkeypatch.setenv("AUTO_APPLY", "true")
    monkeypatch.delenv("API_AUTH_DISABLED", raising=False)
    monkeypatch.delenv("ALLOWED_IPS", raising=False)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    return TestClient(server.app, raise_server_exceptions=False)


def test_health_is_minimal_and_unauthenticated(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert not any(key in response.text for key in SENSITIVE)


def test_status_requires_a_token(client):
    assert client.get("/status").status_code == 401


def test_status_with_viewer_token(client):
    body = client.get("/status", headers={"Authorization": "Bearer acme-viewer"}).json()
    assert body["auto_apply"] == "true" and body["org_id"] == "acme"
    assert set(SENSITIVE) <= set(body)


def test_status_is_org_scoped(client):
    assert client.get("/status", headers={"Authorization": "Bearer contoso-viewer"}).status_code == 403
    ok = client.get("/status?org_id=contoso", headers={"Authorization": "Bearer contoso-viewer"})
    assert ok.status_code == 200 and ok.json()["org_id"] == "contoso"


def test_admin_token_reads_any_org_status(client):
    assert client.get("/status?org_id=contoso", headers={"Authorization": "Bearer platform-admin"}).status_code == 200
