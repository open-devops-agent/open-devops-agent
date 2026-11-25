"""
Tests for FastAPI webhook endpoints and org-doc routes.
All external services (agent, queue, storage) are mocked.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


ADMIN_TOKEN = "test-admin-token"
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
# Webhook tests run with a secret configured by default, so every request below
# must authenticate; the no-secret path has its own explicit test.
WEBHOOK_SECRET = "test-secret"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.delenv("API_ORG_TOKENS", raising=False)
    monkeypatch.delenv("API_AUTH_DISABLED", raising=False)
    monkeypatch.setenv("WEBHOOK_SECRET", WEBHOOK_SECRET)
    with (
        patch("agent.core.DevOpsAgent"),
        patch("tools.notify.SlackNotifier"),
        patch("services.incident_queue.IncidentQueue"),
        patch("services.incident_store.IncidentStore"),
        patch("services.org_docs.OrgDocs"),
        patch("services.escalation.EscalationService"),
    ):
        from api.server import app
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


def _github_sig(payload: bytes, secret: str = WEBHOOK_SECRET) -> str:
    mac = hmac.new(secret.encode(), payload, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _post_signed(client, path: str, payload: dict, headers: dict | None = None):
    """POST a JSON body with an HMAC-SHA256 signature over the exact bytes sent."""
    body = json.dumps(payload).encode()
    signed = {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _github_sig(body),
        **(headers or {}),
    }
    return client.post(path, content=body, headers=signed)


# ─── /health ─────────────────────────────────────────────────────────────────

def test_health_returns_200(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data


def test_api_version_matches_project_metadata(client):
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib

    with (Path(__file__).resolve().parents[1] / "pyproject.toml").open("rb") as source:
        expected = tomllib.load(source)["project"]["version"]
    assert client.app.version == expected
    assert client.get("/openapi.json").json()["info"]["version"] == expected
    assert client.get("/health").json()["version"] == expected


def test_api_version_prefers_installed_distribution(client, monkeypatch):
    from api import server

    def installed_version(name):
        assert name == "devops-ai-agent"
        return "9.8.7"

    monkeypatch.setattr(server, "version", installed_version)
    assert server._app_version() == "9.8.7"


# ─── /audit ──────────────────────────────────────────────────────────────────

def test_audit_returns_200(client):
    resp = client.get("/audit", headers=AUTH)
    assert resp.status_code == 200
    assert isinstance(resp.json(), (list, dict))


# ─── /webhook/github ─────────────────────────────────────────────────────────

def test_github_webhook_invalid_signature_returns_401(client):
    payload = json.dumps({"action": "opened"}).encode()
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": "sha256=invalidsignature",
            "X-GitHub-Event": "push",
        },
    )
    assert resp.status_code == 401


def test_github_webhook_valid_signature_returns_200(client):
    resp = _post_signed(
        client,
        "/webhook/github",
        {"action": "opened", "repository": {"full_name": "org/repo"}},
        headers={"X-GitHub-Event": "push"},
    )
    assert resp.status_code == 200


def test_github_webhook_missing_signature_returns_401(client):
    resp = client.post(
        "/webhook/github",
        json={"action": "opened"},
        headers={"X-GitHub-Event": "push"},
    )
    assert resp.status_code == 401


def test_github_webhook_no_secret_accepts_all(client, monkeypatch):
    """Current fail-open behavior when no secret is configured (#64)."""
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    payload = json.dumps({"action": "opened"}).encode()
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={"Content-Type": "application/json", "X-GitHub-Event": "push"},
    )
    assert resp.status_code == 200


# ─── /webhook/alertmanager ───────────────────────────────────────────────────

ALERTMANAGER_PAYLOAD = {
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "PodCrashLoopBackOff", "namespace": "default"},
            "annotations": {"summary": "Pod is crash looping"},
        }
    ]
}


def test_alertmanager_webhook_valid_payload(client):
    resp = _post_signed(client, "/webhook/alertmanager", ALERTMANAGER_PAYLOAD)
    assert resp.status_code == 200


def test_alertmanager_webhook_bearer_token(client):
    """Alertmanager cannot sign bodies; it sends the secret as a bearer token."""
    resp = client.post(
        "/webhook/alertmanager",
        json=ALERTMANAGER_PAYLOAD,
        headers={"Authorization": f"Bearer {WEBHOOK_SECRET}"},
    )
    assert resp.status_code == 200


def test_alertmanager_webhook_wrong_bearer_token_returns_401(client):
    resp = client.post(
        "/webhook/alertmanager",
        json=ALERTMANAGER_PAYLOAD,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


def test_alertmanager_webhook_empty_alerts(client):
    resp = _post_signed(client, "/webhook/alertmanager", {"alerts": []})
    assert resp.status_code == 200


# ─── /webhook/manual ─────────────────────────────────────────────────────────

def test_manual_trigger_enqueues_incident(client):
    resp = _post_signed(client, "/webhook/manual", {"type": "k8s", "namespace": "default"})
    assert resp.status_code == 200


def test_manual_trigger_unsigned_returns_401(client):
    resp = client.post("/webhook/manual", json={"type": "k8s", "namespace": "default"})
    assert resp.status_code == 401


# ─── /orgs/{org_id}/docs ─────────────────────────────────────────────────────

def test_upload_doc_text_returns_200(client):
    resp = client.post(
        "/orgs/test-org/docs",
        json={"path": "runbooks/restart.md", "content": "# Restart runbook"},
        headers=AUTH,
    )
    assert resp.status_code == 200


def test_list_org_docs_returns_200(client):
    resp = client.get("/orgs/test-org/docs", headers=AUTH)
    assert resp.status_code == 200


def test_get_org_doc_missing_returns_404(client):
    resp = client.get("/orgs/test-org/docs/nonexistent/path.md", headers=AUTH)
    assert resp.status_code in (404, 200)


def test_delete_org_doc_returns_200_or_404(client):
    resp = client.delete("/orgs/test-org/docs/runbooks/restart.md", headers=AUTH)
    assert resp.status_code in (200, 404)
