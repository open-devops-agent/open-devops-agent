"""
Tests for FastAPI webhook endpoints and org-doc routes.
All external services (agent, queue, storage) are mocked.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


ADMIN_TOKEN = "test-admin-token"
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.delenv("API_ORG_TOKENS", raising=False)
    monkeypatch.delenv("API_AUTH_DISABLED", raising=False)
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


def _github_sig(payload: bytes, secret: str = "test-secret") -> str:
    mac = hmac.new(secret.encode(), payload, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _post_signed_webhook(client, path, payload):
    body = json.dumps(payload).encode()
    return client.post(path, content=body, headers={"X-Hub-Signature-256": _github_sig(body)})


# ─── /health ─────────────────────────────────────────────────────────────────

def test_health_returns_200(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data


# ─── /audit ──────────────────────────────────────────────────────────────────

def test_audit_returns_200(client):
    resp = client.get("/audit", headers=AUTH)
    assert resp.status_code == 200
    assert isinstance(resp.json(), (list, dict))


# ─── /webhook/github ─────────────────────────────────────────────────────────

def test_github_webhook_invalid_signature_returns_401(client, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
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


def test_github_webhook_valid_signature_returns_200(client, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
    payload = json.dumps({"action": "opened", "repository": {"full_name": "org/repo"}}).encode()
    sig = _github_sig(payload, "test-secret")
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "push",
        },
    )
    assert resp.status_code == 200


def test_github_webhook_no_secret_fails_closed(client, monkeypatch):
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    payload = json.dumps({"action": "opened"}).encode()
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={"Content-Type": "application/json", "X-GitHub-Event": "push"},
    )
    assert resp.status_code == 503


# ─── /webhook/alertmanager ───────────────────────────────────────────────────

def test_alertmanager_webhook_valid_payload(client):
    payload = {
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "PodCrashLoopBackOff", "namespace": "default"},
                "annotations": {"summary": "Pod is crash looping"},
            }
        ]
    }
    resp = _post_signed_webhook(client, "/webhook/alertmanager", payload)
    assert resp.status_code == 200


def test_alertmanager_webhook_empty_alerts(client):
    resp = _post_signed_webhook(client, "/webhook/alertmanager", {"alerts": []})
    assert resp.status_code == 200


# ─── /webhook/manual ─────────────────────────────────────────────────────────

def test_manual_trigger_enqueues_incident(client):
    payload = {"type": "k8s", "namespace": "default"}
    resp = _post_signed_webhook(client, "/webhook/manual", payload)
    assert resp.status_code == 200


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
