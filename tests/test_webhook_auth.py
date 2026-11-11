"""
Tests for webhook authentication on /webhook/alertmanager and /webhook/manual.

Mirrors the GitHub endpoint behaviour: HMAC-SHA256 over the raw request body,
header `X-Hub-Signature-256`, secret `WEBHOOK_SECRET`, fail-closed defaults when
no secret is configured.
"""

import hashlib
import hmac
import json
import os
import time

# DevOpsAgent is instantiated at import time and requires a key.
os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest
from fastapi.testclient import TestClient

from api.server import app

SECRET = "test-webhook-secret"
SLACK_SECRET = "slack-secret"

# httpx ASCII-encodes str header values and would raise in the client before the
# request is sent, so the non-ASCII header has to be handed over as bytes. The
# server decodes it back to a latin-1 str, which is what reaches verification.
NON_ASCII_SIGNATURE_HEADER = b"sha256=\xff\xfe"
NON_ASCII_SLACK_SIGNATURE_HEADER = b"v0=\xff\xfe"

# Well-formed (hex, right length) but not the expected digest.
WRONG_SLACK_SIGNATURE = "v0=" + "0" * 64

ALERTMANAGER_PAYLOAD = {
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "PodCrashLooping", "namespace": "default"},
            "annotations": {"summary": "Pod is crash looping"},
        }
    ]
}

MANUAL_PAYLOAD = {
    "type": "k8s",
    "namespace": "default",
    "pod": "test-pod",
    "description": "Test incident",
}

GITHUB_PAYLOAD = {
    "action": "completed",
    "workflow_run": {
        "conclusion": "failure",
        "id": 12345,
        "name": "CI",
        "head_branch": "main",
        "head_sha": "abc123def456",
        "html_url": "https://github.com/org/repo/actions/runs/12345",
    },
    "repository": {"full_name": "org/repo"},
}


def _sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)
    return TestClient(app)


@pytest.fixture
def no_secret_client(monkeypatch):
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    return TestClient(app)


@pytest.fixture
def error_reporting_client(monkeypatch):
    """Client that surfaces an unhandled server error as a 500 response.

    With the default ``raise_server_exceptions=True`` the exception propagates out
    of the client instead, so a crash could not be distinguished from a rejection.
    """
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def slack_client(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", SLACK_SECRET)
    return TestClient(app, raise_server_exceptions=False)


class TestAlertmanagerWebhookAuth:
    def test_valid_signature_accepted(self, client):
        body = json.dumps(ALERTMANAGER_PAYLOAD).encode()
        response = client.post(
            "/webhook/alertmanager",
            headers={"X-Hub-Signature-256": _sign(body)},
            content=body,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "queued"

    def test_invalid_signature_rejected(self, client):
        body = json.dumps(ALERTMANAGER_PAYLOAD).encode()
        response = client.post(
            "/webhook/alertmanager",
            headers={"X-Hub-Signature-256": "sha256=invalid"},
            content=body,
        )
        assert response.status_code == 401

    def test_missing_signature_rejected(self, client):
        body = json.dumps(ALERTMANAGER_PAYLOAD).encode()
        response = client.post("/webhook/alertmanager", content=body)
        assert response.status_code == 401

    def test_signature_for_different_body_rejected(self, client):
        real_body = json.dumps(ALERTMANAGER_PAYLOAD).encode()
        other_body = json.dumps({"alerts": []}).encode()
        response = client.post(
            "/webhook/alertmanager",
            headers={"X-Hub-Signature-256": _sign(other_body)},
            content=real_body,
        )
        assert response.status_code == 401

    def test_no_secret_fails_closed(self, no_secret_client):
        body = json.dumps(ALERTMANAGER_PAYLOAD).encode()
        response = no_secret_client.post("/webhook/alertmanager", content=body)
        assert response.status_code == 503


class TestManualWebhookAuth:
    def test_valid_signature_accepted(self, client):
        body = json.dumps(MANUAL_PAYLOAD).encode()
        response = client.post(
            "/webhook/manual",
            headers={"X-Hub-Signature-256": _sign(body)},
            content=body,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "queued"

    def test_invalid_signature_rejected(self, client):
        body = json.dumps(MANUAL_PAYLOAD).encode()
        response = client.post(
            "/webhook/manual",
            headers={"X-Hub-Signature-256": "sha256=invalid"},
            content=body,
        )
        assert response.status_code == 401

    def test_missing_signature_rejected(self, client):
        body = json.dumps(MANUAL_PAYLOAD).encode()
        response = client.post("/webhook/manual", content=body)
        assert response.status_code == 401

    def test_signature_for_different_body_rejected(self, client):
        real_body = json.dumps(MANUAL_PAYLOAD).encode()
        other_body = json.dumps({"type": "k8s"}).encode()
        response = client.post(
            "/webhook/manual",
            headers={"X-Hub-Signature-256": _sign(other_body)},
            content=real_body,
        )
        assert response.status_code == 401

    def test_no_secret_fails_closed(self, no_secret_client):
        body = json.dumps(MANUAL_PAYLOAD).encode()
        response = no_secret_client.post("/webhook/manual", content=body)
        assert response.status_code == 503


class TestGitHubWebhookRegression:
    """Ensure the existing GitHub webhook auth path still works."""

    def test_valid_signature_accepted(self, client):
        body = json.dumps(GITHUB_PAYLOAD).encode()
        response = client.post(
            "/webhook/github",
            headers={
                "X-GitHub-Event": "workflow_run",
                "X-Hub-Signature-256": _sign(body),
            },
            content=body,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "queued"

    def test_invalid_signature_rejected(self, client):
        body = json.dumps(GITHUB_PAYLOAD).encode()
        response = client.post(
            "/webhook/github",
            headers={
                "X-GitHub-Event": "workflow_run",
                "X-Hub-Signature-256": "sha256=invalid",
            },
            content=body,
        )
        assert response.status_code == 401

    def test_no_secret_fails_closed(self, no_secret_client):
        body = json.dumps(GITHUB_PAYLOAD).encode()
        response = no_secret_client.post(
            "/webhook/github",
            headers={"X-GitHub-Event": "workflow_run"},
            content=body,
        )
        assert response.status_code == 503


class TestMalformedSignatureRejected:
    """A malformed request must be rejected with 401, never crash with a 500.

    Signature verification is unauthenticated, so anything that makes it raise is
    reachable by any caller. Fail closed: reject, do not error out.
    """

    def test_non_ascii_signature_header_rejected(self, error_reporting_client):
        body = json.dumps(MANUAL_PAYLOAD).encode()
        response = error_reporting_client.post(
            "/webhook/manual",
            headers={"X-Hub-Signature-256": NON_ASCII_SIGNATURE_HEADER},
            content=body,
        )
        assert response.status_code == 401

    def test_non_ascii_slack_signature_header_rejected(self, slack_client):
        response = slack_client.post(
            "/slack/action",
            headers={
                "X-Slack-Signature": NON_ASCII_SLACK_SIGNATURE_HEADER,
                "X-Slack-Request-Timestamp": str(int(time.time())),
            },
            content=b"payload=%7B%7D",
        )
        assert response.status_code == 401

    def test_non_utf8_slack_body_rejected(self, slack_client):
        response = slack_client.post(
            "/slack/action",
            headers={
                "X-Slack-Signature": WRONG_SLACK_SIGNATURE,
                "X-Slack-Request-Timestamp": str(int(time.time())),
            },
            content=b"\xff\xfe",
        )
        assert response.status_code == 401
