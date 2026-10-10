"""
Security controls — emergency stop, webhook auth, Slack signatures, SSH hardening.
"""
import hashlib
import hmac
import json
import os
import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.webhook_auth import (
    verify_hmac_sha256_signature,
    verify_slack_signature,
    verify_webhook_request,
)
from tools.executor import SafeExecutor
from tools.safety import requires_configured_approval
from tools.ssh_utils import build_ssh_command

# Header values reach the application latin-1-decoded, so an unauthenticated
# caller can put non-ASCII characters into a signature header.
NON_ASCII_WEBHOOK_SIGNATURE = "sha256=\xff\xfe"
NON_ASCII_SLACK_SIGNATURE = "v0=\xff\xfe"

# Well-formed (hex, right length) but not the expected digest.
WRONG_WEBHOOK_SIGNATURE = "sha256=" + "0" * 64
WRONG_SLACK_SIGNATURE = "v0=" + "0" * 64


class TestEmergencyStop:
    @pytest.mark.asyncio
    async def test_blocks_mutating_commands(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        executor = SafeExecutor()
        result = await executor.run_safe("kubectl rollout restart deployment/api")
        assert result.get("emergency_stop") is True
        assert result.get("blocked") is True

    @pytest.mark.asyncio
    async def test_allows_read_only_commands(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        executor = SafeExecutor()
        with patch("asyncio.create_subprocess_shell") as mock_proc:
            mock_proc.return_value = AsyncMock(
                returncode=0,
                communicate=AsyncMock(return_value=(b"ok", b"")),
            )
            result = await executor.run_safe("kubectl get pods")
            assert result.get("success") is True

    @pytest.mark.asyncio
    async def test_blocks_approved_run_during_emergency_stop(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        executor = SafeExecutor()
        result = await executor.run("systemctl restart nginx")
        assert result.get("emergency_stop") is True


class TestRequireApprovalFor:
    def test_rollback_requires_approval(self, monkeypatch):
        monkeypatch.setenv("REQUIRE_APPROVAL_FOR", "rollback")
        assert requires_configured_approval("kubectl rollout undo deployment/api") is True

    def test_unlisted_action_not_forced(self, monkeypatch):
        monkeypatch.setenv("REQUIRE_APPROVAL_FOR", "delete")
        assert requires_configured_approval("systemctl restart nginx") is False


class TestWebhookAuth:
    def test_valid_hmac_signature(self):
        secret = "test-secret"
        payload = b'{"type":"server"}'
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert verify_hmac_sha256_signature(payload, sig, secret) is True

    def test_rejects_invalid_signature(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "secret")
        assert verify_webhook_request(b"{}", "sha256=deadbeef") is False

    def test_skips_when_no_secret_configured(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
        assert verify_webhook_request(b"{}", None) is True

    # Fail-closed invariant: any signature that is not a byte-for-byte match of the
    # expected signature must be rejected — malformed, empty, absent or simply
    # incorrect. No input turns a rejection into an acceptance, and none raises.

    def test_rejects_non_ascii_signature(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b"{}", NON_ASCII_WEBHOOK_SIGNATURE) is False

    def test_rejects_non_ascii_signature_in_hmac_helper(self):
        payload = b'{"type":"server"}'
        assert (
            verify_hmac_sha256_signature(payload, NON_ASCII_WEBHOOK_SIGNATURE, "test-secret")
            is False
        )

    def test_rejects_empty_signature(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b"{}", "") is False

    def test_rejects_absent_signature_when_secret_configured(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b"{}", None) is False

    def test_accepts_correct_signature(self, monkeypatch):
        """Regression guard: fail-closed handling must not break the accept path."""
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        payload = b'{"type":"server"}'
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert verify_webhook_request(payload, sig) is True

    def test_rejects_incorrect_but_well_formed_signature(self, monkeypatch):
        """Regression guard: fail-closed handling must not make the compare permissive."""
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b'{"type":"server"}', WRONG_WEBHOOK_SIGNATURE) is False

    def test_accepts_gitlab_static_token(self, monkeypatch):
        from api.webhook_auth import verify_webhook_auth

        monkeypatch.setenv("WEBHOOK_SECRET", "gitlab-secret")
        assert verify_webhook_auth(b'{"object_kind":"merge_request"}', static_token="gitlab-secret") is True
        assert verify_webhook_auth(b'{"object_kind":"merge_request"}', static_token="wrong") is False
        assert verify_webhook_auth(b"{}", signature=None, static_token=None) is False


class TestSlackSignature:
    def test_valid_slack_signature(self):
        secret = "slack-secret"
        body = b"payload=%7B%7D"
        timestamp = str(int(time.time()))
        basestring = f"v0:{timestamp}:{body.decode()}"
        signature = "v0=" + hmac.new(
            secret.encode(), basestring.encode(), hashlib.sha256
        ).hexdigest()
        assert verify_slack_signature(body, timestamp, signature, secret) is True

    def test_rejects_stale_timestamp(self):
        secret = "slack-secret"
        body = b"payload=%7B%7D"
        timestamp = str(int(time.time()) - 600)
        basestring = f"v0:{timestamp}:{body.decode()}"
        signature = "v0=" + hmac.new(
            secret.encode(), basestring.encode(), hashlib.sha256
        ).hexdigest()
        assert verify_slack_signature(body, timestamp, signature, secret) is False

    # Same fail-closed invariant as TestWebhookAuth. The accept path is guarded by
    # test_valid_slack_signature above, which must keep passing.

    def test_rejects_non_ascii_signature(self):
        timestamp = str(int(time.time()))
        assert (
            verify_slack_signature(
                b"payload=%7B%7D", timestamp, NON_ASCII_SLACK_SIGNATURE, "slack-secret"
            )
            is False
        )

    def test_rejects_empty_signature(self):
        timestamp = str(int(time.time()))
        assert verify_slack_signature(b"payload=%7B%7D", timestamp, "", "slack-secret") is False

    def test_rejects_absent_signature(self):
        timestamp = str(int(time.time()))
        assert verify_slack_signature(b"payload=%7B%7D", timestamp, None, "slack-secret") is False

    def test_rejects_incorrect_but_well_formed_signature(self):
        """Regression guard: fail-closed handling must not make the compare permissive."""
        timestamp = str(int(time.time()))
        assert (
            verify_slack_signature(
                b"payload=%7B%7D", timestamp, WRONG_SLACK_SIGNATURE, "slack-secret"
            )
            is False
        )

    def test_rejects_non_utf8_body(self):
        """A body that is not UTF-8 must be rejected, not decoded lossily and not raise."""
        timestamp = str(int(time.time()))
        assert (
            verify_slack_signature(b"\xff\xfe", timestamp, WRONG_SLACK_SIGNATURE, "slack-secret")
            is False
        )


class TestSshUtils:
    def test_strict_host_key_checking_by_default(self, monkeypatch):
        monkeypatch.delenv("SSH_STRICT_HOST_KEY_CHECKING", raising=False)
        cmd = build_ssh_command("10.0.0.5", "df -h")
        assert "StrictHostKeyChecking=yes" in cmd
        assert "StrictHostKeyChecking=no" not in cmd

    def test_applies_remote_user(self, monkeypatch):
        monkeypatch.setenv("SSH_REMOTE_USER", "ubuntu")
        cmd = build_ssh_command("10.0.0.5", "uptime")
        assert "ubuntu@10.0.0.5" in cmd

    def test_allows_opt_out_for_dev(self, monkeypatch):
        monkeypatch.setenv("SSH_STRICT_HOST_KEY_CHECKING", "false")
        cmd = build_ssh_command("10.0.0.5", "uptime")
        assert "StrictHostKeyChecking=no" in cmd


class TestWebhookEndpoints:
    def test_manual_webhook_requires_signature_when_secret_set(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        from api.server import app

        client = TestClient(app)
        response = client.post(
            "/webhook/manual",
            json={"type": "server", "description": "test"},
        )
        assert response.status_code == 401

    def test_manual_webhook_accepts_valid_signature(self, monkeypatch):
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        from api.server import app

        payload = {"type": "server", "description": "test"}
        body = json.dumps(payload).encode()
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        client = TestClient(app)
        with patch("api.server.enqueue_incident", new=AsyncMock(return_value="INC-1")):
            response = client.post(
                "/webhook/manual",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Hub-Signature-256": sig,
                },
            )
        assert response.status_code == 200
        assert response.json()["status"] == "queued"

    def test_health_reports_emergency_stop(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        from api.server import app

        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["emergency_stop"] is True
