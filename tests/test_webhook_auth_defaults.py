"""Missing integration secrets must not authorize webhooks or Slack approvals."""

import base64
import json
import os
from unittest.mock import AsyncMock, Mock
from urllib.parse import urlencode

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest
from fastapi.testclient import TestClient

from api import server
from api.webhook_auth import (
    verify_slack_signature,
    verify_static_webhook_token,
    verify_webhook_auth,
    verify_webhook_request,
)

HELPERS = [
    (verify_webhook_request, (b"{}", None), "WEBHOOK_SECRET", "WEBHOOK_AUTH_DISABLED"),
    (verify_static_webhook_token, (None,), "WEBHOOK_SECRET", "WEBHOOK_AUTH_DISABLED"),
    (verify_webhook_auth, (b"{}",), "WEBHOOK_SECRET", "WEBHOOK_AUTH_DISABLED"),
    (
        verify_slack_signature,
        (b"payload", None, None),
        "SLACK_SIGNING_SECRET",
        "SLACK_AUTH_DISABLED",
    ),
]
HELPER_IDS = [helper.__name__ for helper, *_ in HELPERS]
WEBHOOKS = [
    "/webhook/github",
    "/webhook/gitlab",
    "/webhook/bitbucket",
    "/webhook/alertmanager",
    "/webhook/grafana",
    "/webhook/manual",
]


@pytest.fixture(autouse=True)
def auth_environment(monkeypatch):
    for name in (
        "WEBHOOK_SECRET",
        "SLACK_SIGNING_SECRET",
        "WEBHOOK_AUTH_DISABLED",
        "SLACK_AUTH_DISABLED",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("helper,args,secret_name,flag", HELPERS, ids=HELPER_IDS)
@pytest.mark.parametrize("secret", [None, ""], ids=["unset", "empty"])
def test_helpers_reject_missing_secrets(monkeypatch, helper, args, secret_name, flag, secret):
    if secret is not None:
        monkeypatch.setenv(secret_name, secret)
    assert helper(*args) is False


@pytest.mark.parametrize("helper,args,secret_name,flag", HELPERS, ids=HELPER_IDS)
@pytest.mark.parametrize("enabled", ["true", " TRUE ", "1", "yes"])
def test_explicit_development_opt_out(monkeypatch, helper, args, secret_name, flag, enabled):
    monkeypatch.setenv(flag, enabled)
    assert helper(*args) is True


@pytest.mark.parametrize("helper,args,secret_name,flag", HELPERS, ids=HELPER_IDS)
@pytest.mark.parametrize("disabled", ["false", "0", "unexpected"])
def test_other_flag_values_do_not_bypass_auth(
    monkeypatch, helper, args, secret_name, flag, disabled
):
    monkeypatch.setenv(flag, disabled)
    assert helper(*args) is False


@pytest.mark.parametrize("helper,args,secret_name,flag", HELPERS, ids=HELPER_IDS)
def test_development_opt_out_does_not_override_configured_secret(
    monkeypatch, helper, args, secret_name, flag
):
    monkeypatch.setenv(secret_name, "configured-secret")
    monkeypatch.setenv(flag, "true")
    assert helper(*args) is False


@pytest.mark.parametrize("path", WEBHOOKS)
def test_unconfigured_webhook_rejected_before_enqueue(monkeypatch, path):
    enqueue = AsyncMock(return_value="INC-test")
    monkeypatch.setattr(server, "enqueue_incident", enqueue)
    response = TestClient(server.app).post(path, json={"type": "k8s"})
    assert response.status_code == 503
    assert "WEBHOOK_SECRET" in response.json()["detail"]
    enqueue.assert_not_awaited()


@pytest.mark.parametrize("flag", ["SLACK_AUTH_DISABLED", "API_AUTH_DISABLED", "MCP_AUTH_DISABLED"])
def test_other_auth_opt_outs_do_not_disable_webhook_auth(monkeypatch, flag):
    monkeypatch.setenv(flag, "true")
    response = TestClient(server.app).post("/webhook/manual", json={"type": "k8s"})
    assert response.status_code == 503


def test_development_webhook_can_enqueue_unsigned_request(monkeypatch):
    monkeypatch.setenv("WEBHOOK_AUTH_DISABLED", "true")
    enqueue = AsyncMock(return_value="INC-test")
    monkeypatch.setattr(server, "enqueue_incident", enqueue)
    response = TestClient(server.app).post("/webhook/manual", json={"type": "k8s"})
    assert response.status_code == 200
    assert response.json()["incident_id"] == "INC-test"
    enqueue.assert_awaited_once()


@pytest.fixture
def slack_approval(monkeypatch):
    execute = AsyncMock()
    record = Mock()
    monkeypatch.setattr(server, "agent", Mock(execute_approved_action=execute))
    monkeypatch.setattr(server, "_record_slack_decision", record)
    monkeypatch.setattr(server, "_slack_approvers", lambda org_id: {"U_TEST"})
    value = json.dumps(
        {
            "org_id": "org-test",
            "incident_id": "INC-test",
            "command": base64.b64encode(b"systemctl restart nginx").decode(),
        }
    )
    payload = {
        "actions": [{"action_id": "approve_action", "value": value}],
        "user": {"id": "U_TEST"},
    }
    return TestClient(server.app), urlencode({"payload": json.dumps(payload)}), execute, record


@pytest.mark.parametrize("webhook_opt_out", [False, True])
def test_unsigned_slack_approval_cannot_execute(monkeypatch, slack_approval, webhook_opt_out):
    if webhook_opt_out:
        monkeypatch.setenv("WEBHOOK_AUTH_DISABLED", "true")
    client, body, execute, record = slack_approval
    response = client.post("/slack/action", content=body)
    assert response.status_code == 503
    assert "SLACK_SIGNING_SECRET" in response.json()["detail"]
    execute.assert_not_awaited()
    record.assert_not_called()


def test_explicit_slack_development_opt_out(monkeypatch, slack_approval):
    monkeypatch.setenv("SLACK_AUTH_DISABLED", "true")
    client, body, execute, record = slack_approval
    response = client.post("/slack/action", content=body)
    assert response.status_code == 200
    execute.assert_awaited_once_with("INC-test", "systemctl restart nginx", org_id="org-test")
    record.assert_called_once()


def test_configured_secret_still_rejects_unsigned_webhook_with_opt_out(monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "configured-secret")
    monkeypatch.setenv("WEBHOOK_AUTH_DISABLED", "true")
    response = TestClient(server.app).post("/webhook/manual", json={"type": "k8s"})
    assert response.status_code == 401


def test_configured_secret_still_rejects_unsigned_slack_with_opt_out(monkeypatch, slack_approval):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "configured-secret")
    monkeypatch.setenv("SLACK_AUTH_DISABLED", "true")
    client, body, execute, record = slack_approval
    assert client.post("/slack/action", content=body).status_code == 401
    execute.assert_not_awaited()
    record.assert_not_called()
