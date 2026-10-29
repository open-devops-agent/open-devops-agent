"""Only allowlisted Slack users can approve actions, and every decision is recorded (#117)."""
import base64
import hashlib
import hmac
import json
import os
import time
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urlencode

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest
from fastapi.testclient import TestClient

from api import server
from services.org_config import OrgConfig
from storage.memory_storage import MemoryStorage

SIGNING_SECRET = "test-slack-signing-secret"
COMMAND = "kubectl rollout undo deployment/api -n default"


def approval_value(org_id="org-a", command=COMMAND):
    return json.dumps(
        {"org_id": org_id, "incident_id": "INC-1", "command": base64.b64encode(command.encode()).decode()}
    )


def post_action(client, action_id, value, user_id="U_ALICE", user_name="alice"):
    body = urlencode(
        {
            "payload": json.dumps(
                {
                    "user": {"id": user_id, "username": user_name},
                    "actions": [{"action_id": action_id, "value": value}],
                }
            )
        }
    ).encode()
    timestamp = str(int(time.time()))
    digest = hmac.new(
        SIGNING_SECRET.encode(), b"v0:" + timestamp.encode() + b":" + body, hashlib.sha256
    ).hexdigest()
    return client.post(
        "/slack/action",
        content=body,
        headers={"X-Slack-Request-Timestamp": timestamp, "X-Slack-Signature": f"v0={digest}"},
    )


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", SIGNING_SECRET)
    monkeypatch.delenv("SLACK_APPROVER_IDS", raising=False)
    config = OrgConfig(storage=MemoryStorage())
    monkeypatch.setattr("services.org_context.OrgConfig", lambda: config)
    execute = AsyncMock()
    monkeypatch.setattr(server, "agent", MagicMock(execute_approved_action=execute))
    store = MagicMock()
    monkeypatch.setattr(server, "incident_store", store)
    client = TestClient(server.app)
    return client, execute, store, config


def decisions(store):
    return [call.args[3] for call in store.save_log.call_args_list]


class TestWithoutAllowlist:
    def test_any_user_can_approve_and_is_recorded(self, env):
        client, execute, store, _ = env
        response = post_action(client, "approve_action", approval_value(), user_id="U_ANYONE")

        assert response.status_code == 200
        assert response.json()["text"].startswith("✅ Approved by <@U_ANYONE>")
        execute.assert_awaited_once_with("INC-1", COMMAND, org_id="org-a")
        [record] = decisions(store)
        assert record["decision"] == "approved"
        assert record["slack_user_id"] == "U_ANYONE"
        assert record["command"] == COMMAND
        assert store.save_log.call_args.args[0] == "org-a"


class TestGlobalAllowlist:
    def test_listed_user_approves(self, env, monkeypatch):
        client, execute, store, _ = env
        monkeypatch.setenv("SLACK_APPROVER_IDS", "U_BOB, U_ALICE")
        response = post_action(client, "approve_action", approval_value(), user_id="U_ALICE")

        assert response.json()["text"].startswith("✅ Approved by <@U_ALICE>")
        execute.assert_awaited_once()
        assert decisions(store)[0]["decision"] == "approved"

    def test_unlisted_user_is_refused_and_nothing_runs(self, env, monkeypatch):
        client, execute, store, _ = env
        monkeypatch.setenv("SLACK_APPROVER_IDS", "U_BOB")
        response = post_action(client, "approve_action", approval_value(), user_id="U_MALLORY", user_name="mallory")

        assert response.status_code == 200
        body = response.json()
        assert body["response_type"] == "ephemeral"
        assert body["replace_original"] is False
        assert "not an approver" in body["text"]
        execute.assert_not_awaited()
        [record] = decisions(store)
        assert record["decision"] == "denied"
        assert record["slack_user_id"] == "U_MALLORY"
        assert record["slack_user_name"] == "mallory"

    def test_missing_user_is_refused(self, env, monkeypatch):
        client, execute, _, _ = env
        monkeypatch.setenv("SLACK_APPROVER_IDS", "U_BOB")
        response = post_action(client, "approve_action", approval_value(), user_id="")
        assert "not an approver" in response.json()["text"]
        execute.assert_not_awaited()


class TestPerOrgAllowlist:
    def test_org_config_overrides_global(self, env, monkeypatch):
        client, execute, _, config = env
        monkeypatch.setenv("SLACK_APPROVER_IDS", "U_GLOBAL")
        config.save("org-a", {"SLACK_APPROVER_IDS": "U_ACME_LEAD"})

        refused = post_action(client, "approve_action", approval_value("org-a"), user_id="U_GLOBAL")
        assert "not an approver" in refused.json()["text"]
        execute.assert_not_awaited()

        approved = post_action(client, "approve_action", approval_value("org-a"), user_id="U_ACME_LEAD")
        assert approved.json()["text"].startswith("✅ Approved by <@U_ACME_LEAD>")
        execute.assert_awaited_once()

    def test_other_org_uses_global_list(self, env, monkeypatch):
        client, execute, _, config = env
        monkeypatch.setenv("SLACK_APPROVER_IDS", "U_GLOBAL")
        config.save("org-a", {"SLACK_APPROVER_IDS": "U_ACME_LEAD"})
        response = post_action(client, "approve_action", approval_value("org-b"), user_id="U_GLOBAL")
        assert response.json()["text"].startswith("✅ Approved")
        execute.assert_awaited_once_with("INC-1", COMMAND, org_id="org-b")

    def test_approver_ids_is_a_storable_org_key(self):
        config = OrgConfig(storage=MemoryStorage())
        config.save("org-a", {"SLACK_APPROVER_IDS": "U1,U2"})
        assert config.get("org-a") == {"SLACK_APPROVER_IDS": "U1,U2"}


def test_reject_is_recorded_with_the_actor(env):
    client, execute, store, _ = env
    response = post_action(client, "reject_action", "reject", user_id="U_CAROL")
    assert response.json()["text"].startswith("❌ Rejected by <@U_CAROL>")
    execute.assert_not_awaited()
    assert decisions(store)[0]["decision"] == "rejected"


def test_record_failure_does_not_block_approval(env, monkeypatch):
    client, execute, store, _ = env
    store.save_log.side_effect = RuntimeError("storage down")
    response = post_action(client, "approve_action", approval_value())
    assert response.status_code == 200
    execute.assert_awaited_once()


def test_invalid_signature_still_rejected_before_anything(env):
    client, execute, store, _ = env
    response = client.post(
        "/slack/action",
        content=b"payload=%7B%7D",
        headers={"X-Slack-Request-Timestamp": str(int(time.time())), "X-Slack-Signature": "v0=" + "0" * 64},
    )
    assert response.status_code == 401
    execute.assert_not_awaited()
    store.save_log.assert_not_called()
