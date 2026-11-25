"""Per-org webhook secrets bind a request to its tenant (#61)."""
import hashlib
import hmac
import json
import time
from unittest.mock import AsyncMock
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

PLATFORM = "platform-secret"
ACME = "acme-secret"


def sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def app(monkeypatch):
    from api import server
    from services.org_config import OrgConfig
    from storage.memory_storage import MemoryStorage

    config = OrgConfig(storage=MemoryStorage())
    config.save("acme", {"WEBHOOK_SECRET": ACME, "SLACK_SIGNING_SECRET": "acme-slack"})
    monkeypatch.setattr(server, "org_config", config)
    monkeypatch.setenv("WEBHOOK_SECRET", PLATFORM)
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "platform-slack")
    monkeypatch.setenv("ORG_ID", "default")
    monkeypatch.delenv("REQUIRE_ORG_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("ALLOWED_IPS", raising=False)
    enqueue = AsyncMock(side_effect=lambda ctx, **kw: kw.get("incident_id") or "INC-1")
    monkeypatch.setattr(server, "enqueue_incident", enqueue)
    server.enqueued = enqueue
    return server


def post_manual(client, payload, secret, org=None):
    body = json.dumps(payload).encode()
    headers = {"X-Hub-Signature-256": sign(body, secret), "Content-Type": "application/json"}
    if org:
        headers["X-Org-ID"] = org
    return client.post("/webhook/manual", content=body, headers=headers)


def test_org_secret_authenticates_its_own_org(app):
    r = post_manual(TestClient(app.app), {"type": "server"}, ACME, org="acme")
    assert r.status_code == 200
    assert app.enqueued.call_args.args[0]["org_id"] == "acme"


def test_platform_secret_cannot_impersonate_an_org_with_its_own_secret(app):
    client = TestClient(app.app)
    assert post_manual(client, {"type": "server"}, PLATFORM, org="acme").status_code == 401
    # nor by naming the org in the body instead of the header
    assert post_manual(client, {"type": "server", "org_id": "acme"}, PLATFORM).status_code == 401
    app.enqueued.assert_not_called()


def test_org_secret_cannot_be_used_for_another_org(app):
    client = TestClient(app.app)
    # authenticated as acme, but the body tries to target another org
    r = post_manual(client, {"type": "server", "org_id": "contoso"}, ACME, org="acme")
    assert r.status_code == 200 and app.enqueued.call_args.args[0]["org_id"] == "acme"  # header wins
    assert post_manual(client, {"type": "server"}, ACME, org="contoso").status_code == 401
    assert post_manual(client, {"type": "server"}, ACME).status_code == 401


def test_platform_secret_still_works_for_orgs_without_their_own(app):
    client = TestClient(app.app)
    assert post_manual(client, {"type": "server"}, PLATFORM, org="contoso").status_code == 200
    assert post_manual(client, {"type": "server"}, PLATFORM).status_code == 200


def test_require_org_secret_refuses_platform_secret_for_other_orgs(app, monkeypatch):
    monkeypatch.setenv("REQUIRE_ORG_WEBHOOK_SECRET", "true")
    client = TestClient(app.app)
    assert post_manual(client, {"type": "server"}, PLATFORM, org="contoso").status_code == 403
    assert post_manual(client, {"type": "server"}, PLATFORM).status_code == 200  # the platform's own org


def alerts_body(*orgs):
    return json.dumps({"alerts": [
        {"status": "firing", "labels": {"alertname": f"HighCPU{i}", **({"org_id": o} if o else {})},
         "startsAt": f"2026-11-25T00:00:0{i}Z"} for i, o in enumerate(orgs)
    ]}).encode()


def test_alertmanager_label_cannot_route_platform_alerts_into_a_protected_org(app):
    body = alerts_body("acme")
    r = TestClient(app.app).post("/webhook/alertmanager", content=body,
                                 headers={"Authorization": f"Bearer {PLATFORM}"})
    assert r.status_code == 403
    app.enqueued.assert_not_called()


def test_mixed_batch_is_rejected_before_anything_is_queued(app):
    body = alerts_body(None, "acme")  # first alert is allowed, second is not
    r = TestClient(app.app).post("/webhook/alertmanager", content=body,
                                 headers={"Authorization": f"Bearer {PLATFORM}"})
    assert r.status_code == 403
    app.enqueued.assert_not_called()


def test_alertmanager_bearer_with_org_secret(app):
    body = alerts_body(None, "contoso")  # labels can't move an org-bound request elsewhere
    r = TestClient(app.app).post("/webhook/alertmanager", content=body,
                                 headers={"Authorization": f"Bearer {ACME}", "X-Org-ID": "acme"})
    assert r.status_code == 200
    assert {c.args[0]["org_id"] for c in app.enqueued.call_args_list} == {"acme"}


def test_gitlab_token_per_org(app):
    body = json.dumps({"object_kind": "pipeline", "object_attributes": {"status": "failed", "id": 7},
                       "project": {"id": 1}}).encode()
    client = TestClient(app.app)
    ok = client.post("/webhook/gitlab", content=body, headers={"X-Gitlab-Token": ACME, "X-Org-ID": "acme"})
    bad = client.post("/webhook/gitlab", content=body, headers={"X-Gitlab-Token": PLATFORM, "X-Org-ID": "acme"})
    assert ok.status_code == 200 and bad.status_code == 401


def test_storage_outage_fails_closed(app, monkeypatch):
    def broken(_org):
        raise RuntimeError("bucket unavailable")

    monkeypatch.setattr(app.org_config, "get", broken)
    r = post_manual(TestClient(app.app), {"type": "server"}, PLATFORM, org="acme")
    assert r.status_code == 503
    app.enqueued.assert_not_called()


def slack_request(org, secret):
    value = json.dumps({"org_id": org, "incident_id": "INC-9", "command": "a3ViZWN0bCBnZXQgcG9kcw=="})
    payload = {"actions": [{"action_id": "approve_action", "value": value}], "user": {"id": "U1"}}
    body = urlencode({"payload": json.dumps(payload)}).encode()
    ts = str(int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:{body.decode()}".encode(), hashlib.sha256).hexdigest()
    return body, {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig,
                  "Content-Type": "application/x-www-form-urlencoded"}


def test_slack_uses_the_orgs_own_signing_secret(app, monkeypatch):
    monkeypatch.setattr(app, "_slack_approvers", lambda org: set())
    monkeypatch.setattr(app, "_record_slack_decision", lambda *a, **k: None)
    monkeypatch.setattr(app.agent, "execute_approved_action", AsyncMock())
    client = TestClient(app.app)
    body, headers = slack_request("acme", "platform-slack")
    assert client.post("/slack/action", content=body, headers=headers).status_code == 401
    body, headers = slack_request("acme", "acme-slack")
    assert client.post("/slack/action", content=body, headers=headers).status_code == 200
    body, headers = slack_request("contoso", "platform-slack")  # no own Slack app: platform secret
    assert client.post("/slack/action", content=body, headers=headers).status_code == 200
