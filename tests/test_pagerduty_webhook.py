"""PagerDuty V3 webhook ingress (#17)."""
import hashlib
import hmac
import json
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

PD_SECRET = "pd-subscription-secret"


def pd_event(event_type="incident.triggered", **data):
    base = {
        "id": "Q1ABC",
        "number": 42,
        "title": "High CPU on api-server",
        "urgency": "high",
        "html_url": "https://acme.pagerduty.com/incidents/Q1ABC",
        "created_at": "2026-11-26T10:00:00Z",
        "service": {"id": "PSVC1", "summary": "checkout-api"},
        "priority": {"summary": "P1"},
        "incident_key": "datadog-123",
    }
    base.update(data)
    return {"event": {"id": "EV1", "event_type": event_type, "occurred_at": "2026-11-26T10:00:01Z", "data": base}}


def sign(body: bytes, secret: str = PD_SECRET) -> str:
    return "v1=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def app(monkeypatch):
    from api import server
    from services.alert_dedupe import AlertDeduper
    from services.org_config import OrgConfig
    from storage.memory_storage import MemoryStorage

    storage = MemoryStorage()
    monkeypatch.setattr(server, "org_config", OrgConfig(storage=storage))
    monkeypatch.setattr(server, "alert_deduper", AlertDeduper(storage=storage))
    monkeypatch.setenv("PAGERDUTY_WEBHOOK_SECRET", PD_SECRET)
    monkeypatch.setenv("WEBHOOK_SECRET", "platform-secret")
    monkeypatch.setenv("PAGERDUTY_SERVICE_ID", "PAGENT")
    monkeypatch.setenv("ORG_ID", "default")
    monkeypatch.delenv("PAGERDUTY_INGEST_AGENT_SERVICE", raising=False)
    monkeypatch.delenv("ALLOWED_IPS", raising=False)
    enqueue = AsyncMock(side_effect=lambda ctx, **kw: kw.get("incident_id") or "INC-1")
    monkeypatch.setattr(server, "enqueue_incident", enqueue)
    server.enqueued = enqueue
    return server


def post(app, payload, signature=None, headers=None):
    body = json.dumps(payload).encode()
    h = {"Content-Type": "application/json", **(headers or {})}
    if signature is not None:
        h["X-PagerDuty-Signature"] = signature(body) if callable(signature) else signature
    return TestClient(app.app).post("/webhook/pagerduty", content=body, headers=h)


def test_triggered_incident_is_queued_with_context(app):
    r = post(app, pd_event(), sign)
    assert r.status_code == 200 and r.json()["status"] == "queued"
    ctx = app.enqueued.call_args.args[0]
    assert ctx["source"] == "pagerduty" and ctx["severity"] == "critical"
    assert ctx["pagerduty_incident_id"] == "Q1ABC" and ctx["service"] == "checkout-api"
    assert ctx["html_url"].endswith("/Q1ABC") and ctx["org_id"] == "default"


def test_low_urgency_maps_to_warning(app):
    post(app, pd_event(urgency="low"), sign)
    assert app.enqueued.call_args.args[0]["severity"] == "warning"


def test_rotating_secret_header_with_two_signatures(app):
    r = post(app, pd_event(), lambda b: f"v1=deadbeef, {sign(b)}")
    assert r.status_code == 200


@pytest.mark.parametrize("signature", [None, "v1=0000", lambda b: sign(b, "wrong-secret"), "sha256=abc"])
def test_bad_or_missing_signature_is_rejected(app, signature):
    assert post(app, pd_event(), signature).status_code == 401
    app.enqueued.assert_not_called()


@pytest.mark.parametrize("event_type", ["incident.acknowledged", "incident.resolved", "incident.annotated", "pagey.ping"])
def test_other_events_are_acknowledged_and_ignored(app, event_type):
    r = post(app, pd_event(event_type), sign)
    assert r.status_code == 200 and r.json()["status"] == "ignored"
    app.enqueued.assert_not_called()


def test_reopened_incident_is_queued(app):
    assert post(app, pd_event("incident.reopened"), sign).json()["status"] == "queued"


@pytest.mark.parametrize("data", [
    {"incident_key": "INC-20261126100000-ab12cd"},   # created by our own escalation
    {"incident_key": "mcp-acme"},
    {"service": {"id": "PAGENT", "summary": "devops-agent escalations"}},
])
def test_agent_escalations_never_loop_back(app, data):
    r = post(app, pd_event(**data), sign)
    assert r.json() == {"status": "ignored", "reason": "agent_escalation"}
    app.enqueued.assert_not_called()


def test_agent_service_can_be_opted_in(app, monkeypatch):
    monkeypatch.setenv("PAGERDUTY_INGEST_AGENT_SERVICE", "true")
    r = post(app, pd_event(service={"id": "PAGENT", "summary": "shared"}), sign)
    assert r.json()["status"] == "queued"


def test_retried_delivery_is_deduplicated(app):
    first = post(app, pd_event(), sign).json()
    second = post(app, pd_event(), sign).json()
    assert first["status"] == "queued" and second["status"] == "duplicate"
    assert app.enqueued.call_count == 1


def test_per_org_secret_binds_the_org(app):
    app.org_config.save("acme", {"PAGERDUTY_WEBHOOK_SECRET": "acme-pd-secret"})
    ok = post(app, pd_event(), lambda b: sign(b, "acme-pd-secret"), {"X-Org-ID": "acme"})
    assert ok.status_code == 200 and app.enqueued.call_args.args[0]["org_id"] == "acme"
    # the platform PagerDuty secret can't post into acme
    assert post(app, pd_event(id="Q2"), sign, {"X-Org-ID": "acme"}).status_code == 401


def test_bearer_webhook_secret_works_without_pd_signature(app, monkeypatch):
    monkeypatch.delenv("PAGERDUTY_WEBHOOK_SECRET")
    r = post(app, pd_event(), headers={"Authorization": "Bearer platform-secret"})
    assert r.status_code == 200
    assert post(app, pd_event(id="Q3"), headers={"Authorization": "Bearer nope"}).status_code == 401
