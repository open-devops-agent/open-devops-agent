"""The local incident simulator must sign the bytes it sends to the API."""

import hashlib
import hmac
import json

import httpx
import pytest

from scripts import simulate_incident


@pytest.mark.asyncio
async def test_simulator_signs_exact_payload(monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "simulator-secret")
    monkeypatch.setattr(simulate_incident, "load_dotenv", lambda: None)
    received = []

    def respond(request):
        received.append(request)
        return httpx.Response(200, json={"status": "queued"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    monkeypatch.setattr(simulate_incident.httpx, "AsyncClient", lambda **kwargs: client)
    await simulate_incident.simulate("k8s")

    [request] = received
    assert json.loads(request.content) == simulate_incident.INCIDENTS["k8s"]
    expected = (
        "sha256=" + hmac.new(b"simulator-secret", request.content, hashlib.sha256).hexdigest()
    )
    assert request.headers["X-Hub-Signature-256"] == expected


@pytest.mark.asyncio
async def test_simulator_does_not_claim_rejected_request_was_submitted(monkeypatch, capsys):
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    monkeypatch.setattr(simulate_incident, "load_dotenv", lambda: None)

    def reject(request):
        assert "X-Hub-Signature-256" not in request.headers
        return httpx.Response(503, json={"detail": "Webhook authentication is not configured"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(reject))
    monkeypatch.setattr(simulate_incident.httpx, "AsyncClient", lambda **kwargs: client)
    with pytest.raises(httpx.HTTPStatusError):
        await simulate_incident.simulate("k8s")
    assert "Incident submitted!" not in capsys.readouterr().out
