"""Startup warnings for missing webhook and Slack secrets (#64)."""
from __future__ import annotations

import asyncio
import os

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest
from structlog.testing import capture_logs

from api import server


def _warnings() -> list:
    with capture_logs() as logs:
        server._warn_missing_webhook_secrets()
    return [entry["event"] for entry in logs if entry["log_level"] == "warning"]


@pytest.fixture
def no_secrets(monkeypatch):
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("SLACK_SIGNING_SECRET", raising=False)


def test_warns_for_both_missing_secrets(no_secrets):
    warnings = _warnings()
    assert len(warnings) == 2
    assert any(w.startswith("WEBHOOK_SECRET is not set") for w in warnings)
    assert any(w.startswith("SLACK_SIGNING_SECRET is not set") for w in warnings)


def test_no_warning_when_both_secrets_set(no_secrets, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "test-signing-secret")
    assert _warnings() == []


def test_warns_only_for_missing_webhook_secret(no_secrets, monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "test-signing-secret")
    warnings = _warnings()
    assert len(warnings) == 1
    assert warnings[0].startswith("WEBHOOK_SECRET is not set")


def test_warns_only_for_missing_slack_secret(no_secrets, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
    warnings = _warnings()
    assert len(warnings) == 1
    assert warnings[0].startswith("SLACK_SIGNING_SECRET is not set")


def test_empty_secret_counts_as_missing(no_secrets, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "")
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "test-signing-secret")
    warnings = _warnings()
    assert len(warnings) == 1
    assert warnings[0].startswith("WEBHOOK_SECRET is not set")


def test_lifespan_calls_the_check(monkeypatch):
    calls = []
    monkeypatch.setattr(server, "_warn_missing_webhook_secrets", lambda: calls.append(1))
    monkeypatch.setattr(server, "acquire_background_worker_lock", lambda: None)
    monkeypatch.setattr(server, "_ensure_storage_is_shared", lambda handle: None)
    monkeypatch.setattr(server, "release_background_worker_lock", lambda handle: None)
    monkeypatch.setattr(server.incident_queue, "adopt_legacy_reviews", lambda: None)

    async def run():
        async with server.lifespan(server.app):
            pass

    asyncio.run(run())
    assert calls == [1]
