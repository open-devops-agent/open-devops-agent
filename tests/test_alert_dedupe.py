"""Repeated Alertmanager / Grafana notifications must not create duplicate incidents (#124)."""
import copy
import json
import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest
from fastapi.testclient import TestClient

from api import server
from services.alert_dedupe import AlertDeduper, alert_identity
from services.incident_store import IncidentStore
from storage.memory_storage import MemoryStorage

ALERT = {
    "status": "firing",
    "fingerprint": "a1b2c3d4e5f60718",
    "labels": {"alertname": "PodCrashLooping", "namespace": "prod", "pod": "api-1"},
    "annotations": {"summary": "crash looping"},
    "startsAt": "2026-10-29T10:00:00Z",
}


def payload(*alerts):
    return {"alerts": [copy.deepcopy(a) for a in alerts]}


@pytest.fixture
def queued(monkeypatch):
    calls = []

    async def fake_enqueue(context, incident_id=None):
        calls.append((context, incident_id))
        return incident_id

    monkeypatch.setattr(server, "enqueue_incident", fake_enqueue)
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("ALERT_DEDUPE_WINDOW_SEC", raising=False)
    return calls


@pytest.fixture
def client(queued):
    return TestClient(server.app)


@pytest.mark.parametrize("endpoint", ["/webhook/alertmanager", "/webhook/grafana"])
class TestWebhookDedupe:
    def test_repeat_notification_is_a_duplicate(self, client, queued, endpoint):
        first = client.post(endpoint, json=payload(ALERT)).json()
        second = client.post(endpoint, json=payload(ALERT)).json()

        assert first["status"] == "queued" and len(first["incident_ids"]) == 1
        assert second == {"status": "duplicate", "incident_ids": [], "duplicate_of": first["incident_ids"]}
        assert len(queued) == 1
        # The queued incident uses the id recorded in the dedupe marker.
        assert queued[0][1] == first["incident_ids"][0]

    def test_new_starts_at_is_a_new_incident(self, client, queued, endpoint):
        refired = dict(ALERT, startsAt="2026-10-29T14:00:00Z")
        a = client.post(endpoint, json=payload(ALERT)).json()
        b = client.post(endpoint, json=payload(refired)).json()
        assert a["status"] == b["status"] == "queued"
        assert a["incident_ids"] != b["incident_ids"]
        assert len(queued) == 2

    def test_mixed_batch_reports_new_and_duplicate(self, client, queued, endpoint):
        other = dict(ALERT, fingerprint="ffff0000ffff0000", labels={"alertname": "DiskFull", "host": "web-1"})
        first = client.post(endpoint, json=payload(ALERT)).json()
        mixed = client.post(endpoint, json=payload(ALERT, other)).json()
        assert mixed["status"] == "queued"
        assert len(mixed["incident_ids"]) == 1
        assert mixed["duplicate_of"] == first["incident_ids"]

    def test_orgs_are_deduplicated_separately(self, client, queued, endpoint):
        a = client.post(endpoint, json=payload(ALERT), headers={"X-Org-ID": "acme"}).json()
        b = client.post(endpoint, json=payload(ALERT), headers={"X-Org-ID": "globex"}).json()
        assert a["status"] == b["status"] == "queued"
        assert len(queued) == 2

    def test_window_zero_disables_dedupe(self, client, queued, endpoint, monkeypatch):
        monkeypatch.setenv("ALERT_DEDUPE_WINDOW_SEC", "0")
        client.post(endpoint, json=payload(ALERT))
        assert client.post(endpoint, json=payload(ALERT)).json()["status"] == "queued"
        assert len(queued) == 2

    def test_resolved_alerts_are_ignored(self, client, queued, endpoint):
        resolved = dict(ALERT, status="resolved")
        assert client.post(endpoint, json=payload(resolved)).json() == {"status": "queued", "incident_ids": []}
        assert queued == []


class TestIdentity:
    def test_fingerprint_wins_over_labels(self):
        relabelled = dict(ALERT, labels={"alertname": "Other"})
        assert alert_identity(ALERT) == alert_identity(relabelled)

    def test_labels_used_without_fingerprint_and_order_does_not_matter(self):
        a = {"labels": {"b": "2", "a": "1"}, "startsAt": "t"}
        b = {"labels": {"a": "1", "b": "2"}, "startsAt": "t"}
        c = {"labels": {"a": "1", "b": "3"}, "startsAt": "t"}
        assert alert_identity(a) == alert_identity(b) != alert_identity(c)

    def test_starts_at_is_part_of_identity(self):
        assert alert_identity(ALERT) != alert_identity(dict(ALERT, startsAt="2026-10-30T00:00:00Z"))


class TestClaim:
    def test_only_first_claim_wins(self):
        deduper = AlertDeduper(MemoryStorage())
        assert deduper.claim("acme", ALERT, "INC-1") == (True, "INC-1")
        assert deduper.claim("acme", ALERT, "INC-2") == (False, "INC-1")

    def test_expired_marker_allows_a_new_incident(self, monkeypatch):
        storage = MemoryStorage()
        deduper = AlertDeduper(storage)
        deduper.claim("acme", ALERT, "INC-1")
        key = deduper._key("acme", alert_identity(ALERT))
        marker = storage.get_json(key)
        marker["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        storage.put_json(key, marker)

        assert deduper.claim("acme", ALERT, "INC-2") == (True, "INC-2")
        assert deduper.claim("acme", ALERT, "INC-3") == (False, "INC-2")

    def test_custom_window(self, monkeypatch):
        monkeypatch.setenv("ALERT_DEDUPE_WINDOW_SEC", "60")
        storage = MemoryStorage()
        deduper = AlertDeduper(storage)
        deduper.claim("acme", ALERT, "INC-1")
        key = deduper._key("acme", alert_identity(ALERT))
        marker = storage.get_json(key)
        marker["created_at"] = (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
        storage.put_json(key, marker)
        assert deduper.claim("acme", ALERT, "INC-2")[0] is True

    def test_invalid_window_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("ALERT_DEDUPE_WINDOW_SEC", "soon")
        deduper = AlertDeduper(MemoryStorage())
        deduper.claim("acme", ALERT, "INC-1")
        assert deduper.claim("acme", ALERT, "INC-2") == (False, "INC-1")

    def test_markers_live_outside_the_queue(self):
        storage = MemoryStorage()
        AlertDeduper(storage).claim("acme", ALERT, "INC-1")
        keys = storage.list_keys("acme/")
        assert keys and all(k.startswith("acme/alert_dedupe/") for k in keys)


def test_retention_removes_old_markers():
    storage = MemoryStorage()
    deduper = AlertDeduper(storage)
    deduper.claim("acme", ALERT, "INC-old")
    deduper.claim("acme", dict(ALERT, startsAt="2026-10-29T12:00:00Z"), "INC-new")
    old_key = deduper._key("acme", alert_identity(ALERT))
    marker = storage.get_json(old_key)
    marker["created_at"] = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    storage.put_json(old_key, marker)

    store = IncidentStore(storage=storage)
    store.retention_days = 90
    store.apply_retention("acme")

    remaining = storage.list_keys("acme/alert_dedupe/")
    assert old_key not in remaining
    assert len(remaining) == 1
    assert json.loads(storage.get_bytes(remaining[0]))["incident_id"] == "INC-new"
