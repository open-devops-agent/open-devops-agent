"""
Deduplicate repeated Alertmanager / Grafana notifications (#124).

Both re-send a still-firing alert every group_interval / repeat_interval, after
restarts, and once per HA replica. Without dedupe each delivery becomes a new
incident that re-runs diagnosis and can re-apply a fix.

An alert's identity is its org, its ``fingerprint`` (or a hash of its sorted
labels when absent) and its ``startsAt``. The first delivery atomically claims a
marker for that identity; repeats within ``ALERT_DEDUPE_WINDOW_SEC`` are
reported as duplicates of the original incident. A new ``startsAt`` (the alert
resolved and fired again) is a new incident. Markers live outside the queue, so
the poll loop never scans them, and are removed by retention.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Optional, Tuple

import structlog

from storage.base import StorageProvider
from storage.factory import get_storage

log = structlog.get_logger()

DEFAULT_WINDOW_SEC = 3600
CATEGORY = "alert_dedupe"


def dedupe_window_seconds() -> int:
    try:
        return max(0, int(os.getenv("ALERT_DEDUPE_WINDOW_SEC", str(DEFAULT_WINDOW_SEC))))
    except ValueError:
        return DEFAULT_WINDOW_SEC


def alert_identity(alert: dict) -> str:
    """Stable digest of one alert firing: fingerprint (or labels) plus startsAt."""
    labels = alert.get("labels") or {}
    fingerprint = alert.get("fingerprint") or json.dumps(labels, sort_keys=True, separators=(",", ":"))
    material = json.dumps([fingerprint, alert.get("startsAt") or ""], separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AlertDeduper:
    def __init__(self, storage: Optional[StorageProvider] = None):
        self.storage = storage or get_storage()

    def _key(self, org_id: str, digest: str) -> str:
        return self.storage.org_prefix(org_id, CATEGORY, f"{digest}.json")

    def claim(self, org_id: str, alert: dict, incident_id: str) -> Tuple[bool, str]:
        """Claim this alert firing for ``incident_id``.

        Returns ``(True, incident_id)`` when the caller should enqueue it, or
        ``(False, existing_incident_id)`` for a repeat within the window.
        """
        window = dedupe_window_seconds()
        if window == 0:
            return True, incident_id

        digest = alert_identity(alert)
        key = self._key(org_id, digest)
        now = datetime.now(timezone.utc)
        marker = {
            "incident_id": incident_id,
            "alertname": (alert.get("labels") or {}).get("alertname", ""),
            "starts_at": alert.get("startsAt"),
            "created_at": now.isoformat(),
        }
        if self.storage.put_json_if_absent(key, marker):
            return True, incident_id

        existing = self.storage.get_json(key) or {}
        try:
            created = datetime.fromisoformat(existing["created_at"])
        except (KeyError, TypeError, ValueError):
            created = None
        if created is not None and (now - created).total_seconds() < window:
            log.info(
                "Duplicate alert notification ignored",
                org_id=org_id,
                alertname=marker["alertname"],
                incident_id=existing.get("incident_id"),
            )
            return False, existing.get("incident_id", "")

        # Cooldown over (or unreadable marker): the alert is still firing, so
        # treat this delivery as a new attempt.
        self.storage.put_json(key, marker)
        return True, incident_id
