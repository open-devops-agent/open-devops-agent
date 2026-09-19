"""
Persistent incident store — audit trail, step logs, checkpoints in cloud storage.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import structlog

from services.pii_scrubber import scrub_dict, scrub_value
from storage.base import StorageProvider
from storage.factory import get_storage

log = structlog.get_logger()


class IncidentStore:
    def __init__(self, storage: Optional[StorageProvider] = None):
        self.storage = storage or get_storage()
        self.retention_days = int(os.getenv("AUDIT_RETENTION_DAYS", "90"))

    def save_audit(self, org_id: str, incident_id: str, entry: dict) -> str:
        scrubbed = scrub_dict(entry)
        key = self.storage.audit_key(org_id, incident_id)
        self.storage.put_json(key, scrubbed)
        log.info("Audit saved", org_id=org_id, incident_id=incident_id, key=key)
        return key

    def save_log(self, org_id: str, incident_id: str, log_name: str, data: Any) -> str:
        scrubbed = scrub_value(data)
        key = self.storage.log_key(org_id, incident_id, log_name)
        self.storage.put_json(key, scrubbed)
        return key

    def save_conversation(self, org_id: str, incident_id: str, messages: list) -> str:
        return self.save_log(org_id, incident_id, "conversation.json", _serialize_messages(messages))

    def save_checkpoint(
        self,
        org_id: str,
        incident_id: str,
        messages: list,
        actions_taken: list,
        steps: int,
        full_context: dict,
        issue_type: str,
    ) -> str:
        checkpoint = scrub_dict({
            "incident_id": incident_id,
            "org_id": org_id,
            "messages": _serialize_messages(messages),
            "actions_taken": actions_taken,
            "steps": steps,
            "full_context": full_context,
            "issue_type": issue_type,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        key = self.storage.checkpoint_key(org_id, incident_id)
        self.storage.put_json(key, checkpoint)
        return key

    def load_checkpoint(self, org_id: str, incident_id: str) -> Optional[dict]:
        key = self.storage.checkpoint_key(org_id, incident_id)
        return self.storage.get_json(key)

    def delete_checkpoint(self, org_id: str, incident_id: str):
        self.storage.delete(self.storage.checkpoint_key(org_id, incident_id))

    def list_audit(self, org_id: str, limit: int = 50) -> List[dict]:
        prefix = self.storage.org_prefix(org_id, "audit")
        keys = self.storage.list_keys(prefix)
        entries = []
        for key in reversed(keys):
            data = self.storage.get_json(key)
            if data:
                entries.append(data)
            if len(entries) >= limit:
                break
        return entries

    def apply_retention(self, org_id: str) -> int:
        """Delete audit, log, checkpoint, and queue objects older than retention_days."""
        if self.retention_days <= 0:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        month_cutoff = cutoff.replace(day=1)
        deleted = 0
        for category in ("audit", "logs", "checkpoints", "queue"):
            prefix = self.storage.org_prefix(org_id, category)
            for key in self.storage.list_keys(prefix):
                obj_date, month_granularity = _object_retention_date(self.storage, key, category)
                if obj_date is None:
                    continue
                expired = obj_date < month_cutoff if month_granularity else obj_date < cutoff
                if expired:
                    self.storage.delete(key)
                    deleted += 1
        if deleted:
            log.info("Retention cleanup", org_id=org_id, deleted=deleted)
        return deleted


_RETENTION_TIMESTAMP_FIELDS = (
    "updated_at",
    "completed_at",
    "failed_at",
    "claimed_at",
    "created_at",
)


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _path_year_month(key: str, category: str) -> Optional[datetime]:
    """Return a month-granularity date when the key embeds /{category}/{year}/{month}/."""
    parts = key.split("/")
    try:
        year_idx = parts.index(category) + 1
    except ValueError:
        return None
    if year_idx + 1 >= len(parts):
        return None
    try:
        year = int(parts[year_idx])
        month = int(parts[year_idx + 1])
    except ValueError:
        return None
    if year < 1970 or not 1 <= month <= 12:
        return None
    return datetime(year, month, 1, tzinfo=timezone.utc)


def _payload_timestamp(storage: StorageProvider, key: str) -> Optional[datetime]:
    """Read retention age from checkpoint/queue JSON when the key has no year/month."""
    try:
        data = storage.get_json(key)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    for field in _RETENTION_TIMESTAMP_FIELDS:
        parsed = _parse_iso_datetime(data.get(field))
        if parsed is not None:
            return parsed
    return None


def _object_retention_date(storage: StorageProvider, key: str, category: str):
    """Return (datetime, month_granularity) or (None, False) if age cannot be determined."""
    path_date = _path_year_month(key, category)
    if path_date is not None:
        return path_date, True
    payload_date = _payload_timestamp(storage, key)
    if payload_date is not None:
        return payload_date, False
    return None, False


def _serialize_messages(messages: list) -> list:
    out = []
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, list):
            blocks = []
            for block in content:
                if hasattr(block, "model_dump"):
                    blocks.append(block.model_dump())
                elif isinstance(block, dict):
                    blocks.append(block)
                else:
                    blocks.append({"type": getattr(block, "type", "text"), "text": getattr(block, "text", str(block))})
            out.append({"role": msg["role"], "content": blocks})
        else:
            out.append(msg)
    return out
