"""Shared test fixtures."""
import sys

import pytest

from storage.memory_storage import MemoryStorage


@pytest.fixture(autouse=True)
def fresh_alert_dedupe(monkeypatch):
    """Give each test its own alert-dedupe markers.

    Several tests post the same alert payload; without this the shared
    in-memory storage would make later tests see them as repeat notifications.
    """
    server = sys.modules.get("api.server")
    if server is not None:
        monkeypatch.setattr(server.alert_deduper, "storage", MemoryStorage())
