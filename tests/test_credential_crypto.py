"""Credential encryption at rest (#60)."""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from services.credential_crypto import (
    CIPHERTEXT_KEY,
    ENCRYPTED_MARKER,
    unwrap_from_storage,
    wrap_for_storage,
)
from services.org_config import OrgConfig
from storage.memory_storage import MemoryStorage


@pytest.fixture
def fernet_key(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("ENCRYPT_CREDENTIALS", "true")
    monkeypatch.setenv("CREDENTIALS_MASTER_KEY", key)
    return key


def test_wrap_plaintext_when_disabled(monkeypatch):
    monkeypatch.setenv("ENCRYPT_CREDENTIALS", "false")
    data = {"GITHUB_TOKEN": "ghp_test"}
    assert wrap_for_storage(data) == data


def test_round_trip_encrypted(fernet_key):
    original = {"GITHUB_TOKEN": "ghp_secret", "SLACK_WEBHOOK_URL": "https://hooks.example"}
    wrapped = wrap_for_storage(original)
    assert wrapped.get(ENCRYPTED_MARKER) is True
    assert CIPHERTEXT_KEY in wrapped
    assert "ghp_secret" not in str(wrapped)
    assert unwrap_from_storage(wrapped) == original


def test_org_config_stores_ciphertext(fernet_key):
    storage = MemoryStorage()
    cfg = OrgConfig(storage=storage)
    result = cfg.save("acme", {"GITHUB_TOKEN": "ghp_live", "AUTO_APPLY": "false"})
    assert result["encrypted_at_rest"] is True
    raw = storage.get_json(storage.org_prefix("acme", "config", "credentials.json"))
    assert raw.get(ENCRYPTED_MARKER) is True
    assert "ghp_live" not in str(raw)
    loaded = cfg.get("acme")
    assert loaded["GITHUB_TOKEN"] == "ghp_live"


def test_reads_legacy_plaintext(monkeypatch):
    monkeypatch.setenv("ENCRYPT_CREDENTIALS", "false")
    storage = MemoryStorage()
    cfg = OrgConfig(storage=storage)
    key = storage.org_prefix("acme", "config", "credentials.json")
    storage.put_json(key, {"GITLAB_TOKEN": "glpat-old"})
    assert cfg.get("acme")["GITLAB_TOKEN"] == "glpat-old"
