"""Credential lifecycle: validation, rotation metadata, audit trail, revocation (#62)."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from services.org_config import CredentialValidationError, OrgConfig, validate_credentials
from storage.memory_storage import MemoryStorage

GH = "ghp_" + "a" * 36
GH2 = "github_pat_" + "b" * 40
ANTHROPIC = "sk-ant-" + "x" * 30


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_VALIDATION", "strict")


@pytest.fixture
def config():
    return OrgConfig(storage=MemoryStorage())


class TestValidation:
    @pytest.mark.parametrize("key, value", [
        ("ANTHROPIC_API_KEY", "sk-proj-abcdefgh"),
        ("GITHUB_TOKEN", "my-github-token"),
        ("SLACK_WEBHOOK_URL", "https://example.com/hook"),
        ("SLACK_BOT_TOKEN", "xoxp-123456789"),
        ("JENKINS_URL", "jenkins.internal"),
        ("AWS_ACCESS_KEY_ID", "AKIA123"),
        ("EMAIL_SMTP_PORT", "smtp"),
        ("AUTO_APPLY", "yes"),
        ("LLM_PROVIDER", "mistral"),
        ("GITLAB_TOKEN", "short"),
        ("GITLAB_TOKEN", "glpat-abc def ghi"),
        ("JIRA_URL", "https://jira.example.com\r\nX-Injected: 1"),
    ])
    def test_rejects_clearly_wrong_values(self, key, value):
        assert key in validate_credentials({key: value})

    @pytest.mark.parametrize("key, value", [
        ("ANTHROPIC_API_KEY", ANTHROPIC),
        ("GITHUB_TOKEN", GH),
        ("GITHUB_TOKEN", GH2),
        ("GITHUB_TOKEN", "0123456789abcdef0123456789abcdef01234567"),
        ("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T0/B0/xyz"),
        ("JENKINS_URL", "http://jenkins.internal:8080"),
        ("AWS_ACCESS_KEY_ID", "AKIAABCDEFGHIJKLMNOP"),
        ("EMAIL_SMTP_PORT", "587"),
        ("LLM_PROVIDER", "gemini"),
        ("GITLAB_TOKEN", "glpat-abcdefghijklmnop"),
        ("GITHUB_ORG", "acme"),
    ])
    def test_accepts_real_shapes(self, key, value):
        assert validate_credentials({key: value}) == {}

    def test_errors_never_echo_values(self, strict, config):
        secret = "sk-proj-THIS-IS-SECRET"
        with pytest.raises(CredentialValidationError) as exc:
            config.save("acme", {"ANTHROPIC_API_KEY": secret})
        assert secret not in str(exc.value) and secret not in json.dumps(exc.value.errors)
        assert config.get("acme") == {}

    def test_warn_mode_saves_anyway(self, monkeypatch, config):
        monkeypatch.setenv("CREDENTIAL_VALIDATION", "warn")
        config.save("acme", {"GITHUB_TOKEN": "my-github-token"})
        assert config.get("acme") == {"GITHUB_TOKEN": "my-github-token"}


class TestRotation:
    def test_update_merges_and_null_removes(self, strict, config):
        config.save("acme", {"GITHUB_TOKEN": GH, "GITHUB_ORG": "acme"})
        result = config.update("acme", {"GITHUB_TOKEN": GH2, "GITHUB_ORG": None, "ANTHROPIC_API_KEY": ANTHROPIC})
        assert config.get("acme") == {"GITHUB_TOKEN": GH2, "ANTHROPIC_API_KEY": ANTHROPIC}
        assert result["changed"] == ["GITHUB_TOKEN"]
        assert result["added"] == ["ANTHROPIC_API_KEY"]
        assert result["removed"] == ["GITHUB_ORG"]

    def test_save_reports_ignored_unknown_keys(self, config):
        assert config.save("acme", {"GITHUB_TOKEN": GH, "NOT_A_KEY": "x"})["ignored_keys"] == ["NOT_A_KEY"]

    def test_metadata_tracks_who_and_when_per_key(self, config):
        config.save("acme", {"GITHUB_TOKEN": GH, "GITHUB_ORG": "acme"}, actor="api:admin:abc")
        config.update("acme", {"GITHUB_TOKEN": GH2}, actor="mcp")
        meta = config.metadata("acme")
        assert meta["GITHUB_TOKEN"]["updated_by"] == "mcp"
        assert meta["GITHUB_ORG"]["updated_by"] == "api:admin:abc"

    def test_unchanged_value_keeps_its_timestamp(self, config):
        config.save("acme", {"GITHUB_TOKEN": GH}, actor="first")
        before = config.metadata("acme")["GITHUB_TOKEN"]
        config.update("acme", {"GITHUB_TOKEN": GH}, actor="second")
        assert config.metadata("acme")["GITHUB_TOKEN"] == before

    def test_status_flags_stale_secrets(self, config, monkeypatch):
        monkeypatch.setenv("CREDENTIAL_MAX_AGE_DAYS", "30")
        config.save("acme", {"GITHUB_TOKEN": GH, "GITHUB_ORG": "acme"})
        meta = config.metadata("acme")
        old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        for k in meta:
            meta[k]["updated_at"] = old
        config.storage.put_json(config._meta_key("acme"), meta)
        status = config.status("acme")
        assert status["stale"] == ["GITHUB_TOKEN"]  # GITHUB_ORG is not a secret
        assert status["details"]["GITHUB_TOKEN"]["age_days"] == 45
        assert "ghp_" not in json.dumps(status)


class TestAuditAndRevocation:
    def test_audit_events_list_keys_never_values(self, config):
        config.save("acme", {"GITHUB_TOKEN": GH}, actor="api:admin:abc")
        config.update("acme", {"GITHUB_TOKEN": GH2}, actor="api:admin:abc")
        config.delete("acme", actor="api:admin:abc")
        events = config.audit_events("acme")
        assert [e["action"] for e in events] == ["credentials_deleted", "credentials_updated", "credentials_replaced"]
        assert events[0]["removed"] == ["GITHUB_TOKEN"] and events[1]["changed"] == ["GITHUB_TOKEN"]
        dumped = json.dumps(events)
        assert GH not in dumped and GH2 not in dumped

    def test_delete_selected_keys(self, config):
        config.save("acme", {"GITHUB_TOKEN": GH, "GITHUB_ORG": "acme"})
        assert config.delete("acme", ["GITHUB_TOKEN"])["removed"] == ["GITHUB_TOKEN"]
        assert config.get("acme") == {"GITHUB_ORG": "acme"}
        assert "GITHUB_TOKEN" not in config.metadata("acme")

    def test_full_delete_overwrites_before_removing(self, config):
        config.save("acme", {"GITHUB_TOKEN": GH})
        writes = []
        original = config.storage.put_json
        config.storage.put_json = lambda key, data: (writes.append((key, data)), original(key, data))[1]
        config.delete("acme")
        assert (config._config_key("acme"), {"deleted": True}) in writes
        assert config.storage.get_json(config._config_key("acme")) is None
        assert config.metadata("acme") == {}


@pytest.fixture
def api(monkeypatch):
    from api import server

    store = OrgConfig(storage=MemoryStorage())
    monkeypatch.setattr(server, "org_config", store)
    monkeypatch.setenv("API_ADMIN_TOKEN", "platform-admin")
    monkeypatch.setenv("API_ORG_TOKENS", "acme:viewer=viewer-token,acme:admin=acme-admin")
    monkeypatch.delenv("API_AUTH_DISABLED", raising=False)
    monkeypatch.delenv("ALLOWED_IPS", raising=False)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("CREDENTIAL_VALIDATION", "strict")
    return TestClient(server.app, raise_server_exceptions=False), store


ADMIN = {"Authorization": "Bearer acme-admin"}
VIEWER = {"Authorization": "Bearer viewer-token"}


class TestApi:
    def test_put_rejects_invalid_with_422(self, api):
        client, store = api
        r = client.put("/orgs/acme/config", json={"credentials": {"GITHUB_TOKEN": "nope-not-a-token"}}, headers=ADMIN)
        assert r.status_code == 422
        assert "GITHUB_TOKEN" in r.json()["detail"]["errors"]
        assert "nope-not-a-token" not in r.text
        assert store.get("acme") == {}

    def test_patch_rotates_one_key(self, api):
        client, store = api
        client.put("/orgs/acme/config", json={"credentials": {"GITHUB_TOKEN": GH, "GITHUB_ORG": "acme"}}, headers=ADMIN)
        r = client.patch("/orgs/acme/config", json={"credentials": {"GITHUB_TOKEN": GH2}}, headers=ADMIN)
        assert r.status_code == 200 and r.json()["changed"] == ["GITHUB_TOKEN"]
        assert store.get("acme") == {"GITHUB_TOKEN": GH2, "GITHUB_ORG": "acme"}

    def test_delete_and_audit(self, api):
        client, store = api
        client.put("/orgs/acme/config", json={"credentials": {"GITHUB_TOKEN": GH, "GITHUB_ORG": "acme"}}, headers=ADMIN)
        r = client.delete("/orgs/acme/config?keys=GITHUB_TOKEN", headers=ADMIN)
        assert r.status_code == 200 and r.json()["removed"] == ["GITHUB_TOKEN"]
        events = client.get("/orgs/acme/config/audit", headers=ADMIN).json()["events"]
        assert events[0]["action"] == "credentials_deleted"
        assert events[0]["actor"].startswith("api:admin:") and "acme-admin" not in json.dumps(events)
        assert client.delete("/orgs/acme/config", headers=ADMIN).json()["removed"] == ["GITHUB_ORG"]

    @pytest.mark.parametrize("method, path", [
        ("patch", "/orgs/acme/config"), ("delete", "/orgs/acme/config"), ("get", "/orgs/acme/config/audit"),
    ])
    def test_viewer_cannot_change_or_read_history(self, api, method, path):
        client, _ = api
        kwargs = {"json": {"credentials": {}}} if method == "patch" else {}
        assert getattr(client, method)(path, headers=VIEWER, **kwargs).status_code == 403

    def test_other_org_token_cannot_revoke(self, api):
        client, _ = api
        assert client.delete("/orgs/contoso/config", headers=ADMIN).status_code == 403


@pytest.mark.asyncio
async def test_mcp_revoke_and_validation(monkeypatch):
    from unittest.mock import MagicMock

    from devops_mcp.registry import register_platform_tools

    monkeypatch.setenv("CREDENTIAL_VALIDATION", "strict")
    store = OrgConfig(storage=MemoryStorage())
    handlers = {}
    mcp = MagicMock()
    mcp.tool.side_effect = lambda **kw: lambda fn: handlers.setdefault(kw["name"], fn)
    register_platform_tools(mcp, MagicMock(), MagicMock(), MagicMock(), MagicMock(), store)

    bad = await handlers["configure_org_credentials"]({"GITHUB_TOKEN": "nope"}, org_id="acme")
    assert bad["status"] == "invalid" and "GITHUB_TOKEN" in bad["errors"]
    await handlers["configure_org_credentials"]({"GITHUB_TOKEN": GH, "GITHUB_ORG": "acme"}, org_id="acme")
    merged = await handlers["configure_org_credentials"]({"GITHUB_TOKEN": GH2}, org_id="acme", merge=True)
    assert merged["changed"] == ["GITHUB_TOKEN"] and store.get("acme")["GITHUB_ORG"] == "acme"
    revoked = await handlers["revoke_org_credentials"](["GITHUB_TOKEN"], org_id="acme")
    assert revoked["removed"] == ["GITHUB_TOKEN"]
    assert store.metadata("acme")["GITHUB_ORG"]["updated_by"] == "mcp"
