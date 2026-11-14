"""IP allowlist, rate limiting, and RBAC roles."""
from __future__ import annotations

import os

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest
from fastapi.testclient import TestClient

from api import server
from api.ip_allowlist import ip_allowed
from api.rate_limit import SlidingWindowLimiter, path_is_limited


class TestIpAllowlist:
    def test_disabled_allows_all(self, monkeypatch):
        monkeypatch.delenv("ALLOWED_IPS", raising=False)
        assert ip_allowed("1.2.3.4") is True

    def test_cidr_and_single(self, monkeypatch):
        monkeypatch.setenv("ALLOWED_IPS", "10.0.0.5,192.168.1.0/24")
        assert ip_allowed("10.0.0.5") is True
        assert ip_allowed("192.168.1.50") is True
        assert ip_allowed("8.8.8.8") is False

    def test_middleware_blocks(self, monkeypatch):
        monkeypatch.setenv("ALLOWED_IPS", "10.0.0.1")
        monkeypatch.setenv("API_AUTH_DISABLED", "true")
        client = TestClient(server.app, raise_server_exceptions=False)
        # TestClient peer is typically testclient / 127.0.0.1
        res = client.get("/audit?org_id=acme")
        assert res.status_code == 403
        assert "allowlisted" in res.json()["detail"].lower()


class TestRateLimit:
    def test_path_prefixes(self, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_PATHS", "/webhook,/orgs")
        assert path_is_limited("/webhook/github") is True
        assert path_is_limited("/orgs/acme/config") is True
        assert path_is_limited("/health") is False

    def test_sliding_window_blocks(self, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_REQUESTS", "3")
        monkeypatch.setenv("RATE_LIMIT_WINDOW_SEC", "60")
        lim = SlidingWindowLimiter()
        assert lim.allow("k")[0] is True
        assert lim.allow("k")[0] is True
        assert lim.allow("k")[0] is True
        allowed, retry = lim.allow("k")
        assert allowed is False
        assert retry >= 1

    def test_middleware_429(self, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
        monkeypatch.setenv("RATE_LIMIT_REQUESTS", "2")
        monkeypatch.setenv("RATE_LIMIT_WINDOW_SEC", "60")
        monkeypatch.setenv("RATE_LIMIT_PATHS", "/orgs")
        monkeypatch.setenv("API_AUTH_DISABLED", "true")
        monkeypatch.delenv("ALLOWED_IPS", raising=False)
        # Reset module limiter state by creating fresh client traffic
        from api import rate_limit as rl

        rl._limiter = SlidingWindowLimiter()
        client = TestClient(server.app, raise_server_exceptions=False)
        assert client.get("/orgs/acme/config/status").status_code == 200
        assert client.get("/orgs/acme/config/status").status_code == 200
        third = client.get("/orgs/acme/config/status")
        assert third.status_code == 429
        assert "Retry-After" in third.headers


class TestRbacRoles:
    VIEWER = "viewer-token"
    ADMIN_ORG = "admin-org-token"

    @pytest.fixture
    def client(self, monkeypatch):
        monkeypatch.setenv("API_ADMIN_TOKEN", "platform-admin")
        monkeypatch.setenv(
            "API_ORG_TOKENS",
            f"acme:viewer={self.VIEWER},acme:admin={self.ADMIN_ORG}",
        )
        monkeypatch.delenv("API_AUTH_DISABLED", raising=False)
        monkeypatch.delenv("ALLOWED_IPS", raising=False)
        monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
        return TestClient(server.app, raise_server_exceptions=False)

    def test_viewer_can_read_status(self, client):
        res = client.get(
            "/orgs/acme/config/status",
            headers={"Authorization": f"Bearer {self.VIEWER}"},
        )
        assert res.status_code == 200

    def test_viewer_cannot_write_config(self, client):
        res = client.put(
            "/orgs/acme/config",
            headers={"Authorization": f"Bearer {self.VIEWER}"},
            json={"credentials": {"GITHUB_TOKEN": "x"}},
        )
        assert res.status_code == 403
        assert "insufficient" in res.json()["detail"].lower()

    def test_org_admin_can_write(self, client):
        res = client.put(
            "/orgs/acme/config",
            headers={"Authorization": f"Bearer {self.ADMIN_ORG}"},
            json={"credentials": {"GITHUB_TOKEN": "ghp_x"}},
        )
        assert res.status_code == 200
