"""Management API authorization: org config, docs and audit routes (#59)."""
import hashlib
import hmac
import os

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest
from fastapi.testclient import TestClient

from api import server

ADMIN = "admin-token-123"
ORG_A = "org-a-token-456"
ORG_B = "org-b-token-789"

# (method, path template, json body) for every protected route.
ROUTES = [
    ("GET", "/audit?org_id={org}", None),
    ("PUT", "/orgs/{org}/config", {"credentials": {"GITLAB_TOKEN": "glpat-x"}}),
    ("GET", "/orgs/{org}/config/status", None),
    ("POST", "/orgs/{org}/docs", {"path": "runbooks/a.md", "content": "# A"}),
    ("GET", "/orgs/{org}/docs", None),
    ("GET", "/orgs/{org}/docs/runbooks/a.md", None),
    ("DELETE", "/orgs/{org}/docs/runbooks/a.md", None),
]
ROUTE_IDS = [f"{m} {p.split('?')[0]}" for m, p, _ in ROUTES]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def call(client, route, org, headers=None):
    method, path, body = route
    return client.request(method, path.format(org=org), json=body, headers=headers or {})


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN)
    monkeypatch.setenv("API_ORG_TOKENS", f"org-a={ORG_A}, org-b={ORG_B}")
    monkeypatch.delenv("API_AUTH_DISABLED", raising=False)
    return TestClient(server.app, raise_server_exceptions=False)


def allowed(status):
    # Authorised requests reach the handler: success, or 404 for a missing doc.
    return status in (200, 404)


@pytest.mark.parametrize("route", ROUTES, ids=ROUTE_IDS)
class TestProtectedRoutes:
    def test_missing_token_is_401(self, client, route):
        response = call(client, route, "org-a")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_unknown_token_is_401(self, client, route):
        assert call(client, route, "org-a", bearer("nope")).status_code == 401

    def test_non_bearer_scheme_is_401(self, client, route):
        response = call(client, route, "org-a", {"Authorization": f"Basic {ADMIN}"})
        assert response.status_code == 401

    def test_admin_token_reaches_any_org(self, client, route):
        assert allowed(call(client, route, "org-a", bearer(ADMIN)).status_code)
        assert allowed(call(client, route, "some-other-org", bearer(ADMIN)).status_code)

    def test_org_token_reaches_its_own_org(self, client, route):
        assert allowed(call(client, route, "org-a", bearer(ORG_A)).status_code)

    def test_org_token_is_403_for_another_org(self, client, route):
        assert call(client, route, "org-b", bearer(ORG_A)).status_code == 403
        assert call(client, route, "unlisted-org", bearer(ORG_A)).status_code == 403

    def test_not_configured_fails_closed(self, client, route, monkeypatch):
        monkeypatch.delenv("API_ADMIN_TOKEN")
        monkeypatch.delenv("API_ORG_TOKENS")
        response = call(client, route, "org-a", bearer(ADMIN))
        assert response.status_code == 503
        assert "API_ADMIN_TOKEN" in response.json()["detail"]

    def test_explicit_disable_allows_unauthenticated(self, client, route, monkeypatch):
        monkeypatch.delenv("API_ADMIN_TOKEN")
        monkeypatch.delenv("API_ORG_TOKENS")
        monkeypatch.setenv("API_AUTH_DISABLED", "true")
        assert allowed(call(client, route, "org-a").status_code)


def test_rejected_credential_write_stores_nothing(client, monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    route = ROUTES[1]
    assert call(client, route, "org-b", bearer(ORG_A)).status_code == 403
    status = client.get("/orgs/org-b/config/status", headers=bearer(ADMIN)).json()
    assert "GITLAB_TOKEN" not in status["configured"]


def test_audit_defaults_to_env_org_for_authorization(client, monkeypatch):
    monkeypatch.setenv("ORG_ID", "org-a")
    assert client.get("/audit", headers=bearer(ORG_A)).status_code == 200
    monkeypatch.setenv("ORG_ID", "org-b")
    assert client.get("/audit", headers=bearer(ORG_A)).status_code == 403


def test_doc_upload_file_route_is_protected(client):
    files = {"file": ("a.md", b"# A", "text/markdown")}
    url = "/orgs/org-a/docs/upload?path=runbooks/a.md"
    assert client.post(url, files=files).status_code == 401
    assert client.post(url, files=files, headers=bearer(ORG_B)).status_code == 403
    assert client.post(url, files=files, headers=bearer(ORG_A)).status_code == 200


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("org-a=t1,org-b=t2", {"org-a": "t1", "org-b": "t2"}),
        (" org-a = t1 , , bad, =t3, org-c= ", {"org-a": "t1"}),
        ("org-a=tok=en", {"org-a": "tok=en"}),
        ("", {}),
    ],
)
def test_org_token_parsing(monkeypatch, raw, expected):
    from api.api_auth import _org_tokens

    monkeypatch.setenv("API_ORG_TOKENS", raw)
    assert _org_tokens() == expected


def test_health_and_webhooks_stay_outside_api_auth(client, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "test-webhook-secret")
    assert client.get("/health").status_code == 200
    body = b'{"type":"k8s","namespace":"default"}'
    signature = "sha256=" + hmac.new(b"test-webhook-secret", body, hashlib.sha256).hexdigest()
    response = client.post(
        "/webhook/manual", content=body, headers={"X-Hub-Signature-256": signature}
    )
    assert response.status_code == 200
