"""MCP network transport authentication and org binding (#116)."""
import os

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP
from starlette.testclient import TestClient

from devops_mcp.auth import (
    check_network_auth,
    credential_writes_allowed,
    is_loopback,
    protect_http_apps,
    resolve_org,
)

TOKEN = "mcp-secret-token"
# Only passed to the auth checks as a host string; nothing binds to it.
ALL_INTERFACES = "0.0.0.0"  # nosec B104
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}
STREAMABLE_HEADERS = {"Accept": "application/json, text/event-stream"}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (
        "MCP_AUTH_TOKEN",
        "MCP_AUTH_DISABLED",
        "MCP_ORG_ID",
        "MCP_ALLOW_CREDENTIAL_WRITE",
        "FASTMCP_HOST",
        "FASTMCP_PORT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ORG_ID", "default-org")


def small_server():
    mcp = FastMCP(name="test")

    @mcp.tool()
    def ping() -> str:
        return "pong"

    return mcp


class TestStartup:
    @pytest.mark.parametrize("host", ["127.0.0.1", ALL_INTERFACES, "10.1.2.3"])
    def test_network_transport_requires_token(self, host):
        with pytest.raises(SystemExit, match="MCP_AUTH_TOKEN is required"):
            check_network_auth(host)

    def test_token_is_returned_when_set(self, monkeypatch):
        monkeypatch.setenv("MCP_AUTH_TOKEN", TOKEN)
        assert check_network_auth(ALL_INTERFACES) == TOKEN

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
    def test_disable_allowed_on_loopback_only(self, monkeypatch, host):
        monkeypatch.setenv("MCP_AUTH_DISABLED", "true")
        assert check_network_auth(host) is None

    @pytest.mark.parametrize("host", [ALL_INTERFACES, "10.1.2.3", "agent.internal"])
    def test_disable_refused_off_loopback(self, monkeypatch, host):
        monkeypatch.setenv("MCP_AUTH_DISABLED", "true")
        with pytest.raises(SystemExit, match="only allowed on a loopback host"):
            check_network_auth(host)

    def test_is_loopback(self):
        assert is_loopback("127.0.0.5") and is_loopback("::1") and is_loopback("localhost")
        assert not is_loopback(ALL_INTERFACES) and not is_loopback("") and not is_loopback("example.com")

    @pytest.mark.parametrize("transport", ["sse", "streamable-http"])
    def test_run_mcp_refuses_without_token(self, monkeypatch, transport):
        import devops_mcp.server

        create = MagicMock()
        monkeypatch.setattr(devops_mcp.server, "create_mcp_server", create)
        with pytest.raises(SystemExit):
            devops_mcp.server.run_mcp(transport=transport, host=ALL_INTERFACES)
        create.assert_not_called()

    def test_run_mcp_protects_http_apps(self, monkeypatch):
        import devops_mcp.server

        monkeypatch.setenv("MCP_AUTH_TOKEN", TOKEN)
        server = small_server()
        monkeypatch.setattr(devops_mcp.server, "create_mcp_server", lambda **_: server)
        monkeypatch.setattr(server, "run", lambda transport: None)
        devops_mcp.server.run_mcp(transport="streamable-http", host=ALL_INTERFACES, port=9000)
        with TestClient(server.streamable_http_app()) as client:
            assert client.post("/mcp", json=INITIALIZE, headers=STREAMABLE_HEADERS).status_code == 401

    def test_stdio_needs_no_token(self, monkeypatch):
        import devops_mcp.server

        server = MagicMock()
        monkeypatch.setattr(devops_mcp.server, "create_mcp_server", lambda **_: server)
        devops_mcp.server.run_mcp(transport="stdio")
        server.run.assert_called_once_with(transport="stdio")


class TestBearerMiddleware:
    @pytest.fixture
    def streamable(self):
        server = small_server()
        protect_http_apps(server, TOKEN)
        # FastMCP's DNS-rebinding protection only accepts loopback Host headers.
        with TestClient(server.streamable_http_app(), base_url="http://127.0.0.1:8090") as client:
            yield client

    @pytest.mark.parametrize(
        "headers",
        [{}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN}"}, {"Authorization": TOKEN}],
        ids=["missing", "wrong", "basic", "no-scheme"],
    )
    def test_streamable_http_rejects(self, streamable, headers):
        response = streamable.post("/mcp", json=INITIALIZE, headers={**STREAMABLE_HEADERS, **headers})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_streamable_http_accepts_token(self, streamable):
        response = streamable.post(
            "/mcp",
            json=INITIALIZE,
            headers={**STREAMABLE_HEADERS, "Authorization": f"Bearer {TOKEN}"},
        )
        assert response.status_code == 200
        assert "serverInfo" in response.text

    def test_sse_endpoints_reject_without_token(self):
        server = small_server()
        protect_http_apps(server, TOKEN)
        client = TestClient(server.sse_app())
        assert client.get("/sse").status_code == 401
        assert client.post("/messages/?session_id=abc", json=INITIALIZE).status_code == 401

    def test_sse_message_endpoint_passes_token_through(self):
        server = small_server()
        protect_http_apps(server, TOKEN)
        client = TestClient(server.sse_app())
        response = client.post(
            "/messages/?session_id=" + "0" * 32,
            json=INITIALIZE,
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        # Authenticated: reaches the SSE transport, which rejects the unknown session.
        assert response.status_code != 401


class TestOrgBinding:
    def test_unbound_uses_requested_or_default(self):
        assert resolve_org("acme") == "acme"
        assert resolve_org("") == "default-org"
        assert resolve_org(None) == "default-org"

    def test_bound_server_rejects_other_orgs(self, monkeypatch):
        monkeypatch.setenv("MCP_ORG_ID", "acme")
        assert resolve_org("") == "acme"
        assert resolve_org("acme") == "acme"
        with pytest.raises(ValueError, match="bound to org 'acme'"):
            resolve_org("globex")


@pytest.fixture
def real_server(monkeypatch):
    from devops_mcp.server import create_mcp_server

    def build(transport):
        return create_mcp_server(host="127.0.0.1", port=8090, transport=transport)

    return build


async def tool_names(server):
    return {tool.name for tool in await server.list_tools()}


class TestCredentialTool:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("transport", ["sse", "streamable-http"])
    async def test_not_registered_over_network_by_default(self, real_server, transport):
        names = await tool_names(real_server(transport))
        assert "configure_org_credentials" not in names
        assert "get_org_config_status" in names

    @pytest.mark.asyncio
    async def test_opt_in_over_network(self, real_server, monkeypatch):
        monkeypatch.setenv("MCP_ALLOW_CREDENTIAL_WRITE", "true")
        assert "configure_org_credentials" in await tool_names(real_server("sse"))

    @pytest.mark.asyncio
    async def test_registered_on_stdio(self, real_server):
        assert "configure_org_credentials" in await tool_names(real_server("stdio"))

    def test_credential_writes_allowed(self, monkeypatch):
        assert credential_writes_allowed("stdio")
        assert not credential_writes_allowed("sse")
        monkeypatch.setenv("MCP_ALLOW_CREDENTIAL_WRITE", "true")
        assert credential_writes_allowed("streamable-http")


class TestBoundServerTools:
    @pytest.mark.asyncio
    async def test_platform_tool_rejects_other_org(self, real_server, monkeypatch):
        from mcp.server.fastmcp.exceptions import ToolError

        monkeypatch.setenv("MCP_ORG_ID", "acme")
        server = real_server("stdio")
        with pytest.raises(ToolError, match="bound to org"):
            await server.call_tool("get_incident_audit", {"org_id": "globex"})
        with pytest.raises(ToolError, match="bound to org"):
            await server.call_tool(
                "configure_org_credentials", {"org_id": "globex", "credentials": {"GITLAB_TOKEN": "x"}}
            )

    @pytest.mark.asyncio
    async def test_platform_tool_defaults_to_bound_org(self, real_server, monkeypatch):
        monkeypatch.setenv("MCP_ORG_ID", "acme")
        server = real_server("stdio")
        result = await server.call_tool("get_incident_audit", {})
        assert "acme" in str(result)

    @pytest.mark.asyncio
    async def test_agent_tool_rejects_other_org(self, real_server, monkeypatch):
        from mcp.server.fastmcp.exceptions import ToolError

        monkeypatch.setenv("MCP_ORG_ID", "acme")
        server = real_server("stdio")
        with pytest.raises(ToolError, match="bound to org"):
            await server.call_tool("query_logs", {"org_id": "globex", "query": '{app="x"}'})
