"""
Precedence tests for the MCP bind address: explicit --host/--port flags must
beat FASTMCP_HOST/FASTMCP_PORT from the environment (e.g. loaded from .env),
which in turn beat the built-in defaults 127.0.0.1/8090.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def mcp_auth_token(monkeypatch):
    # Network transports refuse to start without a token (#116); these tests
    # are about bind-address precedence, so provide one.
    monkeypatch.setenv("MCP_AUTH_TOKEN", "test-mcp-token")


@pytest.fixture
def stubbed_mcp(monkeypatch):
    """Stub only server creation; the os.environ handling in run_mcp runs for real."""
    import devops_mcp.server

    mcp = MagicMock()
    monkeypatch.setattr(devops_mcp.server, "create_mcp_server", lambda **_kwargs: mcp)
    return mcp


def test_explicit_host_port_beat_env(monkeypatch, stubbed_mcp):
    from devops_mcp.server import run_mcp

    monkeypatch.setenv("FASTMCP_HOST", "203.0.113.9")
    monkeypatch.setenv("FASTMCP_PORT", "8888")

    run_mcp(transport="sse", host="203.0.113.7", port=9999)

    import os

    assert os.environ["FASTMCP_HOST"] == "203.0.113.7"
    assert os.environ["FASTMCP_PORT"] == "9999"
    stubbed_mcp.run.assert_called_once_with(transport="sse")


def test_env_used_when_flags_absent(monkeypatch, stubbed_mcp):
    from devops_mcp.server import run_mcp

    monkeypatch.setenv("FASTMCP_HOST", "203.0.113.9")
    monkeypatch.setenv("FASTMCP_PORT", "8888")

    run_mcp(transport="sse")

    import os

    assert os.environ["FASTMCP_HOST"] == "203.0.113.9"
    assert os.environ["FASTMCP_PORT"] == "8888"


def test_defaults_when_no_env_and_no_flags(monkeypatch, stubbed_mcp):
    from devops_mcp.server import run_mcp

    monkeypatch.delenv("FASTMCP_HOST", raising=False)
    monkeypatch.delenv("FASTMCP_PORT", raising=False)

    run_mcp(transport="streamable-http")

    import os

    assert os.environ["FASTMCP_HOST"] == "127.0.0.1"
    assert os.environ["FASTMCP_PORT"] == "8090"


def test_cli_explicit_flags_beat_env(monkeypatch, stubbed_mcp):
    """The issue #40 repro: drive the real CLI with real argv, stub only the server."""
    from devops_agent.cli import main

    monkeypatch.setenv("FASTMCP_HOST", "203.0.113.9")
    monkeypatch.setenv("FASTMCP_PORT", "8888")
    monkeypatch.setattr(
        sys, "argv", ["devops-agent", "mcp", "--transport", "sse", "--host", "203.0.113.7", "--port", "9999"]
    )

    with pytest.raises(SystemExit) as excinfo:
        main()

    import os

    assert excinfo.value.code == 0
    assert os.environ["FASTMCP_HOST"] == "203.0.113.7"
    assert os.environ["FASTMCP_PORT"] == "9999"
    stubbed_mcp.run.assert_called_once_with(transport="sse")


def test_cli_env_used_when_flags_absent(monkeypatch, stubbed_mcp):
    from devops_agent.cli import main

    monkeypatch.setenv("FASTMCP_HOST", "203.0.113.9")
    monkeypatch.setenv("FASTMCP_PORT", "8888")
    monkeypatch.setattr(sys, "argv", ["devops-agent", "mcp", "--transport", "sse"])

    with pytest.raises(SystemExit) as excinfo:
        main()

    import os

    assert excinfo.value.code == 0
    assert os.environ["FASTMCP_HOST"] == "203.0.113.9"
    assert os.environ["FASTMCP_PORT"] == "8888"


@pytest.fixture
def captured_bind(monkeypatch):
    """Capture the address the REAL server would bind, without starting it.

    create_mcp_server runs for real; only FastMCP.run is monkeypatched, so the
    FastMCP instance's frozen settings (host/port) are asserted directly.
    """
    from mcp.server.fastmcp import FastMCP

    captured = {}

    def fake_run(self, transport=None, **_kwargs):
        captured["host"] = self.settings.host
        captured["port"] = self.settings.port
        captured["transport"] = transport

    monkeypatch.setattr(FastMCP, "run", fake_run)
    return captured


def test_real_server_env_used_when_flags_absent(monkeypatch, captured_bind):
    from devops_mcp.server import run_mcp

    monkeypatch.setenv("FASTMCP_HOST", "203.0.113.9")
    monkeypatch.setenv("FASTMCP_PORT", "8888")

    run_mcp(transport="sse")

    assert captured_bind["host"] == "203.0.113.9"
    assert captured_bind["port"] == 8888


def test_real_server_explicit_flags_beat_env(monkeypatch, captured_bind):
    from devops_mcp.server import run_mcp

    monkeypatch.setenv("FASTMCP_HOST", "203.0.113.9")
    monkeypatch.setenv("FASTMCP_PORT", "8888")

    run_mcp(transport="sse", host="203.0.113.7", port=9999)

    assert captured_bind["host"] == "203.0.113.7"
    assert captured_bind["port"] == 9999


def test_real_server_stdio_ignores_invalid_env_port(monkeypatch, captured_bind):
    """stdio never binds TCP: an unparseable FASTMCP_PORT must not raise.

    Regression: the stdio branch used to resolve int(FASTMCP_PORT) even though
    the value is never used to bind, so FASTMCP_PORT=not-an-integer raised
    ValueError before the server could run.
    """
    from devops_mcp.server import run_mcp

    monkeypatch.setenv("FASTMCP_PORT", "not-an-integer")

    run_mcp(transport="stdio")

    assert captured_bind["transport"] == "stdio"
