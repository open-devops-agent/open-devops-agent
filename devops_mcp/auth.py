"""
Authentication and org binding for the MCP server's network transports (#116).

- ``MCP_AUTH_TOKEN``: bearer token required on every HTTP request when the
  server runs over ``sse`` or ``streamable-http``. Without it the server refuses
  to start, except with ``MCP_AUTH_DISABLED=true`` on a loopback address.
- ``MCP_ORG_ID``: bind the server to one org. Tool calls for any other org are
  rejected, and calls without ``org_id`` use the bound org.
- ``configure_org_credentials`` is only registered over network transports when
  ``MCP_ALLOW_CREDENTIAL_WRITE=true``.

stdio is a local, single-user transport and is not affected.
"""
from __future__ import annotations

import ipaddress
import json
import os
from typing import Any, Awaitable, Callable, Optional

from api.webhook_auth import _signatures_equal, bearer_token

NETWORK_TRANSPORTS = ("sse", "streamable-http")


def _env_flag(name: str) -> bool:
    return os.getenv(name, "false").strip().lower() in ("true", "1", "yes")


def mcp_auth_token() -> str:
    return os.getenv("MCP_AUTH_TOKEN", "").strip()


def mcp_auth_disabled() -> bool:
    return _env_flag("MCP_AUTH_DISABLED")


def credential_writes_allowed(transport: str) -> bool:
    return transport not in NETWORK_TRANSPORTS or _env_flag("MCP_ALLOW_CREDENTIAL_WRITE")


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_network_auth(host: str) -> Optional[str]:
    """Return the bearer token to enforce, or raise if the server must not start.

    Returns None only when auth is explicitly disabled on a loopback host.
    """
    token = mcp_auth_token()
    if token:
        return token
    if mcp_auth_disabled() and is_loopback(host):
        return None
    if mcp_auth_disabled():
        raise SystemExit(
            f"MCP_AUTH_DISABLED=true is only allowed on a loopback host, not {host!r}. "
            "Set MCP_AUTH_TOKEN to serve MCP over the network."
        )
    raise SystemExit(
        "MCP_AUTH_TOKEN is required for the sse and streamable-http transports. "
        "Clients must send `Authorization: Bearer <MCP_AUTH_TOKEN>`."
    )


def resolve_org(org_id: Optional[str]) -> str:
    """The org a tool call acts on, enforcing MCP_ORG_ID when the server is bound."""
    requested = (org_id or "").strip()
    pinned = os.getenv("MCP_ORG_ID", "").strip()
    if pinned:
        if requested and requested != pinned:
            raise ValueError(f"This MCP server is bound to org {pinned!r}; {requested!r} is not allowed")
        return pinned
    return requested or os.getenv("ORG_ID", "default")


ASGIApp = Callable[[dict, Callable[[], Awaitable[dict]], Callable[[dict], Awaitable[None]]], Awaitable[None]]


class BearerAuthMiddleware:
    """Reject HTTP requests without ``Authorization: Bearer <token>``."""

    def __init__(self, app: ASGIApp, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        provided = bearer_token(headers.get("authorization"))
        if provided and _signatures_equal(self.token, provided):
            await self.app(scope, receive, send)
            return
        body = json.dumps({"error": "unauthorized", "detail": "Bearer token required"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b"Bearer"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def protect_http_apps(mcp: Any, token: str) -> None:
    """Wrap FastMCP's Starlette app factories so both HTTP transports require the token."""
    sse_app = mcp.sse_app
    streamable_http_app = mcp.streamable_http_app
    mcp.sse_app = lambda *args, **kwargs: BearerAuthMiddleware(sse_app(*args, **kwargs), token)
    mcp.streamable_http_app = lambda *args, **kwargs: BearerAuthMiddleware(
        streamable_http_app(*args, **kwargs), token
    )
