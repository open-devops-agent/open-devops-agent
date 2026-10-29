"""
DevOps AI Agent MCP Server

Exposes DevOps remediation tools, incident queue APIs, and org docs to any MCP client
(Cursor, Claude Desktop, custom agents, etc.) — not only the built-in agent loop.

Usage:
    devops-agent mcp                    # stdio (Cursor / Claude Desktop)
    MCP_AUTH_TOKEN=... devops-agent mcp --transport sse --port 8090

Network transports (sse, streamable-http) require MCP_AUTH_TOKEN; see devops_mcp/auth.py.
"""
from __future__ import annotations

import os

import structlog
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from agent.core import AGENT_TOOLS, DevOpsAgent
from devops_mcp.auth import check_network_auth, credential_writes_allowed, protect_http_apps
from devops_mcp.registry import register_agent_tools, register_platform_tools, register_resources
from services.incident_queue import IncidentQueue
from services.incident_store import IncidentStore
from services.org_config import OrgConfig
from services.org_docs import OrgDocs

load_dotenv()
log = structlog.get_logger()

INSTRUCTIONS = """\
DevOps AI Agent MCP — infrastructure incident response for any AI agent.

**Bring your own keys (BYOK):** Each org uses their own Anthropic, Slack, GitHub,
kube, and cloud credentials — configure them in your MCP env block or via
configure_org_credentials. The platform operator should not supply org secrets.

Use individual tools (get_k8s_context, get_github_logs, run_kubectl, etc.) to gather
context and apply safe remediations. Use enqueue_incident to queue work for the
background worker, or diagnose_incident to run the full Claude agent loop with your org's API key.

Org runbooks: list_org_docs / get_org_doc. Audit history: get_incident_audit.
"""


def create_mcp_server(host: str, port: int, transport: str = "stdio") -> FastMCP:
    mcp = FastMCP(
        name="devops-ai-agent",
        instructions=INSTRUCTIONS,
        host=host,
        port=port,
    )

    agent = DevOpsAgent()
    incident_queue = IncidentQueue()
    incident_store = IncidentStore()
    org_docs = OrgDocs()
    org_config = OrgConfig()

    register_agent_tools(mcp, agent)
    register_platform_tools(
        mcp,
        agent,
        incident_queue,
        incident_store,
        org_docs,
        org_config,
        allow_credential_writes=credential_writes_allowed(transport),
    )
    register_resources(mcp, incident_store, org_docs)

    log.info(
        "DevOps MCP server initialized",
        tools=len(AGENT_TOOLS) + 8,
        org_id=os.getenv("ORG_ID", "default"),
    )
    return mcp


def run_mcp(
    transport: str = "stdio",
    host: str | None = None,
    port: int | None = None,
) -> None:
    if transport == "stdio":
        # stdio never binds TCP, so FASTMCP_HOST/FASTMCP_PORT are irrelevant
        # on this path: do not read, parse, validate, or mutate them.
        mcp = create_mcp_server(
            host=host if host is not None else "127.0.0.1",
            port=port if port is not None else 8090,
        )
        mcp.run(transport="stdio")
        return

    if transport in ("sse", "streamable-http"):
        # Explicit host/port beat the environment; FASTMCP_HOST/FASTMCP_PORT
        # (e.g. from .env) supply the value only when no flag was passed.
        # FastMCP 1.x freezes settings at construction time, so resolve the
        # bind address first and pass it explicitly to create_mcp_server.
        if host is not None:
            os.environ["FASTMCP_HOST"] = host
        else:
            os.environ.setdefault("FASTMCP_HOST", "127.0.0.1")
            host = os.environ["FASTMCP_HOST"]
        if port is not None:
            os.environ["FASTMCP_PORT"] = str(port)
        else:
            os.environ.setdefault("FASTMCP_PORT", "8090")
            port = int(os.environ["FASTMCP_PORT"])
        token = check_network_auth(host)
        mcp = create_mcp_server(host=host, port=port, transport=transport)
        if token:
            protect_http_apps(mcp, token)
        else:
            log.warning("MCP_AUTH_DISABLED=true: MCP over HTTP is unauthenticated (loopback only)")
        mcp.run(transport=transport)
        return

    raise ValueError(f"Unknown transport: {transport}. Use stdio, sse, or streamable-http.")


if __name__ == "__main__":
    run_mcp()
