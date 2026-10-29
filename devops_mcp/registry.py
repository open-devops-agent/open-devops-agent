"""Register DevOps agent tools and platform APIs on a FastMCP server."""
from __future__ import annotations

import inspect
import json
import os
from typing import Any, Callable, Optional

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from agent.core import AGENT_TOOLS, DevOpsAgent
from devops_mcp.auth import resolve_org
from services.incident_queue import IncidentQueue
from services.incident_store import IncidentStore
from services.org_config import OrgConfig
from services.org_context import org_agent_credentials
from services.org_docs import OrgDocs

load_dotenv()

_TYPE_MAP = {
    "string": str,
    "integer": int,
    "boolean": bool,
    "array": list,
    "object": dict,
    "number": float,
}


def _build_signature(schema: dict) -> inspect.Signature:
    params = [
        inspect.Parameter(
            "org_id",
            inspect.Parameter.KEYWORD_ONLY,
            # Empty means "the default org" (ORG_ID, or MCP_ORG_ID when bound).
            default="",
            annotation=str,
        )
    ]
    required = set(schema.get("required", []))
    for prop_name, prop_schema in schema.get("properties", {}).items():
        py_type = _TYPE_MAP.get(prop_schema.get("type", "string"), Any)
        if prop_name in required:
            params.append(
                inspect.Parameter(prop_name, inspect.Parameter.KEYWORD_ONLY, annotation=py_type)
            )
        else:
            params.append(
                inspect.Parameter(
                    prop_name,
                    inspect.Parameter.KEYWORD_ONLY,
                    default=prop_schema.get("default"),
                    annotation=Optional[py_type],
                )
            )
    return inspect.Signature(params)


def _make_agent_tool_handler(
    agent: DevOpsAgent,
    tool_name: str,
    schema: dict,
) -> Callable[..., Any]:
    async def handler(**kwargs: Any) -> dict:
        org_id = resolve_org(kwargs.pop("org_id", None))
        context = {"org_id": org_id}
        with org_agent_credentials(org_id, agent):
            return await agent.execute_tool(tool_name, kwargs, context)

    handler.__name__ = tool_name
    sig = _build_signature(schema)
    handler.__signature__ = sig
    handler.__annotations__ = {
        p.name: p.annotation for p in sig.parameters.values() if p.annotation is not inspect.Parameter.empty
    }
    handler.__annotations__["return"] = dict
    return handler


def register_agent_tools(mcp: FastMCP, agent: DevOpsAgent) -> None:
    """Expose every AGENT_TOOLS entry as an MCP tool."""
    for tool_def in AGENT_TOOLS:
        handler = _make_agent_tool_handler(agent, tool_def["name"], tool_def["input_schema"])
        mcp.add_tool(
            handler,
            name=tool_def["name"],
            description=tool_def["description"],
        )


def register_platform_tools(
    mcp: FastMCP,
    agent: DevOpsAgent,
    incident_queue: IncidentQueue,
    incident_store: IncidentStore,
    org_docs: OrgDocs,
    org_config: OrgConfig,
    allow_credential_writes: bool = True,
) -> None:
    """Incident queue, audit, org docs, and full agent diagnosis for MCP clients.

    ``configure_org_credentials`` is only registered when ``allow_credential_writes``
    is true (always on stdio; on network transports only with
    MCP_ALLOW_CREDENTIAL_WRITE=true).
    """

    if allow_credential_writes:

        @mcp.tool(
            name="configure_org_credentials",
            description=(
                "Store this org's own API keys and integrations (Anthropic, Slack, GitHub, kube, cloud). "
                "Each org brings their own credentials — not the platform operator's."
            ),
        )
        async def configure_org_credentials(
            credentials: dict,
            org_id: str = "",
        ) -> dict:
            org = resolve_org(org_id)
            result = org_config.save(org, credentials)
            return {"status": "saved", **result}

    @mcp.tool(
        name="get_org_config_status",
        description="Check which credentials are configured for an org (values are never returned).",
    )
    async def get_org_config_status(org_id: str = "") -> dict:
        org = resolve_org(org_id)
        return org_config.status(org)

    @mcp.tool(name="enqueue_incident", description="Queue an incident for background processing by the DevOps agent worker.")
    async def enqueue_incident(
        incident_type: str,
        org_id: str = "",
        context: Optional[dict] = None,
        incident_id: Optional[str] = None,
    ) -> dict:
        """Add an incident to the durable queue (processed by the API server's queue worker)."""
        org = resolve_org(org_id)
        payload = dict(context or {})
        payload.setdefault("type", incident_type)
        payload.setdefault("source", "mcp")
        payload["org_id"] = org
        queued_id = incident_queue.enqueue(org, payload, incident_id)
        return {"status": "queued", "incident_id": queued_id, "org_id": org}

    @mcp.tool(
        name="diagnose_incident",
        description=(
            "Run the full DevOps AI agent on an incident context (Claude reasoning loop). "
            "Use individual tools instead when you only need diagnostics or remediation actions."
        ),
    )
    async def diagnose_incident(
        incident_type: str,
        org_id: str = "",
        context: Optional[dict] = None,
        incident_id: Optional[str] = None,
    ) -> dict:
        """Synchronously run the built-in agent loop and return diagnosis + actions."""
        org = resolve_org(org_id)
        payload = dict(context or {})
        payload.setdefault("type", incident_type)
        payload.setdefault("source", "mcp")
        payload["org_id"] = org
        iid = incident_id or f"mcp-{org}"
        with org_agent_credentials(org, agent):
            result = await agent.run(payload, incident_id=iid, resume=False)
        return result

    @mcp.tool(name="get_incident_audit", description="Fetch recent incident audit entries for an organization.")
    async def get_incident_audit(org_id: str = "", limit: int = 20) -> dict:
        org = resolve_org(org_id)
        events = incident_store.list_audit(org, limit=limit)
        return {"org_id": org, "total": len(events), "events": events}

    @mcp.tool(name="list_org_docs", description="List runbooks, playbooks, and policies stored for an organization.")
    async def list_org_docs(org_id: str = "", prefix: str = "") -> dict:
        org = resolve_org(org_id)
        docs = org_docs.list_docs(org, prefix)
        return {"org_id": org, "docs": docs}

    @mcp.tool(name="get_org_doc", description="Retrieve a single org documentation file (runbook, policy, etc.).")
    async def get_org_doc(doc_path: str, org_id: str = "") -> dict:
        org = resolve_org(org_id)
        content = org_docs.get(org, doc_path)
        if content is None:
            return {"org_id": org, "path": doc_path, "error": "Document not found"}
        return {"org_id": org, "path": doc_path, "content": content}

    @mcp.tool(name="upload_org_doc", description="Upload or update org documentation (runbook, policy, playbook).")
    async def upload_org_doc(doc_path: str, content: str, org_id: str = "") -> dict:
        org = resolve_org(org_id)
        key = org_docs.upload(org, doc_path, content)
        return {"status": "uploaded", "org_id": org, "path": doc_path, "storage_key": key}


def register_resources(
    mcp: FastMCP,
    incident_store: IncidentStore,
    org_docs: OrgDocs,
) -> None:
    default_org = resolve_org(None)

    @mcp.resource(f"devops://audit/{default_org}")
    def audit_resource() -> str:
        """Recent incident audit log for the default organization."""
        events = incident_store.list_audit(default_org, limit=20)
        return json.dumps({"org_id": default_org, "events": events}, indent=2)

    @mcp.resource(f"devops://docs/{default_org}/index")
    def docs_index() -> str:
        """Index of org documentation for the default organization."""
        docs = org_docs.list_docs(default_org)
        return json.dumps({"org_id": default_org, "docs": docs}, indent=2)

    @mcp.resource("devops://health")
    def health_resource() -> str:
        """Server health and configuration summary."""
        return json.dumps(
            {
                "status": "ok",
                "auto_apply": os.getenv("AUTO_APPLY", "false"),
                "storage_provider": os.getenv("STORAGE_PROVIDER", "memory"),
                "org_id": default_org,
                "agent_tools_count": len(AGENT_TOOLS),
            },
            indent=2,
        )
