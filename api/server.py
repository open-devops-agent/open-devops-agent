"""
DevOps AI Agent — FastAPI Webhook Server
Receives events from GitHub, Alertmanager, and manual triggers.
Durable queue + cloud storage for audit, logs, checkpoints, and org docs.
"""
import asyncio
import base64
import binascii
import inspect
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import structlog
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agent.core import DevOpsAgent
from agent.classifier import classify_issue
from api.api_auth import api_auth_disabled, require_org_access
from api.webhook_auth import (
    bearer_token,
    get_webhook_secret,
    verify_slack_signature,
    verify_webhook_auth,
    verify_webhook_request,
)
from services.background_lock import (
    acquire_background_worker_lock,
    release_background_worker_lock,
)
from services.incident_queue import IncidentQueue
from services.incident_store import IncidentStore
from services.org_docs import OrgDocs
from services.escalation import EscalationService, parse_queue_timestamp
from services.org_config import OrgConfig
from services.org_context import org_agent_credentials, org_credentials
from services.pii_scrubber import scrub_dict, scrub_text
from tools.notify import SlackNotifier
from tools.safety import is_emergency_stop_active

load_dotenv()

log = structlog.get_logger()

agent = DevOpsAgent()
notifier = SlackNotifier()
incident_queue = IncidentQueue()
incident_store = IncidentStore()
org_docs = OrgDocs()
org_config = OrgConfig()
escalation_service = EscalationService()

_queue_worker_task: Optional[asyncio.Task] = None
_retention_task: Optional[asyncio.Task] = None
_background_lock_handle = None
_queue_running = False

RETENTION_INTERVAL_SEC = 24 * 60 * 60  # one retention pass per day


def _org_id(context: dict, header_org: Optional[str] = None) -> str:
    return context.get("org_id") or header_org or os.getenv("ORG_ID", "default")


async def process_incident(entry: dict):
    """Process a single queued incident with checkpoint resume support."""
    incident_id = entry["incident_id"]
    org_id = entry["org_id"]
    context = entry.get("context", {})
    context["org_id"] = org_id
    context["incident_id"] = incident_id
    started_at = parse_queue_timestamp(entry)

    log.info("Processing incident", id=incident_id, org_id=org_id)

    with org_agent_credentials(org_id, agent, escalation_service):
        await _process_incident_with_org_creds(entry, incident_id, org_id, context, started_at)


async def _process_incident_with_org_creds(
    entry: dict, incident_id: str, org_id: str, context: dict, started_at
):
    result = None

    try:
        result = await agent.run(context, incident_id=incident_id, resume=True)

        decision = escalation_service.evaluate(
            incident_id, org_id, context, result, started_at
        )
        escalation_outcome = None
        if decision.should_escalate:
            escalation_outcome = await escalation_service.escalate(decision, incident_id, org_id)

        audit_entry = scrub_dict({
            "id": incident_id,
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident": context,
            "diagnosis": result.get("diagnosis"),
            "actions_taken": result.get("actions", []),
            "resolved": result.get("resolved", False),
            "fix_applied": result.get("fix_applied", False),
            "suggestions_only": result.get("suggestions_only", False),
            "suggested_fixes": result.get("suggested_fixes", []),
            "verification": result.get("verification"),
            "ai_reasoning": result.get("reasoning"),
            "grounding": result.get("grounding"),
            "steps": result.get("steps"),
            "duration_minutes": decision.duration_minutes,
            "escalated": decision.should_escalate,
            "escalation_reasons": decision.reasons,
            "escalation": escalation_outcome,
        })
        incident_store.save_audit(org_id, incident_id, audit_entry)
        incident_queue.mark_completed(org_id, incident_id, result)

        await notifier.send_resolution(incident_id, result)
        log.info(
            "Incident handled",
            id=incident_id,
            resolved=result.get("resolved"),
            escalated=decision.should_escalate,
        )

    except Exception as e:
        log.error("Incident handling failed", id=incident_id, error=str(e))
        decision = escalation_service.evaluate(
            incident_id, org_id, context, result, started_at, error=str(e)
        )
        escalation_outcome = None
        if decision.should_escalate:
            escalation_outcome = await escalation_service.escalate(decision, incident_id, org_id)

        incident_queue.mark_failed(org_id, incident_id, str(e))
        await notifier.send_error(incident_id, scrub_text(str(e)))

        incident_store.save_audit(org_id, incident_id, scrub_dict({
            "id": incident_id,
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident": context,
            "resolved": False,
            "error": scrub_text(str(e)),
            "escalated": decision.should_escalate,
            "escalation_reasons": decision.reasons,
            "escalation": escalation_outcome,
        }))


async def _queue_worker_loop():
    """Background worker — claims and processes incidents from cloud storage queue."""
    global _queue_running
    poll_interval = float(os.getenv("QUEUE_POLL_INTERVAL_SEC", "5"))
    _queue_running = True
    log.info("Queue worker started", poll_interval=poll_interval)

    while _queue_running:
        try:
            for org_id in incident_queue.list_pending_org_ids():
                incident_queue.recover_stale_processing(org_id)
                entry = incident_queue.claim_next(org_id)
                if entry:
                    await process_incident(entry)
        except Exception as e:
            log.error("Queue worker error", error=str(e))
        await asyncio.sleep(poll_interval)


def _retention_org_ids() -> List[str]:
    """Orgs to sweep: de-duplicated union of ORG_ID and comma-separated ORG_IDS.

    Mirrors the env parsing in IncidentQueue.list_pending_org_ids.
    """
    orgs = [os.getenv("ORG_ID", "default")]
    for org in os.getenv("ORG_IDS", "").split(","):
        org = org.strip()
        if org and org not in orgs:
            orgs.append(org)
    return orgs


async def run_retention_pass():
    """Run one retention pass over every configured org.

    A storage failure for one org is logged and does not stop the pass
    from attempting the remaining orgs; cancellation is never swallowed.
    """
    for org_id in _retention_org_ids():
        try:
            deleted = incident_store.apply_retention(org_id)
            if inspect.isawaitable(deleted):
                await deleted
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.error("Retention cleanup failed", org_id=org_id, error=str(e))


async def _retention_loop():
    """Background retention scheduler — one pass at startup, then every 24 hours."""
    while True:
        try:
            await run_retention_pass()
        except Exception as e:
            log.error("Retention pass error", error=str(e))
        await asyncio.sleep(RETENTION_INTERVAL_SEC)


async def enqueue_incident(context: dict, incident_id: Optional[str] = None) -> str:
    org = _org_id(context)
    context = dict(context)
    context["org_id"] = org
    return incident_queue.enqueue(org, context, incident_id)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _queue_worker_task, _retention_task, _background_lock_handle, _queue_running
    log.info("DevOps AI Agent starting", auto_apply=os.getenv("AUTO_APPLY", "false"))
    if api_auth_disabled():
        log.warning(
            "API_AUTH_DISABLED=true: org config, docs and audit endpoints are unauthenticated"
        )
    _background_lock_handle = acquire_background_worker_lock()
    try:
        incident_queue.adopt_legacy_reviews()
        if _background_lock_handle is None:
            log.info("Queue and retention loops are already running in another process")
        else:
            _queue_worker_task = asyncio.create_task(_queue_worker_loop())
            _retention_task = asyncio.create_task(_retention_loop())
        yield
    finally:
        _queue_running = False
        for task in (_queue_worker_task, _retention_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        _queue_worker_task = None
        _retention_task = None
        release_background_worker_lock(_background_lock_handle)
        _background_lock_handle = None
        log.info("DevOps AI Agent shutting down")


app = FastAPI(
    title="DevOps AI Agent",
    description="Autonomous incident diagnosis and remediation powered by Claude",
    version="1.1.0",
    lifespan=lifespan,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def verify_github_signature(payload: bytes, signature: str) -> bool:
    return verify_webhook_request(payload, signature)


def _require_webhook_auth(
    body: bytes,
    signature: Optional[str] = None,
    static_token: Optional[str] = None,
) -> None:
    if get_webhook_secret() and not verify_webhook_auth(body, signature, static_token):
        raise HTTPException(status_code=401, detail="Invalid signature")


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "auto_apply": os.getenv("AUTO_APPLY", "false"),
        "emergency_stop": is_emergency_stop_active(),
        "storage_provider": os.getenv("STORAGE_PROVIDER", "memory"),
        "org_id": os.getenv("ORG_ID", "default"),
        "queue_worker": _queue_running,
    }


@app.get("/audit")
async def get_audit(
    org_id: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """Return recent incident audit log from cloud storage (org-scoped)."""
    org = org_id or os.getenv("ORG_ID", "default")
    require_org_access(org, authorization)
    events = incident_store.list_audit(org, limit=limit)
    return {"org_id": org, "events": events, "total": len(events)}


class DocUploadBody(BaseModel):
    path: str
    content: str


class OrgConfigBody(BaseModel):
    credentials: dict


@app.put("/orgs/{org_id}/config")
async def save_org_config(
    org_id: str, body: OrgConfigBody, authorization: Optional[str] = Header(None)
):
    """Store org-owned API keys and integrations (BYOK — not platform operator keys)."""
    require_org_access(org_id, authorization)
    result = org_config.save(org_id, body.credentials)
    return {"status": "saved", **result}


@app.get("/orgs/{org_id}/config/status")
async def org_config_status(org_id: str, authorization: Optional[str] = Header(None)):
    """Which credentials are configured for this org (values never returned)."""
    require_org_access(org_id, authorization)
    return org_config.status(org_id)


@app.post("/orgs/{org_id}/docs")
async def upload_doc_text(
    org_id: str, body: DocUploadBody, authorization: Optional[str] = Header(None)
):
    """Upload org documentation (runbooks, policies, playbooks) as text."""
    require_org_access(org_id, authorization)
    try:
        key = org_docs.upload(org_id, body.path, body.content)
        return {"status": "uploaded", "org_id": org_id, "path": body.path, "storage_key": key}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/orgs/{org_id}/docs/upload")
async def upload_doc_file(
    org_id: str,
    path: str,
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
):
    """Upload org documentation from a file."""
    require_org_access(org_id, authorization)
    content = (await file.read()).decode("utf-8")
    try:
        key = org_docs.upload(org_id, path, content, file.content_type or "text/plain")
        return {"status": "uploaded", "org_id": org_id, "path": path, "storage_key": key}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/orgs/{org_id}/docs")
async def list_org_docs(
    org_id: str, prefix: str = "", authorization: Optional[str] = Header(None)
):
    """List org documentation files."""
    require_org_access(org_id, authorization)
    return {"org_id": org_id, "docs": org_docs.list_docs(org_id, prefix)}


@app.get("/orgs/{org_id}/docs/{doc_path:path}")
async def get_org_doc(
    org_id: str, doc_path: str, authorization: Optional[str] = Header(None)
):
    """Retrieve a single org documentation file."""
    require_org_access(org_id, authorization)
    content = org_docs.get(org_id, doc_path)
    if content is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return {"org_id": org_id, "path": doc_path, "content": content}


@app.delete("/orgs/{org_id}/docs/{doc_path:path}")
async def delete_org_doc(
    org_id: str, doc_path: str, authorization: Optional[str] = Header(None)
):
    require_org_access(org_id, authorization)
    if not org_docs.delete(org_id, doc_path):
        raise HTTPException(status_code=404, detail="Document not found")
    return {"status": "deleted", "org_id": org_id, "path": doc_path}


def _parse_json_body(body: Union[bytes, str]) -> Dict[str, Any]:
    """
    Parse a webhook request body as a JSON object.

    Args:
        body: Raw request body

    Returns:
        The parsed JSON object

    Raises:
        HTTPException: 400 if the body is not valid JSON or not a JSON object
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="JSON object required")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="JSON object required")
    return data


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str = Header(None),
    x_hub_signature_256: str = Header(None),
    x_org_id: str = Header(None, alias="X-Org-ID"),
):
    body = await request.body()

    _require_webhook_auth(body, x_hub_signature_256)

    payload = _parse_json_body(body)

    if x_github_event == "workflow_run":
        run = payload.get("workflow_run", {})
        if run.get("conclusion") == "failure":
            context = {
                "type": "cicd",
                "source": "github_actions",
                "org_id": x_org_id or os.getenv("GITHUB_ORG", os.getenv("ORG_ID", "default")),
                "repo": payload.get("repository", {}).get("full_name"),
                "run_id": run.get("id"),
                "workflow_name": run.get("name"),
                "branch": run.get("head_branch"),
                "commit": run.get("head_sha", "")[:8],
                "html_url": run.get("html_url"),
            }
            incident_id = await enqueue_incident(context)
            return {"status": "queued", "type": "cicd", "incident_id": incident_id}

    if x_github_event == "pull_request":
        action = payload.get("action")
        if action in ("opened", "reopened", "synchronize", "ready_for_review"):
            pr = payload.get("pull_request") or {}
            if pr.get("draft"):
                return {"status": "ignored", "reason": "draft_pr"}
            context = {
                "type": "code_review",
                "source": "github",
                "scm_platform": "github",
                "org_id": x_org_id or os.getenv("GITHUB_ORG", os.getenv("ORG_ID", "default")),
                "repo": payload.get("repository", {}).get("full_name"),
                "change_id": str(pr.get("number") or ""),
                "pr_number": pr.get("number"),
                "title": pr.get("title"),
                "author": (pr.get("user") or {}).get("login"),
                "html_url": pr.get("html_url"),
                "base_ref": (pr.get("base") or {}).get("ref"),
                "head_ref": (pr.get("head") or {}).get("ref"),
                "labels": {"pull_request": "true", "code_review": "true"},
            }
            incident_id = await enqueue_incident(context)
            return {"status": "queued", "type": "code_review", "incident_id": incident_id}

    return {"status": "ignored", "event": x_github_event}


def _alert_context(alert: dict, source: str, x_org_id: Optional[str]) -> dict:
    """Incident context for one Alertmanager-format alert (also sent by Grafana)."""
    labels = alert.get("labels") or {}
    annotations = alert.get("annotations") or {}
    alertname = labels.get("alertname", "")
    return {
        "type": _classify_alert(alertname, labels),
        "source": source,
        "org_id": x_org_id or labels.get("org_id") or os.getenv("ORG_ID", "default"),
        "alertname": alertname,
        "severity": labels.get("severity", "warning"),
        "namespace": labels.get("namespace"),
        "pod": labels.get("pod"),
        "service": labels.get("service"),
        "node": labels.get("node"),
        "summary": annotations.get("summary", ""),
        "description": annotations.get("description", ""),
        "starts_at": alert.get("startsAt"),
        "generator_url": alert.get("generatorURL"),
        "logql": annotations.get("logql") or annotations.get("loki_query"),
        "labels": labels,
    }


@app.post("/webhook/alertmanager")
async def alertmanager_webhook(
    request: Request,
    x_org_id: str = Header(None, alias="X-Org-ID"),
    x_hub_signature_256: str = Header(None),
    x_webhook_signature: str = Header(None, alias="X-Webhook-Signature"),
    authorization: str = Header(None),
):
    """Alertmanager alerts. Auth: HMAC signature or `Authorization: Bearer <WEBHOOK_SECRET>`."""
    body = await request.body()
    _require_webhook_auth(
        body,
        signature=x_hub_signature_256 or x_webhook_signature,
        static_token=bearer_token(authorization),
    )

    payload = _parse_json_body(body)
    queued = []

    for alert in payload.get("alerts", []):
        if alert.get("status") != "firing":
            continue
        incident_id = await enqueue_incident(_alert_context(alert, "alertmanager", x_org_id))
        queued.append(incident_id)

    return {"status": "queued", "incident_ids": queued}


@app.post("/webhook/grafana")
async def grafana_webhook(
    request: Request,
    x_org_id: str = Header(None, alias="X-Org-ID"),
    x_hub_signature_256: str = Header(None),
    x_webhook_signature: str = Header(None, alias="X-Webhook-Signature"),
    authorization: str = Header(None),
):
    """Grafana Alerting webhook contact point.

    Auth: `Authorization: Bearer <WEBHOOK_SECRET>` (set in the contact point's
    Authorization header settings) or an HMAC signature.
    """
    body = await request.body()
    _require_webhook_auth(
        body,
        signature=x_hub_signature_256 or x_webhook_signature,
        static_token=bearer_token(authorization),
    )

    payload = _parse_json_body(body)
    queued = []

    for alert in payload.get("alerts", []):
        if alert.get("status") != "firing":
            continue
        context = _alert_context(alert, "grafana", x_org_id)
        context.update(
            {
                "dashboard_url": alert.get("dashboardURL"),
                "panel_url": alert.get("panelURL"),
                "alert_values": alert.get("values"),
                "runbook_url": (alert.get("annotations") or {}).get("runbook_url"),
            }
        )
        queued.append(await enqueue_incident(context))

    return {"status": "queued", "incident_ids": queued}


@app.post("/webhook/gitlab")
async def gitlab_webhook(
    request: Request,
    x_org_id: str = Header(None, alias="X-Org-ID"),
    x_gitlab_event: str = Header(None, alias="X-Gitlab-Event"),
    x_gitlab_token: str = Header(None, alias="X-Gitlab-Token"),
    x_hub_signature_256: str = Header(None),
    x_webhook_signature: str = Header(None, alias="X-Webhook-Signature"),
):
    """GitLab pipeline failures and merge-request events for code review."""
    body = await request.body()
    _require_webhook_auth(
        body,
        signature=x_hub_signature_256 or x_webhook_signature,
        static_token=x_gitlab_token,
    )
    payload = _parse_json_body(body)
    event = (x_gitlab_event or payload.get("object_kind") or "").lower()

    if event in ("merge request hook", "merge_request"):
        attrs = payload.get("object_attributes") or {}
        action = (attrs.get("action") or "").lower()
        if action in ("open", "reopen") or (action == "update" and "oldrev" in attrs):
            if (attrs.get("state") or "").lower() in ("closed", "merged"):
                return {"status": "ignored", "reason": "closed_mr"}
            if attrs.get("work_in_progress") or attrs.get("draft"):
                return {"status": "ignored", "reason": "draft_mr"}
            project = payload.get("project") or {}
            context = {
                "type": "code_review",
                "source": "gitlab",
                "scm_platform": "gitlab",
                "org_id": x_org_id or os.getenv("ORG_ID", "default"),
                "repo": str(project.get("id") or project.get("path_with_namespace") or ""),
                "change_id": str(attrs.get("iid") or ""),
                "mr_iid": attrs.get("iid"),
                "title": attrs.get("title"),
                "author": (payload.get("user") or {}).get("username"),
                "html_url": attrs.get("url"),
                "base_ref": attrs.get("target_branch"),
                "head_ref": attrs.get("source_branch"),
                "head_sha": (attrs.get("last_commit") or {}).get("id"),
                "labels": {"merge_request": "true", "code_review": "true"},
            }
            incident_id = await enqueue_incident(context)
            return {"status": "queued", "type": "code_review", "incident_id": incident_id}

    if event in ("pipeline hook", "pipeline"):
        attrs = payload.get("object_attributes") or {}
        if attrs.get("status") == "failed":
            project = payload.get("project") or {}
            context = {
                "type": "cicd",
                "source": "gitlab_ci",
                "org_id": x_org_id or os.getenv("ORG_ID", "default"),
                "project_id": str(project.get("id") or ""),
                "pipeline_id": attrs.get("id"),
                "labels": {"cicd_platform": "gitlab"},
            }
            incident_id = await enqueue_incident(context)
            return {"status": "queued", "type": "cicd", "incident_id": incident_id}

    return {"status": "ignored", "event": event}


@app.post("/webhook/bitbucket")
async def bitbucket_webhook(
    request: Request,
    x_org_id: str = Header(None, alias="X-Org-ID"),
    x_event_key: str = Header(None, alias="X-Event-Key"),
    x_hub_signature_256: str = Header(None),
    x_webhook_signature: str = Header(None, alias="X-Webhook-Signature"),
    x_hub_signature: str = Header(None, alias="X-Hub-Signature"),
):
    """Bitbucket Cloud pull-request events for code review."""
    body = await request.body()
    _require_webhook_auth(body, x_hub_signature_256 or x_webhook_signature or x_hub_signature)
    payload = _parse_json_body(body)
    event = (x_event_key or "").lower()
    if event in ("pullrequest:created", "pullrequest:updated"):
        pr = payload.get("pullrequest") or {}
        if pr.get("draft") or (pr.get("state") or "").upper() == "DRAFT":
            return {"status": "ignored", "reason": "draft_pr"}
        if (pr.get("state") or "").upper() != "OPEN":
            return {"status": "ignored", "reason": "closed_pr"}
        repo = payload.get("repository") or {}
        workspace = (repo.get("workspace") or {}).get("slug") or ""
        slug = repo.get("slug") or repo.get("name") or ""
        full = f"{workspace}/{slug}" if workspace and slug else slug
        context = {
            "type": "code_review",
            "source": "bitbucket",
            "scm_platform": "bitbucket",
            "org_id": x_org_id or os.getenv("ORG_ID", "default"),
            "repo": full,
            "change_id": str(pr.get("id") or ""),
            "pr_number": pr.get("id"),
            "title": pr.get("title"),
            "author": (pr.get("author") or {}).get("display_name"),
            "html_url": (pr.get("links") or {}).get("html", {}).get("href"),
            "base_ref": ((pr.get("destination") or {}).get("branch") or {}).get("name"),
            "head_ref": ((pr.get("source") or {}).get("branch") or {}).get("name"),
            "head_sha": ((pr.get("source") or {}).get("commit") or {}).get("hash"),
            "labels": {"pull_request": "true", "code_review": "true"},
        }
        if not context["change_id"] or not context["repo"]:
            return {"status": "ignored", "reason": "missing_pr_fields"}
        incident_id = await enqueue_incident(context)
        return {"status": "queued", "type": "code_review", "incident_id": incident_id}

    return {"status": "ignored", "reason": "unsupported_event", "event": event}


@app.post("/webhook/manual")
async def manual_trigger(
    request: Request,
    x_org_id: str = Header(None, alias="X-Org-ID"),
    x_hub_signature_256: str = Header(None),
    x_webhook_signature: str = Header(None, alias="X-Webhook-Signature"),
):
    body = await request.body()
    _require_webhook_auth(body, x_hub_signature_256 or x_webhook_signature)

    context = _parse_json_body(body)
    if "type" not in context:
        raise HTTPException(status_code=400, detail="'type' field required")

    context["source"] = "manual"
    if x_org_id:
        context["org_id"] = x_org_id
    incident_id = await enqueue_incident(context)
    return {"status": "queued", "incident_id": incident_id, "context": context}


@app.post("/slack/action")
async def slack_action(
    request: Request,
    background_tasks: BackgroundTasks,
    x_slack_signature: str = Header(None, alias="X-Slack-Signature"),
    x_slack_request_timestamp: str = Header(None, alias="X-Slack-Request-Timestamp"),
):
    body = await request.body()
    if not verify_slack_signature(body, x_slack_request_timestamp, x_slack_signature):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")

    from urllib.parse import parse_qs
    form = parse_qs(body.decode())
    payload = __import__("json").loads(form.get("payload", ["{}"])[0])

    action = payload.get("actions", [{}])[0]
    action_id = action.get("action_id", "")
    value = action.get("value", "")
    user = payload.get("user") or {}
    actor_id = str(user.get("id") or "")
    actor_name = str(user.get("username") or user.get("name") or "")

    if action_id == "approve_action":
        try:
            approval = json.loads(value)
            org_id = approval["org_id"]
            incident_id = approval["incident_id"]
            if not all(
                isinstance(item, str) and item.strip() for item in (org_id, incident_id)
            ):
                raise ValueError("Missing approval organisation or incident")
            cmd = base64.b64decode(approval["command"], validate=True).decode()
            if not cmd.strip():
                raise ValueError("Missing approval command")
        except (ValueError, TypeError, KeyError, binascii.Error):
            # Old buttons do not identify the org. Never guess a tenant for them.
            raise HTTPException(
                status_code=400,
                detail="Invalid approval; request a new approval with organisation context",
            ) from None
        approvers = _slack_approvers(org_id)
        if approvers and actor_id not in approvers:
            _record_slack_decision(org_id, incident_id, "denied", actor_id, actor_name, cmd)
            return JSONResponse(
                {
                    "response_type": "ephemeral",
                    "replace_original": False,
                    "text": (
                        f"⛔ <@{actor_id}> is not an approver for this organization; nothing was run. "
                        "Ask someone listed in SLACK_APPROVER_IDS."
                    ),
                }
            )
        if not approvers:
            log.warning(
                "Slack approval accepted without an approver allowlist; set SLACK_APPROVER_IDS",
                org_id=org_id,
                approver_id=actor_id,
            )
        _record_slack_decision(org_id, incident_id, "approved", actor_id, actor_name, cmd)
        background_tasks.add_task(agent.execute_approved_action, incident_id, cmd, org_id=org_id)
        return JSONResponse({"text": f"✅ Approved by <@{actor_id}>. Executing: `{cmd}`"})

    elif action_id == "reject_action":
        org_id = os.getenv("ORG_ID", "default")
        _record_slack_decision(org_id, "PENDING", "rejected", actor_id, actor_name, None)
        return JSONResponse({"text": f"❌ Rejected by <@{actor_id}>. Incident escalated to on-call."})

    return JSONResponse({"text": "Unknown action"})


def _slack_approvers(org_id: str) -> set:
    """Slack user IDs allowed to approve actions for ``org_id`` (empty = no allowlist).

    Read inside the org's credential scope, so SLACK_APPROVER_IDS can be set per
    org through PUT /orgs/{org_id}/config as well as globally.
    """
    with org_credentials(org_id):
        raw = os.getenv("SLACK_APPROVER_IDS", "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def _record_slack_decision(
    org_id: str,
    incident_id: str,
    decision: str,
    actor_id: str,
    actor_name: str,
    command: Optional[str],
) -> None:
    """Keep who approved, rejected or was refused, and for which command."""
    now = datetime.now(timezone.utc)
    record = {
        "decision": decision,
        "slack_user_id": actor_id,
        "slack_user_name": actor_name,
        "org_id": org_id,
        "incident_id": incident_id,
        "command": command,
        "at": now.isoformat(),
    }
    log.info("Slack approval decision", **record)
    try:
        incident_store.save_log(
            org_id,
            incident_id,
            f"approval-{now.strftime('%Y%m%dT%H%M%S%f')}-{decision}.json",
            record,
        )
    except Exception as exc:  # recording must never block the decision itself
        log.warning("approval_record_failed", error=str(exc))


def _classify_alert(alertname: str, labels: dict) -> str:
    return classify_issue(alertname, labels)
