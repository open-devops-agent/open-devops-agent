"""
Prometheus metrics for the agent itself (#125), served at GET /metrics.

All metrics use a dedicated registry and low-cardinality labels: no incident
IDs, repos, hosts or orgs. Label values that come from requests (incident type,
source) are reduced to a fixed set so a crafted webhook cannot create
unbounded series.
"""
from __future__ import annotations

from typing import Optional

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

INCIDENT_TYPES = {
    "k8s", "cicd", "server", "argocd", "helm", "terraform", "dockerfile",
    "cloud_aws", "cloud_gcp", "cloud_azure", "observability", "data", "code_review",
}
INCIDENT_SOURCES = {
    "alertmanager", "grafana", "github", "gitlab", "gitlab_ci", "bitbucket",
    "manual", "middleware", "mcp", "pagerduty", "slack",
}

INCIDENTS = Counter(
    "devops_agent_incidents_total",
    "Incidents processed by the queue worker.",
    ["type", "source", "outcome"],
    registry=REGISTRY,
)
INCIDENT_DURATION = Histogram(
    "devops_agent_incident_duration_seconds",
    "Wall-clock time to process one incident (diagnosis, actions, verification).",
    ["type"],
    buckets=(5, 15, 30, 60, 120, 300, 600, 1200, 1800, 3600),
    registry=REGISTRY,
)
QUEUE_DEPTH = Gauge(
    "devops_agent_queue_depth",
    "Incidents waiting or in progress, summed over all orgs.",
    ["state"],
    registry=REGISTRY,
)
TOOL_CALLS = Counter(
    "devops_agent_tool_calls_total",
    "Tool calls made by the agent, by outcome.",
    ["tool", "result"],
    registry=REGISTRY,
)
APPROVALS = Counter(
    "devops_agent_approvals_total",
    "Slack approval decisions.",
    ["decision"],
    registry=REGISTRY,
)
LLM_TOKENS = Counter(
    "devops_agent_llm_tokens_total",
    "Claude API tokens used.",
    ["model", "kind"],
    registry=REGISTRY,
)
FIX_VERIFICATIONS = Counter(
    "devops_agent_fix_verification_total",
    "Post-remediation verification results.",
    ["status"],
    registry=REGISTRY,
)
HTTP_REQUESTS = Counter(
    "devops_agent_http_requests_total",
    "HTTP requests handled, by route template and status code.",
    ["route", "method", "status"],
    registry=REGISTRY,
)
EMERGENCY_STOP = Gauge(
    "devops_agent_emergency_stop",
    "1 while AGENT_EMERGENCY_STOP is active.",
    registry=REGISTRY,
)


def _bounded(value: Optional[str], allowed: set) -> str:
    value = (value or "").strip().lower()
    return value if value in allowed else ("unknown" if not value else "other")


def record_incident(context: dict, outcome: str, duration_seconds: float) -> None:
    incident_type = _bounded(context.get("type"), INCIDENT_TYPES)
    source = _bounded(context.get("source"), INCIDENT_SOURCES)
    INCIDENTS.labels(incident_type, source, outcome).inc()
    INCIDENT_DURATION.labels(incident_type).observe(max(0.0, duration_seconds))


def tool_result_label(result) -> str:
    if not isinstance(result, dict):
        return "ok"
    if result.get("emergency_stop"):
        return "emergency_stop"
    if result.get("requires_approval"):
        return "requires_approval"
    if result.get("blocked"):
        return "blocked"
    if result.get("error") or result.get("success") is False:
        return "error"
    return "ok"


def record_tool_call(name: str, result, known_tools: set) -> None:
    tool = name if name in known_tools else "other"
    TOOL_CALLS.labels(tool, tool_result_label(result)).inc()


def record_llm_usage(model: str, usage) -> None:
    if usage is None:
        return
    for kind in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"):
        count = getattr(usage, kind, None)
        if isinstance(count, int) and count > 0:
            LLM_TOKENS.labels(model or "unknown", kind.removesuffix("_tokens")).inc(count)


def record_verification(verification: Optional[dict]) -> None:
    if not verification:
        return
    status = str(verification.get("status") or ("verified" if verification.get("verified") else "unknown"))
    FIX_VERIFICATIONS.labels(_bounded(status, {"verified", "failed", "unstable", "unknown"})).inc()
