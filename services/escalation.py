"""
Escalation service — create tickets / notify team when the agent cannot resolve.

Triggers:
- Incident unresolved after ESCALATION_TIMEOUT_MINUTES (default 10)
- Database-related incidents (blocked DB access or DB alert keywords)
- AI failure (exceptions, max steps, not grounded / hallucination risk)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

from collectors.database_policy import incident_involves_blocked_database, is_database_incident
from services.pii_scrubber import scrub_dict, scrub_text
from tools.email_notifier import EmailNotifier
from tools.jira_tools import JiraClient
from tools.notify import SlackNotifier
from tools.pagerduty_tools import PagerDutyClient
from tools.zoho_tools import ZohoDeskClient

log = structlog.get_logger()

REASON_LABELS = {
    "timeout_unresolved": "Exceeded time limit without resolution",
    "unresolved": "Agent could not resolve the incident",
    "database_issue": "Database issue — requires DBA / human investigation",
    "agent_error": "Agent crashed or API failure",
    "not_grounded": "Insufficient evidence — possible hallucination risk",
    "max_steps_reached": "Max agent steps reached without fix",
    "ai_cannot_solve": "Issue outside agent capabilities",
}


@dataclass
class EscalationDecision:
    should_escalate: bool
    reasons: List[str] = field(default_factory=list)
    priority: str = "high"
    summary: str = ""
    description: str = ""
    duration_minutes: float = 0.0


class EscalationService:
    def __init__(self):
        self.slack = SlackNotifier()
        self.email = EmailNotifier()
        self.jira = JiraClient()
        self.zoho = ZohoDeskClient()
        self.pagerduty = PagerDutyClient()
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        """Re-read escalation clients after an org credential overlay."""
        self.enabled = os.getenv("ESCALATION_ENABLED", "true").lower() == "true"
        self.timeout_minutes = int(os.getenv("ESCALATION_TIMEOUT_MINUTES", "10"))
        self.channels = [
            c.strip().lower()
            for c in os.getenv("ESCALATION_CHANNELS", "slack,email").split(",")
            if c.strip()
        ]
        self.on_db = os.getenv("ESCALATION_ON_DB_ISSUES", "true").lower() == "true"
        self.on_unresolved = os.getenv("ESCALATION_ON_UNRESOLVED", "true").lower() == "true"
        self.on_ai_failure = os.getenv("ESCALATION_ON_AI_FAILURE", "true").lower() == "true"
        self.on_security = os.getenv("ESCALATION_ON_SECURITY", "true").lower() == "true"
        for client in (self.email, self.jira, self.zoho, self.pagerduty):
            refresh = getattr(client, "refresh_credentials", None)
            if callable(refresh):
                refresh()

    def evaluate(
        self,
        incident_id: str,
        org_id: str,
        context: dict,
        result: Optional[dict],
        started_at: datetime,
        error: Optional[str] = None,
    ) -> EscalationDecision:
        if not self.enabled:
            return EscalationDecision(should_escalate=False)

        now = datetime.now(timezone.utc)
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        duration_min = (now - started_at).total_seconds() / 60

        result = result or {}
        reasons: List[str] = []
        actions = result.get("actions", [])
        resolved = result.get("resolved", False)
        grounding = result.get("grounding") or {}

        if error and self.on_ai_failure:
            reasons.append("agent_error")

        db_incident = is_database_incident(context) or incident_involves_blocked_database(actions)
        if db_incident and self.on_db:
            reasons.append("database_issue")

        if not resolved and self.on_unresolved:
            reasons.append("unresolved")
            if duration_min >= self.timeout_minutes:
                reasons.append("timeout_unresolved")

        if grounding.get("grounded") is False and self.on_ai_failure:
            reasons.append("not_grounded")

        if result.get("diagnosis") == "Max steps reached without resolution":
            reasons.append("max_steps_reached")

        threats = result.get("threat_findings") or context.get("threat_findings") or {}
        security_incident = (
            context.get("type") == "security"
            or result.get("issue_type") == "security"
            or threats.get("highest_severity") in ("high", "critical")
        )
        if security_incident and self.on_security:
            reasons.insert(0, "security_incident")

        if not reasons:
            return EscalationDecision(should_escalate=False, duration_minutes=duration_min)

        priority = "critical" if "database_issue" in reasons or "agent_error" in reasons else "high"
        if "timeout_unresolved" in reasons:
            priority = "high"
        if "security_incident" in reasons and threats.get("highest_severity") == "critical":
            priority = "critical"

        issue_type = result.get("issue_type") or context.get("type", "unknown")
        summary = self._build_summary(incident_id, issue_type, reasons)
        description = self._build_description(
            incident_id, org_id, context, result, reasons, duration_min, error
        )

        return EscalationDecision(
            should_escalate=True,
            reasons=reasons,
            priority=priority,
            summary=summary,
            description=description,
            duration_minutes=duration_min,
        )

    async def escalate(self, decision: EscalationDecision, incident_id: str, org_id: str) -> Dict[str, Any]:
        if not decision.should_escalate:
            return {"escalated": False}

        log.info(
            "Escalating incident",
            incident_id=incident_id,
            reasons=decision.reasons,
            channels=self.channels,
        )

        outcomes: Dict[str, Any] = {
            "escalated": True,
            "incident_id": incident_id,
            "org_id": org_id,
            "reasons": decision.reasons,
            "channels": {},
        }

        labels = ["devops-ai-agent"] + [r.replace("_", "-") for r in decision.reasons]

        if "slack" in self.channels:
            await self.slack.send_escalation(
                incident_id=incident_id,
                org_id=org_id,
                summary=decision.summary,
                reasons=decision.reasons,
                description=decision.description,
                duration_minutes=decision.duration_minutes,
                priority=decision.priority,
            )
            outcomes["channels"]["slack"] = {"sent": True}

        if "email" in self.channels:
            sent = self.email.send_escalation_ticket(
                incident_id=incident_id,
                org_id=org_id,
                summary=decision.summary,
                reasons=decision.reasons,
                description=decision.description,
                priority=decision.priority,
            )
            outcomes["channels"]["email"] = {"sent": sent}

        if "jira" in self.channels:
            jira_result = await self.jira.create_ticket(
                summary=decision.summary,
                description=decision.description,
                priority=decision.priority,
                labels=labels,
            )
            outcomes["channels"]["jira"] = jira_result

        if "zoho" in self.channels:
            zoho_result = await self.zoho.create_ticket(
                subject=decision.summary,
                description=decision.description,
                priority="High" if decision.priority != "low" else "Medium",
            )
            outcomes["channels"]["zoho"] = zoho_result

        if "pagerduty" in self.channels:
            pagerduty_result = await self.pagerduty.create_incident(
                title=decision.summary,
                description=decision.description,
                priority=decision.priority,
                incident_key=incident_id,
            )
            outcomes["channels"]["pagerduty"] = pagerduty_result

        return outcomes

    def _build_summary(self, incident_id: str, issue_type: str, reasons: List[str]) -> str:
        primary = REASON_LABELS.get(reasons[0], reasons[0])
        return f"[DevOps Agent] {primary} — {issue_type} ({incident_id})"

    def _build_description(
        self,
        incident_id: str,
        org_id: str,
        context: dict,
        result: dict,
        reasons: List[str],
        duration_min: float,
        error: Optional[str],
    ) -> str:
        reason_lines = "\n".join(
            f"- {REASON_LABELS.get(r, r)}" for r in reasons
        )
        actions = result.get("actions", [])
        action_lines = "\n".join(
            f"- {a.get('tool')}: {'error' if a.get('result', {}).get('error') else 'ok'}"
            for a in actions[:10]
        ) or "- None"

        return scrub_text(f"""
ESCALATION — Human intervention required
========================================

Incident ID: {incident_id}
Organization: {org_id}
Duration: {duration_min:.1f} minutes
Timeout threshold: {self.timeout_minutes} minutes

ESCALATION REASONS:
{reason_lines}

INCIDENT CONTEXT:
{scrub_dict(context)}

AGENT DIAGNOSIS:
{result.get('diagnosis', 'N/A')[:2000]}

ACTIONS ATTEMPTED:
{action_lines}

GROUNDING:
{result.get('grounding', {})}

AGENT ERROR:
{error or 'None'}

NEXT STEPS FOR HUMAN:
1. Review incident logs in cloud storage: {org_id}/logs/
2. Check audit entry: GET /audit?org_id={org_id}
3. For database issues: engage DBA team — agent cannot access DB by default
4. Apply manual fix and document in org runbooks
""")


def parse_queue_timestamp(entry: dict) -> datetime:
    for key in ("created_at", "claimed_at", "recovered_at"):
        ts = entry.get(key)
        if ts:
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                pass
    return datetime.now(timezone.utc)
