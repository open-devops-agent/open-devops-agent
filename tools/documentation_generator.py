"""
Incident documentation: a postmortem, a runbook and a knowledge-base article
rendered from what the agent actually did on an incident.

Documents are rendered in memory and returned as {filename: markdown}. The API
saves them next to the incident's other logs (see IncidentStore.save_document),
so they follow the same per-org storage, PII scrubbing and retention.

They are never written into the org's knowledge docs: the diagnosis can quote
alert and log text an attacker controls, and the agent reads those docs back.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional

ROLLBACK_HINTS = {
    "k8s": "kubectl rollout undo deployment/<name> -n <namespace>",
    "argocd": "argocd app rollback <app> <history-id>",
    "cicd": "git revert <commit> && git push",
    "server": "Restore the previous configuration from backup and restart the service",
    "database": "Restore the previous parameter group / config and restart the instance",
}

PERMISSIONS = {
    "k8s": "kubectl access to the affected namespace",
    "argocd": "Argo CD access to the application",
    "cicd": "CI/CD and repository access",
    "server": "SSH and sudo on the affected host",
    "cloud_aws": "AWS IAM permissions for the affected resource",
    "cloud_gcp": "GCP IAM permissions for the affected resource",
    "cloud_azure": "Azure RBAC permissions for the affected resource",
    "database": "Database admin access",
}

TAG_KEYWORDS = (
    "crash", "oom", "memory", "cpu", "disk", "network", "timeout", "certificate",
    "permission", "config", "deployment", "dns", "image", "database",
)


def _bullets(items: List[str], empty: str = "None recorded") -> str:
    items = [str(i).strip() for i in items if str(i).strip()]
    return "\n".join(f"- {i}" for i in items) if items else f"- {empty}"


def _checklist(items: List[str]) -> str:
    items = [str(i).strip() for i in items if str(i).strip()]
    return "\n".join(f"- [ ] {i}" for i in items) if items else "- [ ] Confirm the alert has cleared"


def _code(commands: List[str]) -> str:
    commands = [str(c) for c in commands if str(c).strip()]
    return "```bash\n" + "\n".join(commands) + "\n```" if commands else "_No commands recorded._"


def _title(context: dict) -> str:
    return str(context.get("alertname") or context.get("title") or context.get("type") or "Incident")[:80]


def _tags(issue_type: str, text: str) -> List[str]:
    text = text.lower()
    return sorted({issue_type, *(k for k in TAG_KEYWORDS if k in text)})


def _commands_run(actions: List[dict]) -> List[str]:
    commands = []
    for action in actions:
        inputs = action.get("input") if isinstance(action.get("input"), dict) else {}
        result = action.get("result") if isinstance(action.get("result"), dict) else {}
        command = inputs.get("command")
        if command and result.get("executed"):
            commands.append(str(command))
    return commands


def _tools_used(actions: List[dict]) -> List[str]:
    seen: List[str] = []
    for action in actions:
        tool = action.get("tool")
        if tool and tool not in seen:
            seen.append(tool)
    return seen


def render_incident_docs(
    incident_id: str, context: dict, result: dict, now: Optional[datetime] = None
) -> Dict[str, str]:
    """Render postmortem.md, runbook.md and kb.md for a completed incident."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%d %H:%M UTC")
    issue_type = str(result.get("issue_type") or context.get("type") or "unknown")
    title = _title(context)
    diagnosis = str(result.get("diagnosis") or "No diagnosis recorded.").strip()
    actions = result.get("actions") or []
    fixes = result.get("suggested_fixes") or []
    verification = result.get("verification") or {}
    resolved = bool(result.get("resolved"))
    status = "Resolved" if resolved else ("Fix suggested, awaiting a human" if fixes else "Unresolved, escalated")

    executed = _commands_run(actions)
    fix_commands = [c for f in fixes for c in (f.get("commands") or [])]
    verify_steps = [s for f in fixes for s in (f.get("verification_steps") or [])]
    if isinstance(verification, dict) and verification:
        outcome = "passed" if verification.get("verified") else "failed"
        reason = f": {verification['reason']}" if verification.get("reason") else ""
        verified_line = f"Automatic verification {outcome}{reason}"
    else:
        verified_line = "No automatic verification ran"
    tags = _tags(issue_type, f"{title} {diagnosis}")
    findings = result.get("threat_findings") or []

    fix_sections = "\n\n".join(
        f"### {f.get('title') or 'Suggested fix'}\n\n{f.get('description') or ''}\n\n{_code(f.get('commands') or [])}"
        for f in fixes
    ) or "_No fix was suggested._"

    security = ""
    if findings:
        security = "\n## Security findings\n\n" + _bullets(
            [f"{f.get('rule')} ({f.get('severity')}, {f.get('mitre_technique', '')})" for f in findings if isinstance(f, dict)]
        ) + "\n\nTreat this as a security incident: preserve evidence before changing anything.\n"

    postmortem = f"""# Postmortem: {title}

| | |
|---|---|
| Incident | `{incident_id}` |
| Type | {issue_type} |
| Severity | {context.get('severity', 'unknown')} |
| Source | {context.get('source') or context.get('alert_source') or 'unknown'} |
| Status | {status} |
| Fix applied by agent | {'yes' if result.get('fix_applied') else 'no'} |
| Written | {stamp} |

## Diagnosis

{diagnosis}
{security}
## What the agent did

Tools used:

{_bullets(_tools_used(actions))}

Commands executed:

{_code(executed)}

## Fixes

{fix_sections}

## Verification

{verified_line}

{_checklist(verify_steps)}

## Follow-up

- [ ] Confirm the root cause with the owning team
- [ ] Add or tune the alert that should have caught this earlier
- [ ] Decide whether the fix should be automated

Tags: {', '.join(tags)}

_Generated by the DevOps AI Agent from its own investigation. Review before sharing._
"""

    runbook = f"""# Runbook: {issue_type} – {title}

Use this when the same alert fires again.

## Symptoms

{_bullets([title, str(context.get('description') or context.get('summary') or '')])}

## Required access

{PERMISSIONS.get(issue_type, 'Access to the affected system')}

## Investigate

{_code(executed) if executed else _bullets([f'Run the `{t}` tool' for t in _tools_used(actions)])}

## Fix

{_code(fix_commands)}

## Verify

{_checklist(verify_steps)}

## Roll back

{ROLLBACK_HINTS.get(issue_type, 'Revert the change above and confirm the previous state.')}

_From incident `{incident_id}`, {stamp}._
"""

    kb = f"""# {title}

**Category:** {issue_type} · **Tags:** {', '.join(tags)}

## Cause and diagnosis

{diagnosis}

## Fix

{_code(fix_commands)}

_From incident `{incident_id}`, {stamp}._
"""
    return {"postmortem.md": postmortem, "runbook.md": runbook, "kb.md": kb}
