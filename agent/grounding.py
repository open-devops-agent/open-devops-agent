"""
Anti-hallucination grounding — require tool evidence before claiming diagnosis/fixes.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

# Issue types that MUST gather live data via tools before resolving
REQUIRES_TOOL_EVIDENCE: Set[str] = {
    "k8s", "cicd", "server", "argocd", "helm", "terraform",
    "cloud_aws", "cloud_gcp", "cloud_azure",
    "observability", "data", "code_review",
}

# Tools that count as evidence-gathering (not just notify)
EVIDENCE_TOOLS: Set[str] = {
    "get_k8s_context",
    "get_github_logs",
    "get_cicd_logs",
    "get_argocd_status",
    "get_argocd_history",
    "get_cloud_resource",
    "run_shell_command",
    "run_kubectl",
    "get_helm_release",
    "terraform_plan",
    "terraform_validate",
    "get_argocd_status",
    "inspect_disk_usage",
    "diagnose_nginx",
    "bamboo_check_version",
    "query_metrics",
    "evaluate_slo",
    "capacity_check",
    "query_traces",
    "run_synthetic",
    "get_oncall_roster",
    "check_database_health",
    "list_snapshots",
    "dr_readiness_check",
    "kafka_health",
    "elasticsearch_health",
    "redis_health",
    "fetch_code_change",
    "list_open_code_changes",
}

GROUNDING_RULES = """
## GROUNDING RULES (MANDATORY — prevents hallucination)

1. NEVER state a root cause unless you can cite specific evidence from tool output or org documentation.
2. ALWAYS call at least one data-gathering tool before concluding diagnosis for infrastructure incidents.
3. Quote exact error lines, exit codes, pod states, or log snippets from tool results — do not paraphrase from memory.
4. If tool data is missing, inconclusive, or returns an error, say "insufficient evidence" and list what you still need.
5. NEVER invent resource names, IP addresses, error messages, config values, or fix outcomes.
6. NEVER claim a fix was applied unless a remediation tool returned success without error.
7. Prefer org documentation (runbooks/policies) over general knowledge when both apply.
8. In your final summary, include an "Evidence:" section listing tool names and specific findings.
9. If you cannot gather evidence within the step limit, escalate via notify_slack with what was checked.
10. DATABASE ISSUES: Never attempt direct DB changes. The system auto-escalates DB incidents to Jira/Zoho/email/Slack for human/DBA handling.
11. If you cannot resolve within available steps, document findings clearly — the system will auto-create a ticket for the team.
12. FIX SUGGESTIONS (FALLBACK): If collectors, prompts, or tools cannot fully resolve the issue, use suggest_fix as the NEXT option.
    Provide non-destructive commands, YAML/compose/config snippets, and verification steps the human team can run.
    Use suggest_fix when: collection failed/partial, AUTO_APPLY is off, tool returned blocked/requires_approval, or no safe auto-fix exists.
    Never suggest delete, drop, rm -rf, terminate, truncate, or any data-destructive action.
13. RESOLUTION ORDER: (1) gather evidence → (2) apply safe auto-fix if allowed → (3) suggest_fix if not → (4) notify_slack → (5) escalate if still stuck.
"""

REMEDIATION_TOOLS: Set[str] = {
    "apply_k8s_manifest",
    "run_kubectl",
    "run_shell_command",
    "rollback_deployment",
    "sync_argocd_app",
    "rollback_argocd_app",
    "restart_cloud_resource",
    "scale_cloud_service",
    "retry_cicd_pipeline",
    "create_github_pr",
    "create_cicd_pr",
    "helm_rollback",
    "helm_upgrade",
    "cleanup_stale_logs",
    "install_log_cleanup_cron",
    "apply_nginx_config",
    "restart_nginx",
    "renew_certificates",
    "apply_security_updates",
    "bamboo_increment_version",
    "patch_bamboo_plan",
    "update_status_page",
    "assign_incident_commander",
    "create_snapshot",
    "post_code_review",
}

SUGGESTION_TOOLS: Set[str] = {"suggest_fix"}


def has_suggestions(actions_taken: List[dict]) -> bool:
    for action in actions_taken:
        if action.get("tool") in SUGGESTION_TOOLS:
            result = action.get("result", {})
            if result.get("recorded"):
                return True
    return False


def extract_suggested_fixes(actions_taken: List[dict]) -> List[dict]:
    fixes = []
    for action in actions_taken:
        if action.get("tool") == "suggest_fix":
            result = action.get("result", {})
            if result.get("recorded"):
                fixes.append({
                    "title": result.get("title"),
                    "description": result.get("description"),
                    "commands": result.get("commands", []),
                    "config_snippets": result.get("config_snippets", []),
                    "verification_steps": result.get("verification_steps", []),
                })
    return fixes


def append_grounding_rules(prompt: str) -> str:
    return prompt + "\n" + GROUNDING_RULES


def has_tool_evidence(actions_taken: List[dict]) -> bool:
    for action in actions_taken:
        tool = action.get("tool", "")
        result = action.get("result", {})
        if tool in EVIDENCE_TOOLS and not result.get("error") and not result.get("blocked"):
            return True
    return False


def has_successful_remediation(actions_taken: List[dict]) -> bool:
    for action in actions_taken:
        tool = action.get("tool", "")
        result = action.get("result", {})
        if tool in REMEDIATION_TOOLS:
            if result.get("error") or result.get("blocked"):
                continue
            if result.get("success") is False:
                continue
            return True
    return False


def validate_resolution(
    issue_type: str,
    actions_taken: List[dict],
    diagnosis: str,
    claimed_resolved: bool = True,
) -> Dict[str, Any]:
    """
    Returns validation result. If insufficient evidence, mark as not grounded.
    """
    needs_evidence = issue_type in REQUIRES_TOOL_EVIDENCE
    has_evidence = has_tool_evidence(actions_taken)

    issues = []
    if needs_evidence and not has_evidence:
        issues.append("No data-gathering tool was called — diagnosis may be hallucinated.")

    if claimed_resolved and any(t in diagnosis.lower() for t in ("fixed", "resolved", "applied", "restarted")):
        if not has_successful_remediation(actions_taken) and not has_evidence:
            issues.append("Claims fix/resolution without successful remediation tool evidence.")

    if "evidence:" not in diagnosis.lower() and needs_evidence and has_evidence:
        issues.append("Missing required Evidence section in diagnosis.")

    has_sug = has_suggestions(actions_taken)
    if needs_evidence and has_evidence and not has_sug and not has_successful_remediation(actions_taken):
        issues.append("Provide non-destructive fix steps via suggest_fix before finishing.")

    grounded = len(issues) == 0
    return {
        "grounded": grounded,
        "issues": issues,
        "has_tool_evidence": has_evidence,
        "has_suggestions": has_sug,
        "requires_evidence": needs_evidence,
    }


def build_evidence_reminder(validation: dict) -> str:
    issues = validation.get("issues", [])
    extra = ""
    if any("suggest_fix" in i for i in issues):
        extra = (
            "\n\nUse suggest_fix with non-destructive commands and config snippets — "
            "this is the fallback when collectors or auto-fix cannot resolve the issue."
        )
    return (
        "Your response failed grounding validation:\n"
        + "\n".join(f"- {i}" for i in issues)
        + "\n\nCall the appropriate data-gathering tool NOW, then provide diagnosis with an Evidence: section "
        "citing exact tool output. If you cannot auto-fix, use suggest_fix before finishing."
        + extra
    )
