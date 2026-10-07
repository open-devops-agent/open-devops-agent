"""
Safety controls — emergency stop and configurable approval requirements.
"""
import os
from typing import Optional

# Maps REQUIRE_APPROVAL_FOR action names to command substrings (lowercase).
APPROVAL_ACTION_PATTERNS = {
    "rollback": [
        "kubectl rollout undo",
        "helm rollback",
        "rollback",
    ],
    "scale_down": [
        "kubectl scale",
        "scale deployment",
    ],
    "delete": [
        "kubectl delete",
        "helm uninstall",
        "helm delete",
        "rm ",
        "rm-",
    ],
    "exec": [
        "kubectl exec",
        "docker exec",
    ],
}

MUTATING_AGENT_TOOLS = {
    "apply_k8s_manifest",
    "run_kubectl",
    "rollback_deployment",
    "run_shell_command",
    "sync_argocd_app",
    "rollback_argocd_app",
    "helm_rollback",
    "helm_upgrade",
    "restart_ec2_instance",
    "scale_ecs_service",
    "restart_gce_instance",
    "restart_azure_vm",
    "restart_cloud_resource",
    "scale_cloud_service",
    "cleanup_stale_logs",
    "install_log_cleanup_cron",
    "apply_nginx_config",
    "restart_nginx",
    "renew_certificates",
    "apply_security_updates",
    "bamboo_increment_version",
    "patch_bamboo_plan",
    "retry_cicd_pipeline",
    "create_github_pr",
    "create_cicd_pr",
    "update_status_page",
    "create_snapshot",
}


def is_emergency_stop_active() -> bool:
    return os.getenv("AGENT_EMERGENCY_STOP", "false").lower() == "true"


def get_require_approval_actions() -> set[str]:
    raw = os.getenv("REQUIRE_APPROVAL_FOR", "rollback,scale_down,delete,exec")
    return {a.strip().lower() for a in raw.split(",") if a.strip()}


def command_matches_approval_action(command: str, action: str) -> bool:
    patterns = APPROVAL_ACTION_PATTERNS.get(action.lower(), [])
    cmd = command.strip().lower()
    return any(p in cmd for p in patterns)


def requires_configured_approval(command: str) -> bool:
    """True when command matches an action listed in REQUIRE_APPROVAL_FOR."""
    for action in get_require_approval_actions():
        if command_matches_approval_action(command, action):
            return True
    return False


def emergency_stop_block(message: str = "Agent emergency stop is active. Mutating operations are disabled.") -> dict:
    return {
        "blocked": True,
        "emergency_stop": True,
        "requires_approval": False,
        "message": message,
    }


def check_emergency_stop_for_tool(tool_name: str) -> Optional[dict]:
    if is_emergency_stop_active() and tool_name in MUTATING_AGENT_TOOLS:
        return emergency_stop_block(
            f"Agent emergency stop is active. Tool `{tool_name}` is disabled."
        )
    return None
