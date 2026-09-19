"""
DevOps AI Agent — Core Agent Loop
Uses Claude's tool_use to reason, decide, and act on infrastructure incidents.
"""
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

import anthropic
import structlog

from agent.classifier import classify_issue, get_cicd_platform
from agent.grounding import (
    REMEDIATION_TOOLS,
    build_evidence_reminder,
    extract_suggested_fixes,
    has_successful_remediation,
    validate_resolution,
)
from agent.prompts import get_system_prompt
from collectors.k8s import K8sCollector
from collectors.github import GitHubCollector
from collectors.gitlab import GitLabCollector
from collectors.jenkins import JenkinsCollector
from collectors.bamboo import BambooCollector
from collectors.azure_devops import AzureDevOpsCollector
from collectors.argocd import ArgoCDCollector
from collectors.helm import HelmCollector
from collectors.aws import AWSCollector
from collectors.gcp import GCPCollector
from collectors.azure import AzureCollector
from collectors.server import ServerCollector
from collectors.security_scanner import SecurityScanner
from tools.executor import SafeExecutor
from tools.safety import check_emergency_stop_for_tool
from tools.k8s_tools import K8sTools
from tools.github_tools import GitHubTools
from tools.cicd_tools import CICDTools
from tools.argocd_tools import ArgoCDTools
from tools.helm_tools import HelmTools
from tools.iac_tools import IaCTools
from tools.cloud_tools import CloudTools
from tools.notify import SlackNotifier
from tools.fix_suggestions import validate_suggestion
from tools.fix_verifier import FixVerifier
from collectors.database_policy import check_database_access
from services.incident_store import IncidentStore
from services.org_docs import OrgDocs
from services.org_context import org_credentials, refresh_agent_credentials
from services.pii_scrubber import scrub_dict, scrub_text, scrub_value

log = structlog.get_logger()

AGENT_TOOLS = [
    {
        "name": "get_k8s_context",
        "description": "Fetch Kubernetes pod logs, events, describe output, and resource usage for a failing pod.",
        "input_schema": {
            "type": "object",
            "properties": {
                "namespace": {"type": "string", "description": "K8s namespace"},
                "pod_name": {"type": "string", "description": "Pod name or prefix"},
                "include_previous": {"type": "boolean", "description": "Include logs from previous crashed container"},
            },
            "required": ["namespace"],
        },
    },
    {
        "name": "get_github_logs",
        "description": "Fetch the full failed job logs from a GitHub Actions workflow run.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "owner/repo"},
                "run_id": {"type": "integer", "description": "Workflow run ID"},
            },
            "required": ["repo", "run_id"],
        },
    },
    {
        "name": "apply_k8s_manifest",
        "description": "Apply a fixed Kubernetes YAML manifest. Always dry_run=true first.",
        "input_schema": {
            "type": "object",
            "properties": {
                "manifest_yaml": {"type": "string", "description": "Complete YAML manifest"},
                "dry_run": {"type": "boolean", "description": "If true, validate only (don't apply). Default true."},
                "namespace": {"type": "string"},
            },
            "required": ["manifest_yaml"],
        },
    },
    {
        "name": "run_kubectl",
        "description": "Run a safe kubectl command (restart, scale, rollout). No delete commands.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "kubectl command without 'kubectl' prefix, e.g. 'rollout restart deployment/api -n production'"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "run_shell_command",
        "description": "Run a safe server remediation command (systemctl, nginx, df, ps). No rm or destructive commands.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"},
                "host": {"type": "string", "description": "Target host (optional, defaults to localhost)"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "create_github_pr",
        "description": "Create a GitHub PR with a config/Dockerfile fix applied to a branch.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "file_path": {"type": "string", "description": "File to update e.g. '.github/workflows/deploy.yml'"},
                "new_content": {"type": "string", "description": "Full new file content"},
                "pr_title": {"type": "string"},
                "pr_body": {"type": "string"},
            },
            "required": ["repo", "file_path", "new_content", "pr_title", "pr_body"],
        },
    },
    {
        "name": "rollback_deployment",
        "description": "Roll back a Kubernetes deployment to the previous revision.",
        "input_schema": {
            "type": "object",
            "properties": {
                "deployment": {"type": "string"},
                "namespace": {"type": "string"},
                "revision": {"type": "integer", "description": "Specific revision number, or omit for previous"},
            },
            "required": ["deployment", "namespace"],
        },
    },
    {
        "name": "notify_slack",
        "description": "Send a message to Slack with diagnosis and actions taken.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Human-readable summary"},
                "severity": {"type": "string", "enum": ["info", "warning", "critical"]},
                "resolved": {"type": "boolean"},
                "requires_approval": {"type": "boolean"},
                "approval_command": {"type": "string", "description": "Command that needs human approval"},
            },
            "required": ["message", "severity"],
        },
    },
    {
        "name": "suggest_fix",
        "description": (
            "Propose non-destructive fixes for the team to apply. Use when AUTO_APPLY is off, "
            "approval is needed, or to document the exact remediation steps. "
            "NEVER suggest delete, drop, rm -rf, terminate, or data-destructive commands. "
            "Include concrete commands, YAML/config snippets, and verification steps."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short fix title"},
                "description": {"type": "string", "description": "What to do and why (cite evidence)"},
                "commands": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Non-destructive shell/kubectl/docker commands to run manually or with approval",
                },
                "config_snippets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "YAML, compose, nginx, or env config changes (full snippets)",
                },
                "verification_steps": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "How to confirm the fix worked",
                },
            },
            "required": ["title", "description", "commands"],
        },
    },
    # ─── Multi-platform CI/CD Tools ───────────────────────────────────────────
    {
        "name": "get_cicd_logs",
        "description": "Fetch CI/CD pipeline/build logs. Supports: GitHub Actions, GitLab CI, Jenkins, Bamboo, Azure DevOps.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string", "enum": ["github", "gitlab", "jenkins", "bamboo", "azure_devops"]},
                "project_id": {"type": "string", "description": "Project/repo/job identifier"},
                "pipeline_id": {"type": "string", "description": "Pipeline/build/run ID"},
                "additional_params": {"type": "object", "description": "Platform-specific params (e.g., zone, cluster)"},
            },
            "required": ["platform", "project_id"],
        },
    },
    {
        "name": "retry_cicd_pipeline",
        "description": "Retry a failed CI/CD pipeline. Supports: GitLab, Jenkins, Bamboo, Azure DevOps.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string", "enum": ["gitlab", "jenkins", "bamboo", "azure_devops"]},
                "project_id": {"type": "string", "description": "Project/job identifier"},
                "pipeline_id": {"type": "string", "description": "Pipeline/build ID"},
                "additional_params": {"type": "object", "description": "Platform-specific params"},
            },
            "required": ["platform", "project_id"],
        },
    },
    {
        "name": "create_cicd_pr",
        "description": "Create a PR/MR with a CI/CD config fix. Supports: GitHub (via create_github_pr), GitLab, Azure DevOps.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string", "enum": ["github", "gitlab", "azure_devops"]},
                "repo": {"type": "string", "description": "Repository identifier"},
                "file_path": {"type": "string"},
                "new_content": {"type": "string"},
                "pr_title": {"type": "string"},
                "pr_body": {"type": "string"},
                "additional_params": {"type": "object"},
            },
            "required": ["platform", "repo", "file_path", "new_content", "pr_title", "pr_body"],
        },
    },
    # ─── ArgoCD Tools ─────────────────────────────────────────────────────────
    {
        "name": "get_argocd_status",
        "description": "Get ArgoCD application status, health, sync status, and resource details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_name": {"type": "string", "description": "ArgoCD application name"},
            },
            "required": ["app_name"],
        },
    },
    {
        "name": "sync_argocd_app",
        "description": "Sync an ArgoCD application. Always use dry_run=true first to preview changes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_name": {"type": "string"},
                "prune": {"type": "boolean", "description": "Remove resources not in Git. Default false."},
                "dry_run": {"type": "boolean", "description": "Preview only. Default true."},
            },
            "required": ["app_name"],
        },
    },
    {
        "name": "rollback_argocd_app",
        "description": "Rollback an ArgoCD application to a previous git revision.",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_name": {"type": "string"},
                "revision": {"type": "string", "description": "Git commit SHA. If omitted, rolls back to previous revision."},
            },
            "required": ["app_name"],
        },
    },
    {
        "name": "get_argocd_history",
        "description": "Get deployment history for an ArgoCD application.",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_name": {"type": "string"},
                "limit": {"type": "integer", "description": "Max history items. Default 10."},
            },
            "required": ["app_name"],
        },
    },
    # ─── Helm Tools ───────────────────────────────────────────────────────────
    {
        "name": "get_helm_release",
        "description": "Fetch Helm release status, history, values, and manifest preview.",
        "input_schema": {
            "type": "object",
            "properties": {
                "release_name": {"type": "string"},
                "namespace": {"type": "string", "description": "Kubernetes namespace (default: default)"},
            },
            "required": ["release_name"],
        },
    },
    {
        "name": "helm_rollback",
        "description": "Roll back a Helm release to a previous revision. Never uninstall.",
        "input_schema": {
            "type": "object",
            "properties": {
                "release_name": {"type": "string"},
                "namespace": {"type": "string"},
                "revision": {"type": "integer", "description": "Target revision (omit for previous)"},
            },
            "required": ["release_name", "namespace"],
        },
    },
    {
        "name": "helm_upgrade",
        "description": "Upgrade a Helm release. Always dry_run=true first. No uninstall.",
        "input_schema": {
            "type": "object",
            "properties": {
                "release_name": {"type": "string"},
                "chart": {"type": "string", "description": "Chart reference e.g. ./chart or repo/chart"},
                "namespace": {"type": "string"},
                "values_yaml": {"type": "string", "description": "Optional values YAML content"},
                "dry_run": {"type": "boolean", "description": "Default true — validate before applying"},
            },
            "required": ["release_name", "chart", "namespace"],
        },
    },
    # ─── Terraform / IaC Tools (read-only) ────────────────────────────────────
    {
        "name": "terraform_validate",
        "description": "Run terraform validate in a workspace (read-only).",
        "input_schema": {
            "type": "object",
            "properties": {
                "workspace_path": {"type": "string", "description": "Path to Terraform module root"},
            },
        },
    },
    {
        "name": "terraform_plan",
        "description": "Run terraform plan to detect drift (read-only — never apply).",
        "input_schema": {
            "type": "object",
            "properties": {
                "workspace_path": {"type": "string"},
                "extra_args": {"type": "string", "description": "Optional plan flags e.g. -target=module.vpc"},
            },
        },
    },
    # ─── Cloud Provider Tools ─────────────────────────────────────────────────
    {
        "name": "get_cloud_resource",
        "description": (
            "Get diagnostic info for cloud resources. Supports AWS, GCP, Azure compute, "
            "containers, K8s (EKS/GKE/AKS), load balancers, and more. "
            "Database resources (RDS, Cloud SQL, Azure SQL, Redis, DynamoDB) are OPTIONAL "
            "and disabled by default (ENABLE_DATABASE_COLLECTION=false) for security."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "gcp", "azure"]},
                "resource_type": {"type": "string", "description": "e.g., 'ec2', 'ecs', 'gce', 'vm', 'cloud_run'"},
                "resource_id": {"type": "string", "description": "Instance ID, name, etc."},
                "additional_params": {"type": "object", "description": "Cloud-specific params (region, zone, resource_group, cluster)"},
            },
            "required": ["cloud", "resource_type", "resource_id"],
        },
    },
    {
        "name": "restart_cloud_resource",
        "description": "Restart a cloud instance or service (safe operation). Supports: AWS EC2/ECS, GCP GCE/Cloud Run, Azure VM/App Service/Function.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "gcp", "azure"]},
                "resource_type": {"type": "string", "description": "e.g., 'ec2', 'ecs', 'gce', 'vm', 'cloud_run', 'app_service', 'function'"},
                "resource_id": {"type": "string"},
                "additional_params": {"type": "object"},
            },
            "required": ["cloud", "resource_type", "resource_id"],
        },
    },
    {
        "name": "scale_cloud_service",
        "description": "Scale a cloud service. Supports: AWS ECS, Azure App Service. (GCP Cloud Run autoscales)",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "gcp", "azure"]},
                "service_type": {"type": "string"},
                "service_id": {"type": "string"},
                "desired_count": {"type": "integer", "description": "Target instance count (minimum 1)"},
                "additional_params": {"type": "object"},
            },
            "required": ["cloud", "service_type", "service_id", "desired_count"],
        },
    },
]


# Stability-monitoring window for post-remediation verification: the documented
# 300-second (5-minute) window advertised in README and SECURITY_GUARANTEES.
FIX_VERIFICATION_MONITORING_SECONDS = 300


def _verification_expected_state(issue_type: str, context: dict) -> dict:
    """Map the incident type to the expected state that FixVerifier checks."""
    if issue_type == "k8s":
        expected_state = {"pod_status": "Running"}
        if context.get("pod"):
            expected_state["pod_name"] = context["pod"]
        if context.get("namespace"):
            expected_state["namespace"] = context["namespace"]
        return expected_state
    if issue_type in ("server", "linux", "windows", "rhel") and context.get("service"):
        return {"service_name": context["service"]}
    if issue_type == "cicd":
        expected_state = {
            "platform": get_cicd_platform(context.get("labels", {}) or {}, context),
            "expected_status": "success",
        }
        for key in (
            "repo",
            "run_id",
            "project_id",
            "pipeline_id",
            "job_name",
            "build_number",
            "plan_key",
            "project",
        ):
            if context.get(key) is not None:
                expected_state[key] = context[key]
        return expected_state
    if issue_type.startswith("cloud_"):
        expected_state = {}
        if context.get("resource_type"):
            expected_state["resource_type"] = context["resource_type"]
        if context.get("resource_id"):
            expected_state["resource_id"] = context["resource_id"]
        params = context.get("params") or {}
        if isinstance(params, dict):
            expected_state.update({k: v for k, v in params.items() if v is not None})
        return expected_state
    if issue_type == "argocd":
        expected_state = {"health": "Healthy", "sync": "Synced"}
        if context.get("app_name"):
            expected_state["app_name"] = context["app_name"]
        return expected_state
    return {}


def _remediation_summary(actions_taken: list) -> str:
    """Names of the remediation tools applied during the run."""
    return ", ".join(
        a.get("tool", "") for a in actions_taken if a.get("tool") in REMEDIATION_TOOLS
    )


class DevOpsAgent:
    def __init__(self):
        self.client = None
        self.executor = SafeExecutor()
        
        # K8s and existing tools
        self.k8s_tools = K8sTools()
        self.github_tools = GitHubTools()
        
        # New CI/CD and cloud tools
        self.cicd_tools = CICDTools()
        self.argocd_tools = ArgoCDTools()
        self.helm_tools = HelmTools()
        self.iac_tools = IaCTools()
        self.cloud_tools = CloudTools()
        
        self.notifier = SlackNotifier()
        self.fix_verifier = FixVerifier()
        
        # Existing collectors
        self.k8s_collector = K8sCollector()
        self.security_scanner = SecurityScanner()
        self.github_collector = GitHubCollector()
        self.server_collector = ServerCollector()
        
        # New CI/CD collectors
        self.gitlab_collector = GitLabCollector()
        self.jenkins_collector = JenkinsCollector()
        self.bamboo_collector = BambooCollector()
        self.azure_devops_collector = AzureDevOpsCollector()
        
        # ArgoCD collector
        self.argocd_collector = ArgoCDCollector()
        self.helm_collector = HelmCollector()
        
        # Cloud collectors
        self.aws_collector = AWSCollector()
        self.gcp_collector = GCPCollector()
        self.azure_collector = AzureCollector()
        
        self.max_steps = int(os.getenv("MAX_AGENT_STEPS", "10"))
        self.auto_apply = os.getenv("AUTO_APPLY", "false").lower() == "true"
        self._pending_approvals: dict[str, str] = {}
        self.incident_store = IncidentStore()
        self.org_docs = OrgDocs()
        self.claude_retries = int(os.getenv("CLAUDE_API_RETRIES", "3"))
        self.claude_retry_delay = float(os.getenv("CLAUDE_RETRY_DELAY_SEC", "2"))
        self.model = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

    def _anthropic_client(self) -> anthropic.Anthropic:
        key = os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not configured for this org. "
                "Set it in your MCP env or via configure_org_credentials."
            )
        if self.client is None:
            self.client = anthropic.Anthropic(api_key=key)
        return self.client

    def _org_id(self, context: dict) -> str:
        return context.get("org_id") or os.getenv("ORG_ID", "default")

    async def run(
        self,
        context: dict,
        incident_id: Optional[str] = None,
        resume: bool = True,
    ) -> dict:
        """Main agent loop: collect context → reason → act → return result."""
        org_id = self._org_id(context)
        incident_id = incident_id or context.get("incident_id") or (
            f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        )
        issue_type = context.get("type", "server")

        with org_credentials(org_id):
            refresh_agent_credentials(self)
            self.auto_apply = os.getenv("AUTO_APPLY", "false").lower() == "true"
            self.model = os.getenv("CLAUDE_MODEL", self.model)
            return await self._run_with_org_context(
                context, incident_id, resume, org_id, issue_type
            )

    async def _run_with_org_context(
        self,
        context: dict,
        incident_id: Optional[str],
        resume: bool,
        org_id: str,
        issue_type: str,
    ) -> dict:
        """Agent loop body — runs under org_credentials context."""
        log.info(
            "Agent starting",
            type=issue_type,
            source=context.get("source"),
            incident_id=incident_id,
            org_id=org_id,
        )

        actions_taken: list = []
        steps = 0
        messages: list = []
        full_context: dict = {}

        checkpoint = self.incident_store.load_checkpoint(org_id, incident_id) if resume else None
        if checkpoint:
            log.info("Resuming from checkpoint", incident_id=incident_id, steps=checkpoint.get("steps"))
            messages = checkpoint.get("messages", [])
            actions_taken = checkpoint.get("actions_taken", [])
            steps = checkpoint.get("steps", 0)
            full_context = checkpoint.get("full_context", {})
            issue_type = checkpoint.get("issue_type", issue_type)
        else:
            full_context = scrub_dict(await self._collect_context(context))
            org_doc_context = self.org_docs.get_context_for_agent(org_id, issue_type)
            self.incident_store.save_log(org_id, incident_id, "collected_context.json", full_context)

            user_content = (
                f"Incident `{incident_id}` for org `{org_id}`. Diagnose and fix this:\n\n"
                f"```json\n{json.dumps(full_context, indent=2)}\n```\n\n"
            )
            if org_doc_context:
                user_content += f"{org_doc_context}\n\n"
            user_content += (
                "Use tools to gather live evidence before concluding. "
                "Cite exact tool output in your Evidence section.\n\n"
                "RESOLUTION ORDER:\n"
                "1. Diagnose with collector/tool evidence\n"
                "2. Apply safe auto-fix if AUTO_APPLY allows\n"
                "3. If collectors cannot fix, tools are blocked, or data is incomplete — "
                "use suggest_fix with non-destructive commands and config snippets (FALLBACK)\n"
                "4. Always notify_slack with findings and suggested/applied fixes\n"
            )
            if full_context.get("collection_error"):
                user_content += (
                    "\nNOTE: Initial collection was partial or failed. "
                    "Use suggest_fix to provide manual non-destructive remediation steps.\n"
                )
            if context.get("raw_logs"):
                user_content += "\nPartial logs provided in context — use suggest_fix if remote access is unavailable.\n"
            messages = [{"role": "user", "content": scrub_text(user_content)}]

        system_prompt = get_system_prompt(issue_type)
        grounding_retries = 0

        while steps < self.max_steps:
            steps += 1
            log.info("Agent step", step=steps, incident_id=incident_id)

            response = self._call_claude(system_prompt, messages)
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                final_text = next(
                    (b.text for b in response.content if hasattr(b, "text")), ""
                )
                validation = validate_resolution(issue_type, actions_taken, final_text)
                if not validation["grounded"] and grounding_retries < 2 and steps < self.max_steps:
                    grounding_retries += 1
                    messages.append({
                        "role": "user",
                        "content": build_evidence_reminder(validation),
                    })
                    self._save_checkpoint(org_id, incident_id, messages, actions_taken, steps, full_context, issue_type)
                    continue

                fix_applied = has_successful_remediation(actions_taken)
                resolved = validation["grounded"] and (
                    fix_applied
                    or validation.get("has_suggestions")
                )
                suggested_fixes = extract_suggested_fixes(actions_taken)
                verification = None
                if fix_applied:
                    verification = await self.fix_verifier.verify_fix(
                        incident_type=issue_type,
                        fix_applied=_remediation_summary(actions_taken),
                        expected_state=_verification_expected_state(issue_type, context),
                        monitoring_duration=FIX_VERIFICATION_MONITORING_SECONDS,
                    )
                    self.incident_store.save_log(
                        org_id, incident_id, "verification.json", verification
                    )
                    await self.notifier.send_message(
                        f"*Fix verification — incident `{incident_id}`:* "
                        f"`{verification.get('status', 'unknown')}`\n"
                        f"```json\n{json.dumps(verification, indent=2)}\n```",
                        severity="info" if verification.get("verified") else "warning",
                    )
                result = {
                    "resolved": resolved,
                    "diagnosis": final_text,
                    "actions": actions_taken,
                    "steps": steps,
                    "reasoning": final_text,
                    "grounding": validation,
                    "suggested_fixes": suggested_fixes,
                    "fix_applied": fix_applied,
                    "suggestions_only": bool(suggested_fixes) and not fix_applied,
                    "verification": verification,
                    "incident_id": incident_id,
                    "org_id": org_id,
                }
                self.incident_store.save_conversation(org_id, incident_id, messages)
                self.incident_store.delete_checkpoint(org_id, incident_id)
                return result

            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue

                    log.info("Tool call", tool=block.name, input=block.input, incident_id=incident_id)
                    result = await self._execute_tool(block.name, block.input, context)
                    scrubbed_result = scrub_value(result)
                    actions_taken.append({
                        "tool": block.name,
                        "input": scrub_dict(block.input) if isinstance(block.input, dict) else block.input,
                        "result": scrubbed_result,
                    })
                    self.incident_store.save_log(
                        org_id, incident_id,
                        f"step_{steps:03d}_tool_{block.name}.json",
                        {"input": block.input, "result": scrubbed_result},
                    )
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(scrubbed_result),
                    })

                messages.append({"role": "user", "content": tool_results})
                self._save_checkpoint(org_id, incident_id, messages, actions_taken, steps, full_context, issue_type)
                continue

            break

        result = {
            "resolved": False,
            "diagnosis": "Max steps reached without resolution",
            "actions": actions_taken,
            "steps": steps,
            "incident_id": incident_id,
            "org_id": org_id,
        }
        self.incident_store.save_conversation(org_id, incident_id, messages)
        self._save_checkpoint(org_id, incident_id, messages, actions_taken, steps, full_context, issue_type)
        return result

    def _save_checkpoint(self, org_id, incident_id, messages, actions_taken, steps, full_context, issue_type):
        self.incident_store.save_checkpoint(
            org_id, incident_id, messages, actions_taken, steps, full_context, issue_type
        )

    def _call_claude(self, system_prompt: str, messages: list):
        """Call Claude with exponential backoff retry on transient failures."""
        last_error = None
        for attempt in range(1, self.claude_retries + 1):
            try:
                return self._anthropic_client().messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=system_prompt,
                    tools=AGENT_TOOLS,
                    messages=messages,
                )
            except (
                anthropic.APIConnectionError,
                anthropic.RateLimitError,
                anthropic.InternalServerError,
                anthropic.APITimeoutError,
            ) as e:
                last_error = e
                if attempt < self.claude_retries:
                    delay = self.claude_retry_delay * (2 ** (attempt - 1))
                    log.warning("Claude API retry", attempt=attempt, delay=delay, error=str(e))
                    time.sleep(delay)
                else:
                    raise
        raise last_error  # type: ignore[misc]

    async def execute_approved_action(self, incident_id: str, command: str):
        """Execute a command that was approved via Slack."""
        log.info("Executing approved action", incident_id=incident_id, command=command)
        result = await self.executor.run(command)
        if result.get("emergency_stop"):
            await self.notifier.send_message(
                f"🛑 Emergency stop active — approved action blocked for `{incident_id}`:\n```{command}```"
            )
            return
        await self.notifier.send_message(
            f"✅ Approved action executed for `{incident_id}`:\n```{command}```\nResult: {result.get('stdout', '')}"
        )

    async def _collect_context(self, context: dict) -> dict:
        """Enrich the incident context with collected data."""
        enriched = dict(context)
        issue_type = context.get("type")

        # DevSecOps: run SecurityScanner when enabled (issue #6)
        try:
            scan = self.security_scanner.scan_incident_context(enriched)
            if scan.get("scanned"):
                enriched["security_scan"] = scan
        except Exception as exc:  # never block incident flow on scanner errors
            log.warning("security_scan_failed", error=str(exc))

        try:
            if issue_type == "k8s" and context.get("namespace"):
                enriched["k8s_data"] = await self.k8s_collector.collect(
                    context.get("namespace"), context.get("pod")
                )
            elif issue_type == "cicd":
                # Determine CI/CD platform
                platform = get_cicd_platform(context.get("labels", {}), context)
                enriched["cicd_platform"] = platform
                
                if platform == "github" and context.get("repo") and context.get("run_id"):
                    enriched["ci_logs"] = await self.github_collector.collect(
                        context["repo"], context["run_id"]
                    )
                elif platform == "gitlab" and context.get("project_id") and context.get("pipeline_id"):
                    enriched["ci_logs"] = await self.gitlab_collector.collect(
                        context["project_id"], context["pipeline_id"]
                    )
                elif platform == "jenkins" and context.get("job_name"):
                    enriched["ci_logs"] = await self.jenkins_collector.collect(
                        context["job_name"], context.get("build_number")
                    )
                elif platform == "bamboo" and context.get("plan_key"):
                    enriched["ci_logs"] = await self.bamboo_collector.collect(
                        context["plan_key"], context.get("build_number")
                    )
                elif platform == "azure_devops" and context.get("project") and context.get("pipeline_id"):
                    enriched["ci_logs"] = await self.azure_devops_collector.collect(
                        context["project"], context["pipeline_id"], context.get("run_id")
                    )
            elif issue_type == "argocd" and context.get("app_name"):
                enriched["argocd_data"] = await self.argocd_collector.collect(context["app_name"])
            elif issue_type == "helm" and context.get("release_name"):
                enriched["helm_data"] = await self.helm_collector.collect(
                    context["release_name"],
                    context.get("namespace", "default"),
                )
            elif issue_type == "terraform":
                workspace = context.get("workspace_path") or context.get("terraform_workspace")
                if workspace:
                    enriched["terraform_validate"] = await self.iac_tools.terraform_validate(workspace)
                    enriched["terraform_plan"] = await self.iac_tools.terraform_plan(workspace)
                else:
                    enriched["terraform_note"] = (
                        "No workspace_path in context. Use terraform_plan/validate tools or set "
                        "TERRAFORM_WORKSPACE_DIR."
                    )
            elif issue_type == "cloud_aws" and context.get("resource_type") and context.get("resource_id"):
                rt = context["resource_type"]
                blocked = check_database_access(rt, cloud="aws")
                if blocked:
                    enriched["cloud_data"] = blocked
                else:
                    enriched["cloud_data"] = await self.aws_collector.collect(
                        rt, context["resource_id"], **context.get("params", {})
                    )
            elif issue_type == "cloud_gcp" and context.get("resource_type") and context.get("resource_id"):
                rt = context["resource_type"]
                blocked = check_database_access(rt, cloud="gcp")
                if blocked:
                    enriched["cloud_data"] = blocked
                else:
                    enriched["cloud_data"] = await self.gcp_collector.collect(
                        rt, context["resource_id"], **context.get("params", {})
                    )
            elif issue_type == "cloud_azure" and context.get("resource_type") and context.get("resource_id"):
                rt = context["resource_type"]
                blocked = check_database_access(rt, cloud="azure")
                if blocked:
                    enriched["cloud_data"] = blocked
                else:
                    enriched["cloud_data"] = await self.azure_collector.collect(
                        rt, context["resource_id"], **context.get("params", {})
                    )
            elif issue_type == "server":
                target_host = context.get("host") or context.get("node")
                enriched["target_host"] = target_host or "localhost"
                enriched["server_data"] = await self.server_collector.collect(host=target_host)
        except Exception as e:
            log.warning("Context collection partial failure", error=str(e))
            enriched["collection_error"] = str(e)

        return enriched

    async def execute_tool(
        self, name: str, inputs: dict, context: Optional[dict] = None
    ) -> dict:
        """Public entry point for tool execution (used by MCP and external agents)."""
        ctx = context or {}
        org_id = ctx.get("org_id") or os.getenv("ORG_ID", "default")
        with org_credentials(org_id):
            refresh_agent_credentials(self)
            self.auto_apply = os.getenv("AUTO_APPLY", "false").lower() == "true"
            return await self._execute_tool(name, inputs, ctx)

    async def _execute_tool(self, name: str, inputs: dict, context: dict) -> dict:
        """Route tool calls to the appropriate handler."""
        blocked = check_emergency_stop_for_tool(name)
        if blocked:
            return blocked

        try:
            # ─── Existing K8s Tools ───────────────────────────────────────────
            if name == "get_k8s_context":
                return await self.k8s_collector.collect(
                    inputs.get("namespace", "default"),
                    inputs.get("pod_name"),
                    inputs.get("include_previous", True),
                )
            elif name == "apply_k8s_manifest":
                return await self.k8s_tools.apply_manifest(
                    inputs["manifest_yaml"],
                    dry_run=inputs.get("dry_run", True),
                    namespace=inputs.get("namespace"),
                    auto_apply=self.auto_apply,
                    notifier=self.notifier,
                )
            elif name == "run_kubectl":
                return await self.k8s_tools.run_kubectl(inputs["command"], auto_apply=self.auto_apply)
            elif name == "rollback_deployment":
                return await self.k8s_tools.rollback(
                    inputs["deployment"], inputs["namespace"],
                    revision=inputs.get("revision"),
                    auto_apply=self.auto_apply,
                    notifier=self.notifier,
                )
            
            # ─── Existing GitHub/Server Tools ─────────────────────────────────
            elif name == "get_github_logs":
                return await self.github_collector.collect(inputs["repo"], inputs["run_id"])
            elif name == "create_github_pr":
                return await self.github_tools.create_fix_pr(
                    inputs["repo"], inputs["file_path"],
                    inputs["new_content"], inputs["pr_title"], inputs["pr_body"],
                )
            elif name == "run_shell_command":
                host = inputs.get("host") or context.get("host") or context.get("node")
                return await self.executor.run_safe(inputs["command"], host=host)
            
            # ─── Multi-platform CI/CD Tools ────────────────────────────────────
            elif name == "get_cicd_logs":
                platform = inputs["platform"]
                project_id = inputs["project_id"]
                pipeline_id = inputs.get("pipeline_id")
                params = inputs.get("additional_params", {})
                
                if platform == "github":
                    return await self.github_collector.collect(project_id, int(pipeline_id))
                elif platform == "gitlab":
                    return await self.gitlab_collector.collect(project_id, int(pipeline_id))
                elif platform == "jenkins":
                    return await self.jenkins_collector.collect(project_id, int(pipeline_id) if pipeline_id else None)
                elif platform == "bamboo":
                    return await self.bamboo_collector.collect(project_id, int(pipeline_id) if pipeline_id else None)
                elif platform == "azure_devops":
                    return await self.azure_devops_collector.collect(
                        params.get("project", project_id),
                        int(params.get("pipeline_id", pipeline_id)),
                        int(params.get("run_id", pipeline_id))
                    )
                else:
                    return {"error": f"Unsupported CI/CD platform: {platform}"}
            
            elif name == "retry_cicd_pipeline":
                platform = inputs["platform"]
                return await self.cicd_tools.retry_pipeline(
                    platform, inputs["project_id"], inputs.get("pipeline_id"),
                    **inputs.get("additional_params", {})
                )
            
            elif name == "create_cicd_pr":
                platform = inputs["platform"]
                if platform == "github":
                    # Use existing GitHub tool
                    return await self.github_tools.create_fix_pr(
                        inputs["repo"], inputs["file_path"],
                        inputs["new_content"], inputs["pr_title"], inputs["pr_body"]
                    )
                else:
                    return await self.cicd_tools.create_fix_pr(
                        platform, inputs["repo"], inputs["file_path"],
                        inputs["new_content"], inputs["pr_title"], inputs["pr_body"],
                        **inputs.get("additional_params", {})
                    )
            
            # ─── ArgoCD Tools ──────────────────────────────────────────────────
            elif name == "get_argocd_status":
                return await self.argocd_tools.get_application_status(inputs["app_name"])
            
            elif name == "sync_argocd_app":
                return await self.argocd_tools.sync_application(
                    inputs["app_name"],
                    prune=inputs.get("prune", False),
                    dry_run=inputs.get("dry_run", True),
                    auto_apply=self.auto_apply,
                    notifier=self.notifier
                )
            
            elif name == "rollback_argocd_app":
                return await self.argocd_tools.rollback_application(
                    inputs["app_name"],
                    revision=inputs.get("revision"),
                    auto_apply=self.auto_apply,
                    notifier=self.notifier
                )
            
            elif name == "get_argocd_history":
                return await self.argocd_tools.get_application_history(
                    inputs["app_name"],
                    limit=inputs.get("limit", 10)
                )

            # ─── Helm Tools ────────────────────────────────────────────────────
            elif name == "get_helm_release":
                return await self.helm_tools.get_release(
                    inputs["release_name"],
                    inputs.get("namespace", "default"),
                )
            elif name == "helm_rollback":
                return await self.helm_tools.rollback(
                    inputs["release_name"],
                    inputs["namespace"],
                    revision=inputs.get("revision"),
                    auto_apply=self.auto_apply,
                    notifier=self.notifier,
                )
            elif name == "helm_upgrade":
                return await self.helm_tools.upgrade(
                    inputs["release_name"],
                    inputs["chart"],
                    inputs["namespace"],
                    values_yaml=inputs.get("values_yaml"),
                    dry_run=inputs.get("dry_run", True),
                    auto_apply=self.auto_apply,
                    notifier=self.notifier,
                )

            # ─── Terraform / IaC Tools ─────────────────────────────────────────
            elif name == "terraform_validate":
                return await self.iac_tools.terraform_validate(inputs.get("workspace_path"))
            elif name == "terraform_plan":
                return await self.iac_tools.terraform_plan(
                    inputs.get("workspace_path"),
                    extra_args=inputs.get("extra_args", "-input=false"),
                )
            
            # ─── Cloud Provider Tools ──────────────────────────────────────────
            elif name == "get_cloud_resource":
                cloud = inputs["cloud"]
                resource_type = inputs["resource_type"]
                resource_id = inputs["resource_id"]
                params = inputs.get("additional_params", {})

                blocked = check_database_access(resource_type, cloud=cloud)
                if blocked:
                    return blocked

                if cloud == "aws":
                    return await self.aws_collector.collect(resource_type, resource_id, **params)
                elif cloud == "gcp":
                    return await self.gcp_collector.collect(resource_type, resource_id, **params)
                elif cloud == "azure":
                    return await self.azure_collector.collect(resource_type, resource_id, **params)
                else:
                    return {"error": f"Unsupported cloud: {cloud}"}
            
            elif name == "restart_cloud_resource":
                cloud = inputs["cloud"]
                resource_type = inputs["resource_type"]
                resource_id = inputs["resource_id"]
                params = inputs.get("additional_params", {})
                
                if resource_type in ["instance", "ec2", "gce", "vm"]:
                    return await self.cloud_tools.restart_instance(cloud, resource_id, **params)
                else:
                    return await self.cloud_tools.restart_service(cloud, resource_type, resource_id, **params)
            
            elif name == "scale_cloud_service":
                return await self.cloud_tools.scale_service(
                    inputs["cloud"],
                    inputs["service_type"],
                    inputs["service_id"],
                    inputs["desired_count"],
                    **inputs.get("additional_params", {})
                )
            
            # ─── Notifications & suggestions ───────────────────────────────────
            elif name == "suggest_fix":
                suggestion = validate_suggestion(
                    inputs["title"],
                    inputs["description"],
                    inputs.get("commands", []),
                    inputs.get("config_snippets"),
                )
                if suggestion.get("recorded"):
                    verification = inputs.get("verification_steps", [])
                    suggestion["verification_steps"] = verification
                    await self.notifier.send_fix_suggestion(
                        inputs["title"],
                        inputs["description"],
                        suggestion["commands"],
                        config_snippets=suggestion.get("config_snippets"),
                        verification_steps=verification,
                    )
                return suggestion

            elif name == "notify_slack":
                await self.notifier.send_message(
                    inputs["message"],
                    severity=inputs.get("severity", "info"),
                    resolved=inputs.get("resolved", False),
                    requires_approval=inputs.get("requires_approval", False),
                    approval_command=inputs.get("approval_command"),
                )
                return {"sent": True}

            else:
                return {"error": f"Unknown tool: {name}"}

        except Exception as e:
            log.error("Tool execution error", tool=name, error=str(e))
            return {"error": str(e)}
