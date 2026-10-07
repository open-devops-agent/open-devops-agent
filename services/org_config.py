"""
Per-organization credentials — each org brings their own API keys, Slack, and integrations.

Stored at {org_id}/config/credentials.json in org-scoped storage.
Platform operators should only configure shared storage/queue settings in server env.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import structlog

from storage.base import StorageProvider
from storage.factory import get_storage

log = structlog.get_logger()

# Keys orgs own — never shared across tenants on a multi-org server.
ORG_CREDENTIAL_KEYS = [
    "ANTHROPIC_API_KEY",
    "SLACK_WEBHOOK_URL",
    "SLACK_APPROVAL_CHANNEL",
    "SLACK_BOT_TOKEN",
    "SLACK_SIGNING_SECRET",
    "GITHUB_TOKEN",
    "GITHUB_ORG",
    "GITLAB_TOKEN",
    "GITLAB_URL",
    "JENKINS_URL",
    "JENKINS_USERNAME",
    "JENKINS_API_TOKEN",
    "JENKINS_SCM_PROVIDER",
    "JENKINS_SCM_REPO",
    "BAMBOO_URL",
    "BAMBOO_USERNAME",
    "BAMBOO_PASSWORD",
    "BAMBOO_VERSION_VARIABLE",
    "BAMBOO_SCM_PROVIDER",
    "BAMBOO_SPECS_REPO",
    "AZURE_DEVOPS_ORG",
    "AZURE_DEVOPS_PAT",
    "AZURE_DEVOPS_PROJECT",
    "ARGOCD_SERVER_URL",
    "ARGOCD_AUTH_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_REGION",
    "GCP_PROJECT_ID",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "KUBECONFIG",
    "ALLOWED_NAMESPACES",
    "EMAIL_SMTP_HOST",
    "EMAIL_SMTP_PORT",
    "EMAIL_SMTP_USER",
    "EMAIL_SMTP_PASSWORD",
    "EMAIL_FROM",
    "EMAIL_TO",
    "JIRA_URL",
    "JIRA_EMAIL",
    "JIRA_API_TOKEN",
    "JIRA_PROJECT_KEY",
    "ZOHO_ACCESS_TOKEN",
    "ZOHO_DESK_ORG_ID",
    "PAGERDUTY_TOKEN",
    "PAGERDUTY_SERVICE_ID",
    "PAGERDUTY_FROM_EMAIL",
    "PAGERDUTY_SCHEDULE_ID",
    "PROMETHEUS_URL",
    "GRAFANA_URL",
    "GRAFANA_TOKEN",
    "DATADOG_API_KEY",
    "DATADOG_APP_KEY",
    "NEW_RELIC_API_KEY",
    "NEW_RELIC_ACCOUNT_ID",
    "STATUSPAGE_PAGE_ID",
    "STATUSPAGE_API_KEY",
    "AUTO_APPLY",
    "CLAUDE_MODEL",
]

_SENSITIVE_SUFFIXES = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PAT")


class OrgConfig:
    def __init__(self, storage: Optional[StorageProvider] = None):
        self.storage = storage or get_storage()

    def _config_key(self, org_id: str) -> str:
        return self.storage.org_prefix(org_id, "config", "credentials.json")

    def save(self, org_id: str, credentials: dict) -> dict:
        """Save org-owned credentials. Only known ORG_CREDENTIAL_KEYS are stored."""
        filtered = {
            k: v for k, v in credentials.items()
            if k in ORG_CREDENTIAL_KEYS and v is not None and str(v).strip()
        }
        key = self._config_key(org_id)
        self.storage.put_json(key, filtered)
        log.info("Org credentials saved", org_id=org_id, keys=list(filtered.keys()))
        return {"org_id": org_id, "configured_keys": list(filtered.keys())}

    def get(self, org_id: str) -> dict:
        data = self.storage.get_json(self._config_key(org_id))
        return data or {}

    def delete(self, org_id: str) -> bool:
        return self.storage.delete(self._config_key(org_id))

    def status(self, org_id: str) -> dict:
        """Return which credential keys are set (never returns secret values)."""
        stored = self.get(org_id)
        from_env = _env_credentials_for_org(org_id)
        merged_keys = set(stored) | set(from_env)
        return {
            "org_id": org_id,
            "configured": {k: True for k in sorted(merged_keys)},
            "missing_recommended": [
                k for k in ("ANTHROPIC_API_KEY", "SLACK_WEBHOOK_URL", "GITHUB_TOKEN")
                if k not in merged_keys
            ],
        }


def _env_credentials_for_org(org_id: str) -> dict:
    """Credentials from process env when this process is dedicated to one org (MCP stdio)."""
    if os.getenv("ORG_ID", "default") != org_id:
        return {}
    return {
        k: os.getenv(k)
        for k in ORG_CREDENTIAL_KEYS
        if os.getenv(k)
    }


def resolve_org_credentials(org_id: str, org_config: Optional[OrgConfig] = None) -> dict:
    """
    Merge org credentials: stored config overrides env for the same org.
    Used when a single MCP/webhook process serves one org via env (BYOK in mcp.json).
    """
    org_config = org_config or OrgConfig()
    stored = org_config.get(org_id)
    from_env = _env_credentials_for_org(org_id)
    merged = dict(from_env)
    merged.update(stored)
    return merged
