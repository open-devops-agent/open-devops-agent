"""
Per-organization credentials — each org brings their own API keys, Slack, and integrations.

Stored at {org_id}/config/credentials.json in org-scoped storage.
Platform operators should only configure shared storage/queue settings in server env.
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

import structlog

from services.credential_crypto import unwrap_from_storage, wrap_for_storage
from storage.base import StorageProvider
from storage.factory import get_storage

log = structlog.get_logger()

# Keys orgs own — never shared across tenants on a multi-org server.
ORG_CREDENTIAL_KEYS = [
    "ANTHROPIC_API_KEY",
    # AI provider selection (#181): each org can use its own provider and model.
    "LLM_PROVIDER",
    "LLM_MODEL",
    "LLM_API_KEY",
    "LLM_BASE_URL",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_VERSION",
    "SLACK_WEBHOOK_URL",
    "SLACK_APPROVAL_CHANNEL",
    "SLACK_APPROVER_IDS",
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
    "BITBUCKET_USERNAME",
    "BITBUCKET_APP_PASSWORD",
    "BITBUCKET_TOKEN",
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

MAX_VALUE_LENGTH = 8192

# Shape checks for high-risk keys (#62). They catch pasted-in-the-wrong-field and
# truncated values at save time instead of at 3am during an incident. Set
# CREDENTIAL_VALIDATION=warn to log instead of reject, or off to skip them.
_PREFIX_RULES = {
    "ANTHROPIC_API_KEY": (("sk-ant-",), "must start with sk-ant-"),
    "OPENAI_API_KEY": (("sk-",), "must start with sk-"),
    "SLACK_BOT_TOKEN": (("xoxb-",), "must be a bot token (xoxb-)"),
    "SLACK_WEBHOOK_URL": (("https://hooks.slack.com/",), "must be an https://hooks.slack.com/ URL"),
}
_GITHUB_TOKEN = re.compile(r"^(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|[0-9a-f]{40})$")
_AWS_ACCESS_KEY_ID = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
_URL_KEYS = {k for k in ORG_CREDENTIAL_KEYS if k.endswith(("_URL", "_ENDPOINT"))}
_BOOL_KEYS = {"AUTO_APPLY"}
_PORT_KEYS = {"EMAIL_SMTP_PORT"}
_LLM_PROVIDERS = ("anthropic", "openai", "gemini", "azure_openai", "ollama", "openai_compatible")


def is_sensitive(key: str) -> bool:
    return key.endswith(_SENSITIVE_SUFFIXES) or key.endswith("_URL") and "WEBHOOK" in key


class CredentialValidationError(ValueError):
    """Raised when credentials fail validation. ``errors`` maps key -> reason (never values)."""

    def __init__(self, errors: Dict[str, str]):
        super().__init__("Invalid credentials: " + ", ".join(f"{k} ({v})" for k, v in errors.items()))
        self.errors = errors


def validation_mode() -> str:
    mode = os.getenv("CREDENTIAL_VALIDATION", "strict").lower().strip()
    return mode if mode in ("strict", "warn", "off") else "strict"


def validate_credentials(credentials: Dict[str, Any]) -> Dict[str, str]:
    """Return {key: reason} for values that are clearly wrong. Values are never echoed."""
    errors: Dict[str, str] = {}
    for key, raw in credentials.items():
        value = str(raw)
        if len(value) > MAX_VALUE_LENGTH:
            errors[key] = f"longer than {MAX_VALUE_LENGTH} characters"
            continue
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            errors[key] = "contains control characters or line breaks"
            continue
        if is_sensitive(key) and (len(value) < 8 or any(c.isspace() for c in value)):
            errors[key] = "secret looks truncated or contains whitespace"
            continue
        if key in _PREFIX_RULES:
            prefixes, reason = _PREFIX_RULES[key]
            if not value.startswith(prefixes):
                errors[key] = reason
                continue
        if key in _URL_KEYS:
            parsed = urlparse(value)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                errors[key] = "must be an http(s) URL"
        elif key == "GITHUB_TOKEN" and not _GITHUB_TOKEN.match(value):
            errors[key] = "is not a GitHub token (ghp_, gho_, ghs_, ghu_, ghr_, github_pat_ or 40-hex classic)"
        elif key == "AWS_ACCESS_KEY_ID" and not _AWS_ACCESS_KEY_ID.match(value):
            errors[key] = "is not an AWS access key ID (AKIA/ASIA + 16 characters)"
        elif key in _BOOL_KEYS and value.lower() not in ("true", "false"):
            errors[key] = "must be true or false"
        elif key in _PORT_KEYS and not (value.isdigit() and 0 < int(value) < 65536):
            errors[key] = "must be a port number"
        elif key == "LLM_PROVIDER" and value.lower() not in _LLM_PROVIDERS:
            errors[key] = "must be one of " + ", ".join(_LLM_PROVIDERS)
    return errors


def _fingerprint(value: Any) -> str:
    """Stable digest to detect changes without storing or logging the value."""
    return hashlib.sha256(str(value).encode()).hexdigest()


def _max_age_days() -> int:
    try:
        return int(os.getenv("CREDENTIAL_MAX_AGE_DAYS", "90"))
    except ValueError:
        return 90


class OrgConfig:
    def __init__(self, storage: Optional[StorageProvider] = None):
        self.storage = storage or get_storage()

    def _config_key(self, org_id: str) -> str:
        return self.storage.org_prefix(org_id, "config", "credentials.json")

    def _meta_key(self, org_id: str) -> str:
        return self.storage.org_prefix(org_id, "config", "credentials_meta.json")

    def _audit_key(self, org_id: str, now: datetime) -> str:
        return self.storage.org_prefix(
            org_id, "credential_audit", str(now.year), f"{now.month:02d}",
            f"{now.strftime('%Y%m%dT%H%M%S%f')}-{uuid4().hex[:8]}.json",
        )

    def _filter(self, credentials: dict) -> Dict[str, Any]:
        return {
            k: v for k, v in credentials.items()
            if k in ORG_CREDENTIAL_KEYS and v is not None and str(v).strip()
        }

    def _validate(self, org_id: str, filtered: Dict[str, Any]) -> None:
        mode = validation_mode()
        if mode == "off":
            return
        errors = validate_credentials(filtered)
        if not errors:
            return
        if mode == "warn":
            log.warning("org_credentials_invalid", org_id=org_id, errors=errors)
            return
        raise CredentialValidationError(errors)

    def _write(self, org_id: str, previous: dict, new: dict, actor: str, action: str) -> dict:
        """Persist ``new``, update per-key metadata and record an audit event."""
        now = datetime.now(timezone.utc)
        added = sorted(k for k in new if k not in previous)
        removed = sorted(k for k in previous if k not in new)
        changed = sorted(
            k for k in new if k in previous and _fingerprint(new[k]) != _fingerprint(previous[k])
        )
        if new:
            payload = wrap_for_storage(new)
            self.storage.put_json(self._config_key(org_id), payload)
            encrypted = bool(payload.get("_encrypted"))
        else:
            self._secure_delete(self._config_key(org_id))
            encrypted = False

        meta = self.metadata(org_id)
        for k in removed:
            meta.pop(k, None)
        for k in added + changed:
            meta[k] = {"updated_at": now.isoformat(), "updated_by": actor}
        if meta:
            self.storage.put_json(self._meta_key(org_id), meta)
        else:
            self.storage.delete(self._meta_key(org_id))

        event = {
            "action": f"credentials_{action}",
            "org_id": org_id,
            "actor": actor,
            "timestamp": now.isoformat(),
            "added": added,
            "changed": changed,
            "removed": removed,
        }
        if added or changed or removed:
            self.storage.put_json(self._audit_key(org_id, now), event)
        log.info("org_credentials_changed", **event)
        return {
            "org_id": org_id,
            "configured_keys": sorted(new),
            "added": added,
            "changed": changed,
            "removed": removed,
            "encrypted_at_rest": encrypted,
        }

    def _secure_delete(self, key: str) -> bool:
        """Overwrite the stored blob before deleting it, so no readable copy remains
        where the backend keeps the last version (versioned buckets keep older ones:
        see docs/CREDENTIAL_ROTATION.md)."""
        if self.storage.get_json(key) is None:
            return False
        self.storage.put_json(key, {"deleted": True})
        return bool(self.storage.delete(key))

    def save(self, org_id: str, credentials: dict, actor: str = "system") -> dict:
        """Replace the org's credentials. Only known ORG_CREDENTIAL_KEYS are stored."""
        filtered = self._filter(credentials)
        self._validate(org_id, filtered)
        result = self._write(org_id, self.get(org_id), filtered, actor, "replaced")
        result["ignored_keys"] = sorted(k for k in credentials if k not in ORG_CREDENTIAL_KEYS)
        return result

    def update(self, org_id: str, credentials: dict, actor: str = "system") -> dict:
        """Merge: set the given keys, remove keys whose value is null or empty, keep the rest."""
        previous = self.get(org_id)
        to_set = self._filter(credentials)
        self._validate(org_id, to_set)
        to_remove = {
            k for k, v in credentials.items()
            if k in ORG_CREDENTIAL_KEYS and (v is None or not str(v).strip())
        }
        merged = {k: v for k, v in previous.items() if k not in to_remove}
        merged.update(to_set)
        result = self._write(org_id, previous, merged, actor, "updated")
        result["ignored_keys"] = sorted(k for k in credentials if k not in ORG_CREDENTIAL_KEYS)
        return result

    def delete(self, org_id: str, keys: Optional[List[str]] = None, actor: str = "system") -> dict:
        """Revoke all of the org's stored credentials, or only ``keys``."""
        previous = self.get(org_id)
        if keys:
            remaining = {k: v for k, v in previous.items() if k not in set(keys)}
        else:
            remaining = {}
        return self._write(org_id, previous, remaining, actor, "deleted")

    def get(self, org_id: str) -> dict:
        data = self.storage.get_json(self._config_key(org_id))
        return unwrap_from_storage(data)

    def metadata(self, org_id: str) -> Dict[str, dict]:
        data = self.storage.get_json(self._meta_key(org_id))
        return data if isinstance(data, dict) else {}

    def audit_events(self, org_id: str, limit: int = 50) -> List[dict]:
        keys = sorted(self.storage.list_keys(self.storage.org_prefix(org_id, "credential_audit")))
        events = []
        for key in reversed(keys[-limit:] if limit else keys):
            data = self.storage.get_json(key)
            if data:
                events.append(data)
        return events

    def status(self, org_id: str) -> dict:
        """Which keys are set, when each was last changed and by whom (never values)."""
        stored = self.get(org_id)
        from_env = _env_credentials_for_org(org_id)
        merged_keys = set(stored) | set(from_env)
        meta = self.metadata(org_id)
        now = datetime.now(timezone.utc)
        max_age = _max_age_days()
        details: Dict[str, dict] = {}
        stale = []
        for k in sorted(merged_keys):
            info: Dict[str, Any] = {"source": "org" if k in stored else "env", "sensitive": is_sensitive(k)}
            if k in stored and k in meta:
                info.update(meta[k])
                try:
                    age = (now - datetime.fromisoformat(meta[k]["updated_at"])).days
                    info["age_days"] = age
                    if max_age > 0 and age > max_age and info["sensitive"]:
                        stale.append(k)
                except (KeyError, ValueError, TypeError):
                    pass
            details[k] = info
        return {
            "org_id": org_id,
            "configured": {k: True for k in sorted(merged_keys)},
            "details": details,
            "stale": stale,
            "max_age_days": max_age,
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
