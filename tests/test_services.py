"""Tests for PII scrubber, storage, grounding, and incident queue."""
import asyncio
import importlib
import os
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from services.pii_scrubber import scrub_text, scrub_dict
from storage.memory_storage import MemoryStorage
from services.incident_queue import IncidentQueue
from services.incident_store import IncidentStore
from services.org_docs import OrgDocs
from services.org_config import OrgConfig
from services.org_context import org_credentials
from agent.grounding import validate_resolution, has_tool_evidence, append_grounding_rules, has_successful_remediation


class TestPIIScrubber:
    def test_scrubs_email(self):
        text = "Contact user@example.com for help"
        assert "[REDACTED_EMAIL]" in scrub_text(text)
        assert "user@example.com" not in scrub_text(text)

    def test_scrubs_github_token(self):
        text = "Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        result = scrub_text(text)
        assert "ghp_" not in result
        assert "[REDACTED_TOKEN]" in result

    def test_scrubs_nested_dict(self):
        data = {"logs": "password=secret123", "user": "admin@test.com"}
        result = scrub_dict(data)
        assert "secret123" not in str(result)
        assert "[REDACTED_EMAIL]" in str(result)


class TestMemoryStorage:
    def test_put_get_json(self):
        storage = MemoryStorage()
        storage.put_json("org1/audit/test.json", {"id": "INC-1"})
        assert storage.get_json("org1/audit/test.json")["id"] == "INC-1"

    def test_org_paths(self):
        storage = MemoryStorage()
        key = storage.audit_key("acme-corp", "INC-123")
        assert key.startswith("acme-corp/audit/")

    def test_list_and_delete(self):
        storage = MemoryStorage()
        storage.put_json("org1/docs/runbook.md", {"x": 1})
        keys = storage.list_keys("org1/docs")
        assert len(keys) == 1
        assert storage.delete(keys[0])


class TestIncidentQueue:
    @pytest.mark.asyncio
    async def test_enqueue_and_claim(self):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        incident_id = queue.enqueue("test-org", {"type": "k8s", "namespace": "default"})
        entry = queue.claim_next("test-org")
        assert entry is not None
        assert entry["incident_id"] == incident_id
        assert entry["context"]["type"] == "k8s"

    def test_recover_stale_processing(self):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        incident_id = queue.enqueue("test-org", {"type": "server"})
        queue.claim_next("test-org")
        recovered = queue.recover_stale_processing("test-org")
        assert recovered == 1
        entry = queue.claim_next("test-org")
        assert entry["incident_id"] == incident_id


class TestIncidentStore:
    def test_audit_and_checkpoint(self):
        storage = MemoryStorage()
        store = IncidentStore(storage)
        store.save_audit("org1", "INC-1", {"diagnosis": "OOM", "resolved": True})
        audits = store.list_audit("org1")
        assert len(audits) == 1

        store.save_checkpoint("org1", "INC-1", [{"role": "user", "content": "hi"}], [], 1, {}, "k8s")
        cp = store.load_checkpoint("org1", "INC-1")
        assert cp["steps"] == 1
        store.delete_checkpoint("org1", "INC-1")
        assert store.load_checkpoint("org1", "INC-1") is None

    def test_apply_retention_deletes_aged_keys(self, monkeypatch):
        """Characterization: aged audit/log/checkpoint/queue keys are deleted, fresh kept."""
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
        storage = MemoryStorage()
        store = IncidentStore(storage)
        org = "org1"
        now = datetime.now(timezone.utc)
        fresh_ym = f"{now.year}/{now.month:02d}"
        aged_keys = [
            f"{org}/audit/2020/01/INC-old.json",
            f"{org}/logs/2020/01/INC-old/conversation.json",
            f"{org}/checkpoints/2020/01/INC-old.json",
            f"{org}/queue/2020/01/INC-old.json",
        ]
        fresh_keys = [
            f"{org}/audit/{fresh_ym}/INC-new.json",
            f"{org}/logs/{fresh_ym}/INC-new/conversation.json",
            storage.checkpoint_key(org, "INC-new"),
            storage.queue_key(org, "pending", "INC-new"),
        ]
        for key in aged_keys + fresh_keys:
            storage.put_json(key, {"id": "x"})

        deleted = store.apply_retention(org)

        assert deleted == len(aged_keys)
        for key in aged_keys:
            assert not storage.exists(key)
        for key in fresh_keys:
            assert storage.exists(key)

    def test_apply_retention_deletes_production_checkpoint_and_queue_keys(self, monkeypatch):
        """Issue #50: checkpoint_key()/queue_key() entries age out via payload timestamps."""
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
        storage = MemoryStorage()
        store = IncidentStore(storage)
        org = "org1"
        aged_checkpoint = storage.checkpoint_key(org, "INC-old")
        aged_queue = storage.queue_key(org, "pending", "INC-old")
        storage.put_json(
            aged_checkpoint,
            {"incident_id": "INC-old", "updated_at": "2020-01-15T00:00:00+00:00"},
        )
        storage.put_json(
            aged_queue,
            {
                "incident_id": "INC-old",
                "status": "pending",
                "created_at": "2020-01-15T00:00:00+00:00",
            },
        )
        store.save_checkpoint(org, "INC-new", [], [], 1, {}, "k8s")
        fresh_queue = storage.queue_key(org, "pending", "INC-new")
        storage.put_json(
            fresh_queue,
            {
                "incident_id": "INC-new",
                "status": "pending",
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        deleted = store.apply_retention(org)

        assert deleted == 2
        assert not storage.exists(aged_checkpoint)
        assert not storage.exists(aged_queue)
        assert storage.exists(storage.checkpoint_key(org, "INC-new"))
        assert storage.exists(fresh_queue)


class TestRetentionScheduler:
    @pytest.mark.asyncio
    async def test_startup_retention_pass_covers_configured_orgs(self, monkeypatch):
        """Entering the API lifespan must schedule one immediate retention pass
        covering the de-duplicated union of ORG_ID and comma-separated ORG_IDS."""
        monkeypatch.setenv("ORG_ID", "default")
        monkeypatch.setenv("ORG_IDS", "a, b,a,,")
        calls = []

        async def spy_apply_retention(self, org_id):
            calls.append(org_id)
            return 0

        monkeypatch.setattr(IncidentStore, "apply_retention", spy_apply_retention)
        # Neutralize the queue worker loop: no orgs to poll, so it just idles.
        monkeypatch.setattr(IncidentQueue, "list_pending_org_ids", lambda self: [])

        with (
            patch("agent.core.DevOpsAgent"),
            patch("tools.notify.SlackNotifier"),
            patch("services.org_docs.OrgDocs"),
            patch("services.escalation.EscalationService"),
        ):
            import api.server as server

            importlib.reload(server)
            async with server.lifespan(server.app):
                # Give scheduled startup work a deterministic event-loop turn.
                await asyncio.sleep(0)
                await asyncio.sleep(0)

        assert calls == ["default", "a", "b"]


class TestOrgDocs:
    def test_upload_list_get(self):
        storage = MemoryStorage()
        docs = OrgDocs(storage)
        docs.upload("acme", "runbooks/k8s-oom.md", "# OOM runbook\nIncrease memory limits.")
        listed = docs.list_docs("acme")
        assert len(listed) == 1
        content = docs.get("acme", "runbooks/k8s-oom.md")
        assert "OOM runbook" in content

    def test_context_for_agent(self):
        storage = MemoryStorage()
        docs = OrgDocs(storage)
        docs.upload("acme", "runbooks/k8s-oom.md", "# K8s OOM\nSet limits to 512Mi.")
        ctx = docs.get_context_for_agent("acme", "k8s")
        assert "Organization documentation" in ctx
        assert "512Mi" in ctx


class TestGrounding:
    def test_requires_tool_evidence_for_k8s(self):
        validation = validate_resolution("k8s", [], "Pod is OOM killed.")
        assert validation["grounded"] is False
        assert validation["has_tool_evidence"] is False

    def test_passes_with_tool_evidence_and_evidence_section(self):
        actions = [
            {"tool": "get_k8s_context", "result": {"pods": [{"name": "api"}]}},
            {
                "tool": "suggest_fix",
                "result": {
                    "recorded": True,
                    "title": "Increase memory limit",
                    "commands": ["kubectl set resources deployment/api --limits=memory=512Mi -n prod"],
                },
            },
        ]
        diagnosis = "Evidence: get_k8s_context showed OOMKilled.\nRoot cause: memory limit too low."
        validation = validate_resolution("k8s", actions, diagnosis)
        assert validation["grounded"] is True
        assert has_tool_evidence(actions)
        assert validation["has_suggestions"] is True

    def test_passes_with_successful_remediation_without_suggest_fix(self):
        actions = [
            {"tool": "get_k8s_context", "result": {"pods": [{"name": "api"}]}},
            {"tool": "apply_k8s_manifest", "result": {"success": True}},
        ]
        diagnosis = "Evidence: get_k8s_context showed OOMKilled.\nApplied memory limit fix."
        validation = validate_resolution("k8s", actions, diagnosis)
        assert validation["grounded"] is True

    def test_append_grounding_rules(self):
        prompt = append_grounding_rules("You are a DevOps agent.")
        assert "GROUNDING RULES" in prompt
        assert "hallucination" in prompt.lower() or "NEVER" in prompt

    def test_successful_remediation_after_failed_attempt(self):
        """Issue #54: later successful remediation counts even if an earlier attempt failed."""
        actions = [
            {"tool": "apply_k8s_manifest", "result": {"success": False, "error": "conflict"}},
            {"tool": "run_kubectl", "result": {"success": True}},
        ]
        assert has_successful_remediation(actions) is True

    def test_no_successful_remediation_when_all_fail(self):
        actions = [
            {"tool": "apply_k8s_manifest", "result": {"success": False, "error": "conflict"}},
            {"tool": "run_kubectl", "result": {"success": False, "error": "timeout"}},
        ]
        assert has_successful_remediation(actions) is False


class TestOrgConfig:
    def test_save_and_status(self):
        storage = MemoryStorage()
        config = OrgConfig(storage=storage)
        config.save("acme", {
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/test",
            "GITHUB_TOKEN": "ghp_test",
            "UNKNOWN_KEY": "ignored",
        })
        status = config.status("acme")
        assert status["configured"]["SLACK_WEBHOOK_URL"] is True
        assert status["configured"]["GITHUB_TOKEN"] is True
        assert "UNKNOWN_KEY" not in status["configured"]

    def test_org_credentials_overlay(self, monkeypatch):
        storage = MemoryStorage()
        config = OrgConfig(storage=storage)
        config.save("acme", {"GITHUB_TOKEN": "ghp_acme"})
        monkeypatch.setenv("ORG_ID", "acme")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_global")

        with org_credentials("acme", config):
            assert os.getenv("GITHUB_TOKEN") == "ghp_acme"

        assert os.getenv("GITHUB_TOKEN") == "ghp_global"
