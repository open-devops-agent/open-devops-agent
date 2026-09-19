"""
Tests for DevOps AI Agent
Run: pytest tests/ -v
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from tools.executor import SafeExecutor
from agent.prompts import get_system_prompt
from agent.classifier import classify_issue


# ─── Executor Safety Tests ────────────────────────────────────────────────────

class TestSafeExecutor:
    def setup_method(self):
        self.executor = SafeExecutor()

    def test_classifies_read_only_as_safe(self):
        assert self.executor._classify("kubectl get pods -n default") == "safe"
        assert self.executor._classify("kubectl describe pod my-pod") == "safe"
        assert self.executor._classify("kubectl logs my-pod") == "safe"
        assert self.executor._classify("df -h") == "safe"
        assert self.executor._classify("ps aux --sort=-%cpu") == "safe"

    def test_classifies_restart_as_allowed(self):
        assert self.executor._classify("kubectl rollout restart deployment/api") == "allowed"

    def test_classifies_scale_as_requires_approval_by_default(self):
        assert self.executor._classify("kubectl scale deployment/api --replicas=3") == "requires_approval"
        assert self.executor._classify("systemctl restart nginx") == "allowed"

    def test_classifies_delete_as_requires_approval(self):
        assert self.executor._classify("kubectl delete pod my-pod") == "requires_approval"
        assert self.executor._classify("rm -rf /var/log/app") == "requires_approval"
        assert self.executor._classify("kubectl exec -it my-pod -- bash") == "requires_approval"

    def test_blocks_dangerous_commands(self):
        assert self.executor._classify("dd if=/dev/zero of=/dev/sda") == "requires_approval"
        assert self.executor._classify("shutdown -r now") == "requires_approval"
        assert self.executor._classify("mkfs.ext4 /dev/sdb") == "requires_approval"

    @pytest.mark.asyncio
    async def test_blocks_unapproved_restart_when_auto_apply_false(self):
        self.executor.auto_apply = False
        result = await self.executor.run_safe("kubectl rollout restart deployment/api -n prod")
        assert result.get("blocked") is True
        assert result.get("requires_approval") is True

    @pytest.mark.asyncio
    async def test_allows_safe_commands_without_approval(self):
        with patch("asyncio.create_subprocess_shell") as mock_proc:
            mock_proc.return_value = AsyncMock(
                returncode=0,
                communicate=AsyncMock(return_value=(b"NAME   READY\npod-1   1/1", b"")),
            )
            result = await self.executor.run_safe("kubectl get pods")
            assert result.get("success") is True


# ─── Prompt Tests ─────────────────────────────────────────────────────────────

class TestPrompts:
    def test_returns_prompt_for_known_type(self):
        for t in ["cicd", "k8s", "server", "dockerfile"]:
            prompt = get_system_prompt(t)
            assert len(prompt) > 100
            assert isinstance(prompt, str)

    def test_returns_default_for_unknown_type(self):
        prompt = get_system_prompt("unknown_type")
        assert "DevOps" in prompt


# ─── Classifier Tests ─────────────────────────────────────────────────────────

class TestClassifier:
    def test_classifies_k8s_alerts(self):
        for name in ["PodCrashLooping", "ContainerOOMKilled", "ImagePullBackOff"]:
            assert classify_issue(name, {}) == "k8s"

    def test_classifies_server_alerts(self):
        for name in ["HighCPU", "DiskFull", "NginxDown", "HighMemoryUsage"]:
            assert classify_issue(name, {}) == "server"

    def test_classifies_cicd_alerts(self):
        for name in ["DeploymentFailed", "PipelineError", "BuildFailed"]:
            assert classify_issue(name, {}) == "cicd"


# ─── Integration: Agent with mocked Claude ────────────────────────────────────

class TestAgentLoop:
    @pytest.mark.asyncio
    async def test_agent_handles_k8s_incident(self):
        from agent.core import DevOpsAgent
        import os

        os.environ['ANTHROPIC_API_KEY'] = 'sk-ant-test-dummy-key-for-testing'

        with patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_anthropic.return_value = mock_client

            # Step 1: Claude requests tool
            tool_block = MagicMock()
            tool_block.type = "tool_use"
            tool_block.name = "get_k8s_context"
            tool_block.id = "tool_1"
            tool_block.input = {"namespace": "production"}

            mock_tool_response = MagicMock()
            mock_tool_response.stop_reason = "tool_use"
            mock_tool_response.content = [tool_block]

            # Step 2: Claude suggests non-destructive fix
            suggest_block = MagicMock()
            suggest_block.type = "tool_use"
            suggest_block.name = "suggest_fix"
            suggest_block.id = "tool_2"
            suggest_block.input = {
                "title": "Increase memory limits",
                "description": "Evidence: OOMKilled on api-pod",
                "commands": ["kubectl set resources deployment/api -n production --limits=memory=512Mi"],
                "verification_steps": ["kubectl get pods -n production"],
            }

            mock_suggest_response = MagicMock()
            mock_suggest_response.stop_reason = "tool_use"
            mock_suggest_response.content = [suggest_block]

            # Step 3: Claude concludes with evidence
            mock_end_response = MagicMock()
            mock_end_response.stop_reason = "end_turn"
            mock_end_response.content = [
                MagicMock(
                    type="text",
                    text="Evidence: get_k8s_context showed OOMKilled on api-pod.\nOOM detected. Suggested memory increase to 512Mi via suggest_fix.",
                )
            ]

            mock_client.messages.create.side_effect = [
                mock_tool_response, mock_suggest_response, mock_end_response,
            ]

            agent = DevOpsAgent()
            agent.k8s_collector.collect = AsyncMock(return_value={"pods": [{"name": "api-pod", "reason": "OOMKilled"}]})
            agent.notifier.send_resolution = AsyncMock()
            agent.notifier.send_fix_suggestion = AsyncMock()
            agent.incident_store = __import__("services.incident_store", fromlist=["IncidentStore"]).IncidentStore(
                __import__("storage.memory_storage", fromlist=["MemoryStorage"]).MemoryStorage()
            )
            agent.org_docs = __import__("services.org_docs", fromlist=["OrgDocs"]).OrgDocs(
                __import__("storage.memory_storage", fromlist=["MemoryStorage"]).MemoryStorage()
            )

            result = await agent.run({
                "type": "k8s",
                "namespace": "production",
                "pod": "api-pod",
                "org_id": "test-org",
            }, incident_id="INC-TEST-001", resume=False)

            assert result["resolved"] is True
            assert "OOM" in result["diagnosis"]
            assert result["grounding"]["grounded"] is True
            assert len(result["suggested_fixes"]) == 1
            assert result["suggestions_only"] is True


# ─── Issue #7: post-remediation FixVerifier integration ───────────────────────

class TestFixVerification:
    """verify_fix runs exactly once after successful remediation (never on a
    suggestions-only run), and its structured result reaches the completed
    result, the incident audit trail, and the Slack completion payload."""

    @staticmethod
    def _script(final_text, *tool_calls):
        """Scripted Claude responses: tool_use rounds, then an end_turn text."""
        script = []
        for i, (name, inputs) in enumerate(tool_calls):
            block = MagicMock()
            block.type, block.name, block.id, block.input = "tool_use", name, f"t{i}", inputs
            script.append(MagicMock(stop_reason="tool_use", content=[block]))
        end = MagicMock(stop_reason="end_turn")
        end.content = [MagicMock(type="text", text=final_text)]
        return script + [end]

    @staticmethod
    def _agent():
        """Agent with in-memory stores and mocked k8s/notification surfaces."""
        import os
        from agent.core import DevOpsAgent
        from services.incident_store import IncidentStore
        from services.org_docs import OrgDocs
        from storage.memory_storage import MemoryStorage

        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test-dummy-key-for-testing"
        agent = DevOpsAgent()
        agent.k8s_collector.collect = AsyncMock(return_value={"pods": []})
        agent.k8s_tools.run_kubectl = AsyncMock(return_value={"success": True})
        agent.notifier.send_message = AsyncMock()
        agent.notifier.send_fix_suggestion = AsyncMock()
        storage = MemoryStorage()
        agent.incident_store = IncidentStore(storage)
        agent.org_docs = OrgDocs(MemoryStorage())
        return agent, storage

    @pytest.mark.asyncio
    async def test_successful_remediation_triggers_verification(self):
        verification_result = {
            "verified": True, "status": "success", "incident_type": "k8s",
            "fix_applied": "run_kubectl", "monitoring_period": 300,
            "timestamp": "2026-08-19T00:00:00", "checks_performed": [],
        }
        with (
            patch("anthropic.Anthropic") as mock_anthropic,
            patch("tools.fix_verifier.FixVerifier.verify_fix",
                  new=AsyncMock(return_value=verification_result)) as mock_verify,
        ):
            mock_anthropic.return_value.messages.create.side_effect = self._script(
                "Evidence: get_k8s_context showed OOMKilled on api-pod.\n"
                "Restarted the deployment via run_kubectl; rollout complete.",
                ("get_k8s_context", {"namespace": "production"}),
                ("run_kubectl", {"command": "rollout restart deployment/api -n production"}),
            )
            agent, storage = self._agent()
            result = await agent.run(
                {"type": "k8s", "namespace": "production", "pod": "api-pod", "org_id": "test-org"},
                incident_id="INC-VERIFY-001", resume=False,
            )

            # Exactly one verifier call, incident-derived expected state, and the
            # documented 300-second (5-minute) stability window.
            mock_verify.assert_awaited_once()
            assert mock_verify.await_args.kwargs == {
                "incident_type": "k8s",
                "fix_applied": "run_kubectl",
                "expected_state": {"pod_name": "api-pod", "namespace": "production", "pod_status": "Running"},
                "monitoring_duration": 300,
            }
            # The same structured value reaches the completed result, the
            # incident audit trail, and the Slack completion payload.
            assert result["fix_applied"] is True
            assert result["verification"] == verification_result
            keys = [k for k in storage.list_keys("test-org/logs") if k.endswith("verification.json")]
            assert len(keys) == 1
            assert storage.get_json(keys[0]) == verification_result
            agent.notifier.send_message.assert_awaited_once()
            slack_message = agent.notifier.send_message.await_args.args[0]
            assert "INC-VERIFY-001" in slack_message
            assert '"status": "success"' in slack_message

    @pytest.mark.asyncio
    async def test_suggestions_only_skips_verification(self):
        with (
            patch("anthropic.Anthropic") as mock_anthropic,
            patch("tools.fix_verifier.FixVerifier.verify_fix", new=AsyncMock()) as mock_verify,
        ):
            mock_anthropic.return_value.messages.create.side_effect = self._script(
                "Evidence: get_k8s_context showed OOMKilled on api-pod.\n"
                "OOM detected. Suggested memory increase to 512Mi via suggest_fix.",
                ("get_k8s_context", {"namespace": "production"}),
                ("suggest_fix", {
                    "title": "Increase memory limits",
                    "description": "Evidence: OOMKilled on api-pod",
                    "commands": ["kubectl set resources deployment/api -n production --limits=memory=512Mi"],
                }),
            )
            agent, storage = self._agent()
            result = await agent.run(
                {"type": "k8s", "namespace": "production", "pod": "api-pod", "org_id": "test-org"},
                incident_id="INC-VERIFY-002", resume=False,
            )

            assert result["suggestions_only"] is True
            assert result.get("fix_applied") is False
            mock_verify.assert_not_called()
            assert result.get("verification") is None
            assert [k for k in storage.list_keys("test-org/logs") if k.endswith("verification.json")] == []
            agent.notifier.send_message.assert_not_called()


# ─── Issue #7 regressions: canonical audit surface and stability stage ────────

class TestVerificationAuditAndStability:
    """The queue completion mapper must place the structured verification result
    into the canonical org-scoped audit entry (the surface returned by GET /audit),
    and the agent's configured stability window must make at least one
    post-immediate observation before reporting stability."""

    @pytest.mark.asyncio
    async def test_canonical_audit_entry_contains_verification(self):
        import api.server as server
        from services.incident_store import IncidentStore
        from storage.memory_storage import MemoryStorage

        verification = {
            "verified": True,
            "status": "success",
            "checks_performed": [{"check_type": "immediate", "passed": True}],
        }
        result = {
            "diagnosis": "OOM remediated", "actions": [], "resolved": True,
            "fix_applied": True, "verification": verification,
        }
        store = IncidentStore(MemoryStorage())
        decision = MagicMock(should_escalate=False, duration_minutes=1.0, reasons=[])
        with (
            patch.object(server, "agent") as mock_agent,
            patch.object(server, "escalation_service") as mock_escalation,
            patch.object(server, "incident_queue") as mock_queue,
            patch.object(server, "notifier") as mock_notifier,
            patch.object(server, "incident_store", store),
        ):
            mock_agent.run = AsyncMock(return_value=result)
            mock_escalation.evaluate.return_value = decision
            mock_queue.mark_completed = MagicMock()
            mock_notifier.send_resolution = AsyncMock()
            await server._process_incident_with_org_creds(
                {"incident_id": "INC-AUDIT-1", "org_id": "test-org"},
                "INC-AUDIT-1", "test-org", {"type": "k8s", "org_id": "test-org"}, None,
            )
            response = await server.get_audit(org_id="test-org")

        assert response["total"] == 1
        assert response["events"][0].get("verification") == verification

    @pytest.mark.asyncio
    async def test_stability_stage_observes_with_agent_configured_duration(self):
        from agent.core import FIX_VERIFICATION_MONITORING_SECONDS
        from tools.fix_verifier import FixVerifier

        fake_clock = MagicMock()
        fake_clock.time.side_effect = (tick * 31.0 for tick in range(64))
        fake_asyncio = MagicMock()
        fake_asyncio.sleep = AsyncMock()

        async def immediate_pass(self, incident_type, expected_state):
            return {"check_type": "immediate", "passed": True, "details": {}}

        with (
            patch("tools.fix_verifier.time", fake_clock),
            patch("tools.fix_verifier.asyncio", fake_asyncio),
            patch.object(FixVerifier, "_run_immediate_checks", immediate_pass),
        ):
            result = await FixVerifier().verify_fix(
                incident_type="cicd",
                fix_applied="rerun_pipeline",
                expected_state={},
                monitoring_duration=FIX_VERIFICATION_MONITORING_SECONDS,
            )

        assert result["status"] == "success"
        stability = result["checks_performed"][1]
        assert stability["stable"] is True
        assert stability["checks_performed"] >= 1, (
            "stability was reported without observing the remediated state even once"
        )


class TestVerificationExpectedState:
    def test_cicd_cloud_and_argocd_include_target_identifiers(self):
        from agent.core import _verification_expected_state

        cicd = _verification_expected_state(
            "cicd",
            {"source": "github", "repo": "o/r", "run_id": 99},
        )
        assert cicd["platform"] == "github"
        assert cicd["repo"] == "o/r"
        assert cicd["run_id"] == 99

        cloud = _verification_expected_state(
            "cloud_aws",
            {"resource_type": "ec2", "resource_id": "i-1", "params": {"region": "us-east-1"}},
        )
        assert cloud["resource_type"] == "ec2"
        assert cloud["resource_id"] == "i-1"
        assert cloud["region"] == "us-east-1"

        argocd = _verification_expected_state("argocd", {"app_name": "frontend"})
        assert argocd == {"health": "Healthy", "sync": "Synced", "app_name": "frontend"}
