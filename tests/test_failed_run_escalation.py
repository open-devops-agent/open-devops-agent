"""A run that fails after threat detection must still escalate as a security incident."""
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest

MINER_CONTEXT = {
    "type": "server",
    "host": "web-1",
    "org_id": "acme",
    "summary": "High CPU",
    "raw_logs": "kworker 99%\n/usr/local/.x/xmrig -o stratum+tcp://pool.supportxmr.com:3333",
}


def _agent():
    from agent.core import DevOpsAgent
    from services.incident_store import IncidentStore
    from services.org_docs import OrgDocs
    from storage.memory_storage import MemoryStorage

    agent = DevOpsAgent()
    agent.server_collector.collect = AsyncMock(return_value={"cpu": 99})
    agent.incident_store = IncidentStore(MemoryStorage())
    agent.org_docs = OrgDocs(MemoryStorage())
    return agent


class AuthFailure(Exception):
    pass


@pytest.mark.asyncio
async def test_failed_run_carries_security_findings():
    agent = _agent()
    with patch("anthropic.Anthropic") as mock_anthropic:
        mock_anthropic.return_value.messages.create.side_effect = AuthFailure("invalid x-api-key")
        with pytest.raises(AuthFailure) as excinfo:
            await agent.run(dict(MINER_CONTEXT), incident_id="INC-FAIL-1", resume=False)

    partial = excinfo.value.partial_result
    assert partial["resolved"] is False
    assert partial["issue_type"] == "security"
    assert partial["threat_findings"]["highest_severity"] == "critical"
    assert agent._run_state == {}  # cleaned up after a failure


@pytest.mark.asyncio
async def test_failure_before_collection_keeps_original_type():
    agent = _agent()
    agent._collect_context = AsyncMock(side_effect=AuthFailure("storage down"))
    with pytest.raises(AuthFailure) as excinfo:
        await agent.run({"type": "k8s", "org_id": "acme"}, incident_id="INC-FAIL-2", resume=False)
    assert excinfo.value.partial_result["issue_type"] == "k8s"
    assert excinfo.value.partial_result["threat_findings"] is None


@pytest.mark.asyncio
async def test_run_state_cleared_after_success():
    agent = _agent()
    agent._run_with_org_context = AsyncMock(return_value={"resolved": True})
    await agent.run({"type": "k8s", "org_id": "acme"}, incident_id="INC-OK", resume=False)
    assert agent._run_state == {}


@pytest.mark.asyncio
async def test_server_escalates_failed_security_run_at_critical(monkeypatch):
    from api import server
    from services.escalation import EscalationService

    failure = AuthFailure("invalid x-api-key")
    failure.partial_result = {
        "resolved": False,
        "issue_type": "security",
        "threat_findings": {"highest_severity": "critical", "findings": [{"rule": "crypto_mining"}]},
        "prompt_injection": None,
    }
    agent = MagicMock()
    agent.run = AsyncMock(side_effect=failure)
    escalation = EscalationService()
    escalation.escalate = AsyncMock(return_value={"escalated": True})
    store = MagicMock()
    monkeypatch.setattr(server, "agent", agent)
    monkeypatch.setattr(server, "escalation_service", escalation)
    monkeypatch.setattr(server, "incident_store", store)
    monkeypatch.setattr(server, "incident_queue", MagicMock())
    monkeypatch.setattr(server, "notifier", AsyncMock())

    from datetime import datetime, timezone

    await server._process_incident_with_org_creds(
        {}, "INC-FAIL-3", "acme", dict(MINER_CONTEXT), datetime.now(timezone.utc)
    )

    decision = escalation.escalate.await_args.args[0]
    assert decision.reasons[0] == "security_incident"
    assert "agent_error" in decision.reasons
    assert decision.priority == "critical"
    audit = store.save_audit.call_args.args[2]
    assert audit["issue_type"] == "security"
    assert audit["threat_findings"]["highest_severity"] == "critical"


@pytest.mark.asyncio
async def test_server_without_partial_result_behaves_as_before(monkeypatch):
    from api import server
    from services.escalation import EscalationService

    agent = MagicMock()
    agent.run = AsyncMock(side_effect=RuntimeError("boom"))
    escalation = EscalationService()
    escalation.escalate = AsyncMock(return_value={"escalated": True})
    monkeypatch.setattr(server, "agent", agent)
    monkeypatch.setattr(server, "escalation_service", escalation)
    monkeypatch.setattr(server, "incident_store", MagicMock())
    monkeypatch.setattr(server, "incident_queue", MagicMock())
    monkeypatch.setattr(server, "notifier", AsyncMock())

    from datetime import datetime, timezone

    await server._process_incident_with_org_creds(
        {}, "INC-FAIL-4", "acme", {"type": "k8s"}, datetime.now(timezone.utc)
    )
    decision = escalation.escalate.await_args.args[0]
    assert "security_incident" not in decision.reasons
    assert "agent_error" in decision.reasons
