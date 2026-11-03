"""Prometheus /metrics for the agent itself (#125)."""
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from api import server
from services import metrics


def sample(name, labels=None):
    value = metrics.REGISTRY.get_sample_value(name, labels or {})
    return value or 0.0


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("METRICS_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_EMERGENCY_STOP", raising=False)
    return TestClient(server.app)


class TestEndpoint:
    def test_serves_prometheus_text(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        names = {family.name for family in text_string_to_metric_families(response.text)}
        for expected in (
            "devops_agent_incidents",
            "devops_agent_incident_duration_seconds",
            "devops_agent_queue_depth",
            "devops_agent_tool_calls",
            "devops_agent_approvals",
            "devops_agent_llm_tokens",
            "devops_agent_fix_verification",
            "devops_agent_http_requests",
            "devops_agent_emergency_stop",
        ):
            assert expected in names

    def test_token_required_when_configured(self, client, monkeypatch):
        monkeypatch.setenv("METRICS_TOKEN", "scrape-secret")
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
        ok = client.get("/metrics", headers={"Authorization": "Bearer scrape-secret"})
        assert ok.status_code == 200

    def test_emergency_stop_gauge(self, client, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        client.get("/metrics")
        assert sample("devops_agent_emergency_stop") == 1
        monkeypatch.delenv("AGENT_EMERGENCY_STOP")
        client.get("/metrics")
        assert sample("devops_agent_emergency_stop") == 0

    def test_queue_depth_gauge(self, client, monkeypatch):
        from storage.memory_storage import MemoryStorage
        from services.incident_queue import IncidentQueue

        queue = IncidentQueue(MemoryStorage())
        monkeypatch.setattr(server, "incident_queue", queue)
        monkeypatch.setenv("ORG_ID", "acme")
        queue.enqueue("acme", {"type": "k8s"})
        queue.enqueue("acme", {"type": "server"})
        queue.claim_next("acme")
        client.get("/metrics")
        assert sample("devops_agent_queue_depth", {"state": "pending"}) == 1
        assert sample("devops_agent_queue_depth", {"state": "processing"}) == 1

    def test_queue_depth_failure_does_not_break_scrape(self, client, monkeypatch):
        broken = MagicMock()
        broken.list_pending_org_ids.side_effect = RuntimeError("storage down")
        monkeypatch.setattr(server, "incident_queue", broken)
        assert client.get("/metrics").status_code == 200


class TestHttpRequests:
    def test_counted_by_route_template_not_raw_path(self, client, monkeypatch):
        monkeypatch.setenv("API_ADMIN_TOKEN", "t")
        labels = {"route": "/orgs/{org_id}/docs", "method": "GET", "status": "401"}
        before = sample("devops_agent_http_requests_total", labels)
        client.get("/orgs/acme/docs")
        client.get("/orgs/globex/docs")
        assert sample("devops_agent_http_requests_total", labels) == before + 2

    def test_metrics_scrapes_are_not_counted(self, client):
        client.get("/metrics")
        assert sample(
            "devops_agent_http_requests_total", {"route": "/metrics", "method": "GET", "status": "200"}
        ) == 0


class TestLabels:
    def test_tool_result_labels(self):
        assert metrics.tool_result_label({"success": True}) == "ok"
        assert metrics.tool_result_label({"requires_approval": True, "blocked": True}) == "requires_approval"
        assert metrics.tool_result_label({"blocked": True}) == "blocked"
        assert metrics.tool_result_label({"emergency_stop": True, "blocked": True}) == "emergency_stop"
        assert metrics.tool_result_label({"error": "boom"}) == "error"
        assert metrics.tool_result_label({"success": False}) == "error"
        assert metrics.tool_result_label("text") == "ok"

    def test_unknown_tools_and_untrusted_labels_are_bounded(self):
        before = sample("devops_agent_tool_calls_total", {"tool": "other", "result": "ok"})
        metrics.record_tool_call("made_up_tool_" + "x" * 50, {}, {"query_logs"})
        assert sample("devops_agent_tool_calls_total", {"tool": "other", "result": "ok"}) == before + 1

        before = sample("devops_agent_incidents_total", {"type": "other", "source": "other", "outcome": "failed"})
        metrics.record_incident({"type": "attacker-chosen", "source": "evil"}, "failed", 1.0)
        assert sample(
            "devops_agent_incidents_total", {"type": "other", "source": "other", "outcome": "failed"}
        ) == before + 1

    def test_llm_usage(self):
        labels = {"model": "claude-test", "kind": "input"}
        before = sample("devops_agent_llm_tokens_total", labels)
        metrics.record_llm_usage("claude-test", SimpleNamespace(input_tokens=120, output_tokens=30))
        assert sample("devops_agent_llm_tokens_total", labels) == before + 120
        metrics.record_llm_usage("claude-test", None)

    def test_verification(self):
        labels = {"status": "unstable"}
        before = sample("devops_agent_fix_verification_total", labels)
        metrics.record_verification({"status": "unstable", "verified": False})
        metrics.record_verification(None)
        assert sample("devops_agent_fix_verification_total", labels) == before + 1


class TestInstrumentation:
    @pytest.mark.asyncio
    async def test_incident_outcomes(self, monkeypatch):
        monkeypatch.setattr(server, "escalation_service", MagicMock(evaluate=MagicMock(
            return_value=SimpleNamespace(should_escalate=False, duration_minutes=0, reasons=[])
        )))
        monkeypatch.setattr(server, "incident_store", MagicMock())
        monkeypatch.setattr(server, "incident_queue", MagicMock())
        monkeypatch.setattr(server, "notifier", AsyncMock())
        context = {"type": "k8s", "source": "alertmanager"}

        def count(outcome):
            return sample(
                "devops_agent_incidents_total", {"type": "k8s", "source": "alertmanager", "outcome": outcome}
            )

        resolved, unresolved, failed = count("resolved"), count("unresolved"), count("failed")
        agent = MagicMock()
        monkeypatch.setattr(server, "agent", agent)

        agent.run = AsyncMock(return_value={"resolved": True})
        await server._process_incident_with_org_creds({}, "INC-1", "acme", context, None)
        agent.run = AsyncMock(return_value={"resolved": False})
        await server._process_incident_with_org_creds({}, "INC-2", "acme", context, None)
        agent.run = AsyncMock(side_effect=RuntimeError("claude down"))
        await server._process_incident_with_org_creds({}, "INC-3", "acme", context, None)

        assert (count("resolved"), count("unresolved"), count("failed")) == (resolved + 1, unresolved + 1, failed + 1)
        assert sample("devops_agent_incident_duration_seconds_count", {"type": "k8s"}) >= 3

    @pytest.mark.asyncio
    async def test_public_execute_tool_is_counted(self, monkeypatch):
        from agent.core import DevOpsAgent

        agent = DevOpsAgent()
        monkeypatch.setattr(agent, "_execute_tool", AsyncMock(return_value={"requires_approval": True}))
        labels = {"tool": "restart_nginx", "result": "requires_approval"}
        before = sample("devops_agent_tool_calls_total", labels)
        await agent.execute_tool("restart_nginx", {}, {"org_id": "acme"})
        assert sample("devops_agent_tool_calls_total", labels) == before + 1

    def test_approval_decisions_are_counted(self, monkeypatch):
        monkeypatch.setattr(server, "incident_store", MagicMock())
        before = sample("devops_agent_approvals_total", {"decision": "denied"})
        server._record_slack_decision("acme", "INC-1", "denied", "U1", "mallory", "cmd")
        assert sample("devops_agent_approvals_total", {"decision": "denied"}) == before + 1
