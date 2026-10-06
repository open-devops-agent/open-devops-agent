"""Observability, SLO/error budget, on-call, and data-store safety."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.classifier import classify_issue
from tools.data_state import DataStateTools
from tools.observability import ObservabilityTools, _scalar


class FakeResp:
    def __init__(self, status, payload, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text or ""

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    async def get(self, url, params=None, headers=None, timeout=None, follow_redirects=None):
        self.calls.append(("GET", url, params))
        return self.resp

    async def post(self, url, headers=None, json=None, **kwargs):
        self.calls.append(("POST", url, json))
        return self.resp

    async def aclose(self):
        return None


class TestClassifier:
    def test_observability_and_data_types(self):
        assert classify_issue("SLOBurnRateHigh", {}) == "observability"
        assert classify_issue("KafkaConsumerLag", {}) == "data"
        assert classify_issue("PrometheusTargetDown", {}) == "observability"


class TestObservability:
    def test_scalar_from_prometheus_vector(self):
        payload = {"success": True, "data": {"result": [{"value": [1, "0.995"]}]}}
        assert abs(_scalar(payload) - 0.995) < 1e-9

    @pytest.mark.asyncio
    async def test_prometheus_query(self, monkeypatch):
        monkeypatch.setenv("PROMETHEUS_URL", "http://prom.local")
        resp = FakeResp(200, {"status": "success", "data": {"result": [{"value": [0, "12"]}]}})
        tools = ObservabilityTools(client=FakeClient(resp))
        result = await tools.query_metrics("up")
        assert result["success"] is True
        assert _scalar(result) == 12.0

    @pytest.mark.asyncio
    async def test_evaluate_slo_burning(self, monkeypatch):
        monkeypatch.setenv("PROMETHEUS_URL", "http://prom.local")
        tools = ObservabilityTools()

        async def fake_query(query, provider="prometheus", **kwargs):
            value = "99" if "good" in query else "100"
            return {"success": True, "data": {"result": [{"value": [0, value]}]}}

        tools.query_metrics = fake_query
        result = await tools.evaluate_slo("good", "total", objective=0.999)
        assert result["success"] is True
        assert result["availability"] == 0.99
        assert result["burning"] is True
        assert result["error_budget_remaining"] < 1

    @pytest.mark.asyncio
    async def test_synthetic(self):
        resp = FakeResp(200, {})
        client = FakeClient(resp)
        tools = ObservabilityTools(client=client)
        result = await tools.run_synthetic("https://example.com/health")
        assert result["success"] is True
        assert result["status_code"] == 200

    @pytest.mark.asyncio
    async def test_oncall_roster(self, monkeypatch):
        monkeypatch.setenv("PAGERDUTY_TOKEN", "tok")
        payload = {
            "oncalls": [
                {
                    "escalation_level": 1,
                    "user": {"summary": "Ada", "id": "PU1", "html_url": "https://pd/u/1"},
                    "schedule": {"summary": "Primary"},
                }
            ]
        }
        tools = ObservabilityTools(client=FakeClient(FakeResp(200, payload)))
        result = await tools.get_oncall_roster()
        assert result["success"] is True
        assert result["incident_commander"]["name"] == "Ada"
        assigned = await tools.assign_incident_commander()
        assert assigned["commander"]["name"] == "Ada"

    @pytest.mark.asyncio
    async def test_statuspage(self, monkeypatch):
        monkeypatch.setenv("STATUSPAGE_PAGE_ID", "pg")
        monkeypatch.setenv("STATUSPAGE_API_KEY", "key")
        resp = FakeResp(201, {"id": "inc1", "shortlink": "https://stspg.io/x", "status": "investigating"})
        tools = ObservabilityTools(client=FakeClient(resp))
        result = await tools.update_status_page("API outage", "Looking into 5xx")
        assert result["success"] is True
        assert result["incident_id"] == "inc1"


class TestDataState:
    @pytest.mark.asyncio
    async def test_db_blocked_by_default(self, monkeypatch):
        monkeypatch.delenv("ENABLE_DATABASE_COLLECTION", raising=False)
        result = await DataStateTools().check_database_health("rds", "prod")
        assert result["blocked"] is True

    @pytest.mark.asyncio
    async def test_restore_never_runs(self, monkeypatch):
        monkeypatch.setenv("ENABLE_DATABASE_COLLECTION", "true")
        result = await DataStateTools().restore_from_snapshot("snap-1", "db-prod")
        assert result["blocked"] is True
        assert result["requires_approval"] is True

    @pytest.mark.asyncio
    async def test_rejects_mutating_sql(self, monkeypatch):
        monkeypatch.setenv("ENABLE_DATABASE_COLLECTION", "true")
        result = await DataStateTools().check_database_health(query="DELETE FROM users")
        assert result["blocked"] is True

    @pytest.mark.asyncio
    async def test_elasticsearch_health(self, monkeypatch):
        monkeypatch.setenv("ENABLE_DATA_STORE_COLLECTION", "true")
        monkeypatch.setenv("ELASTICSEARCH_URL", "http://es.local")
        resp = FakeResp(200, {"status": "green", "number_of_nodes": 3})
        result = await DataStateTools(client=FakeClient(resp)).elasticsearch_health()
        assert result["success"] is True
        assert result["status"] == "green"

    @pytest.mark.asyncio
    async def test_kafka_blocked_when_disabled(self, monkeypatch):
        monkeypatch.delenv("ENABLE_DATA_STORE_COLLECTION", raising=False)
        monkeypatch.delenv("ENABLE_DATABASE_COLLECTION", raising=False)
        result = await DataStateTools().kafka_health("kafka:9092")
        assert result["blocked"] is True
