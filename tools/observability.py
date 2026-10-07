"""
Observability and reliability operations.

Prometheus/Grafana/Datadog/New Relic queries, SLO/error-budget math, capacity
signals, traces, synthetic checks, PagerDuty on-call, Statuspage updates.
"""
from __future__ import annotations

import os
import time
from typing import Optional
from urllib.parse import urljoin

import httpx
import structlog

from tools.safety import emergency_stop_block, is_emergency_stop_active

log = structlog.get_logger()


class ObservabilityTools:
    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self._client = client

    async def _http(self) -> httpx.AsyncClient:
        if self._client:
            return self._client
        return httpx.AsyncClient(timeout=30)

    async def query_metrics(
        self,
        query: str,
        provider: str = "prometheus",
        start: Optional[float] = None,
        end: Optional[float] = None,
        step: str = "60s",
    ) -> dict:
        provider = (provider or "prometheus").lower()
        if provider == "prometheus":
            return await self._prometheus(query, start, end, step)
        if provider == "datadog":
            return await self._datadog(query, start, end)
        if provider in ("newrelic", "new_relic"):
            return await self._newrelic(query)
        if provider == "grafana":
            return await self._grafana_prometheus(query)
        return {"error": f"Unknown metrics provider {provider!r}"}

    async def evaluate_slo(
        self,
        good_query: str,
        total_query: str,
        objective: float = 0.999,
        provider: str = "prometheus",
        window: str = "30d",
    ) -> dict:
        if not 0 < objective < 1:
            return {"error": "SLO objective must be between 0 and 1 (e.g. 0.999)"}
        good = await self.query_metrics(good_query, provider=provider)
        total = await self.query_metrics(total_query, provider=provider)
        if good.get("error"):
            return good
        if total.get("error"):
            return total
        good_v = _scalar(good)
        total_v = _scalar(total)
        if total_v is None or total_v <= 0 or good_v is None:
            return {
                "error": "Could not compute SLO — missing or zero total samples",
                "good": good,
                "total": total,
            }
        ratio = good_v / total_v
        budget_total = 1.0 - objective
        consumed = max(0.0, (objective - ratio) / budget_total) if budget_total else 0.0
        remaining = max(0.0, 1.0 - consumed)
        burning = ratio < objective
        return {
            "success": True,
            "window": window,
            "objective": objective,
            "availability": ratio,
            "error_budget_remaining": remaining,
            "error_budget_consumed": consumed,
            "burning": burning,
            "good": good_v,
            "total": total_v,
            "message": (
                f"SLO {objective:.4%} availability={ratio:.4%} "
                f"error budget remaining={remaining:.1%}"
            ),
        }

    async def capacity_check(
        self,
        cpu_query: Optional[str] = None,
        memory_query: Optional[str] = None,
        disk_query: Optional[str] = None,
        provider: str = "prometheus",
        cpu_threshold: float = 80.0,
        memory_threshold: float = 85.0,
        disk_threshold: float = 80.0,
    ) -> dict:
        cpu_query = cpu_query or (
            '100 * (1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m])))'
        )
        memory_query = memory_query or (
            "100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)"
        )
        disk_query = disk_query or (
            '100 * (1 - node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} '
            '/ node_filesystem_size_bytes{fstype!~"tmpfs|overlay"})'
        )
        results = {}
        alerts = []
        for name, query, threshold in (
            ("cpu_pct", cpu_query, cpu_threshold),
            ("memory_pct", memory_query, memory_threshold),
            ("disk_pct", disk_query, disk_threshold),
        ):
            payload = await self.query_metrics(query, provider=provider)
            value = _scalar(payload)
            results[name] = {"value": value, "raw": payload if payload.get("error") else value}
            if value is not None and value >= threshold:
                alerts.append(f"{name} {value:.1f} >= {threshold}")
        return {
            "success": not any(
                isinstance(results[k]["raw"], dict) and results[k]["raw"].get("error")
                for k in results
            ),
            "capacity": results,
            "alerts": alerts,
            "over_capacity": bool(alerts),
            "message": "; ".join(alerts) if alerts else "Capacity within thresholds",
        }

    async def query_traces(
        self,
        service: str,
        backend: str = "tempo",
        limit: int = 5,
    ) -> dict:
        backend = (backend or "tempo").lower()
        if backend == "tempo":
            base = os.getenv("TEMPO_URL", "").rstrip("/")
            if not base:
                return {"error": "TEMPO_URL not configured"}
            url = f"{base}/api/search"
            params = {"tags": f"service.name={service}", "limit": str(limit)}
            return await self._get_json(url, params=params)
        if backend == "jaeger":
            base = os.getenv("JAEGER_URL", "").rstrip("/")
            if not base:
                return {"error": "JAEGER_URL not configured"}
            url = f"{base}/api/traces"
            params = {"service": service, "limit": str(limit)}
            return await self._get_json(url, params=params)
        if backend == "datadog":
            return await self._datadog_traces(service, limit)
        return {"error": f"Unknown trace backend {backend!r}"}

    async def run_synthetic(
        self,
        url: str,
        expect_status: int = 200,
        timeout_seconds: float = 10.0,
    ) -> dict:
        if not url.startswith(("http://", "https://")):
            return {"error": "Synthetic URL must be http(s)"}
        started = time.perf_counter()
        owns = self._client is None
        client = await self._http()
        try:
            resp = await client.get(url, timeout=timeout_seconds, follow_redirects=True)
        except Exception as e:
            return {
                "success": False,
                "url": url,
                "error": str(e),
                "latency_ms": (time.perf_counter() - started) * 1000,
            }
        finally:
            if owns and self._client is None:
                await client.aclose()
        latency = (time.perf_counter() - started) * 1000
        ok = resp.status_code == expect_status
        return {
            "success": ok,
            "url": url,
            "status_code": resp.status_code,
            "expect_status": expect_status,
            "latency_ms": round(latency, 2),
            "message": "synthetic ok" if ok else f"synthetic failed HTTP {resp.status_code}",
        }

    async def get_oncall_roster(self, schedule_id: Optional[str] = None) -> dict:
        token = os.getenv("PAGERDUTY_TOKEN", "")
        if not token:
            return {"error": "PAGERDUTY_TOKEN not configured"}
        base = os.getenv("PAGERDUTY_URL", "https://api.pagerduty.com").rstrip("/")
        params = {"limit": 25}
        if schedule_id or os.getenv("PAGERDUTY_SCHEDULE_ID"):
            params["schedule_ids[]"] = schedule_id or os.getenv("PAGERDUTY_SCHEDULE_ID")
        headers = {
            "Authorization": f"Token token={token}",
            "Accept": "application/vnd.pagerduty+json;version=2",
        }
        payload = await self._get_json(f"{base}/oncalls", params=params, headers=headers)
        if payload.get("error") and not payload.get("oncalls"):
            return payload
        people = []
        for item in payload.get("oncalls") or []:
            user = item.get("user") or {}
            people.append(
                {
                    "name": user.get("summary"),
                    "id": user.get("id"),
                    "html_url": user.get("html_url"),
                    "escalation_level": item.get("escalation_level"),
                    "schedule": (item.get("schedule") or {}).get("summary"),
                }
            )
        return {
            "success": True,
            "oncalls": people,
            "incident_commander": people[0] if people else None,
            "message": (
                f"On-call: {people[0]['name']}" if people else "No one currently on-call"
            ),
        }

    async def assign_incident_commander(self, schedule_id: Optional[str] = None) -> dict:
        roster = await self.get_oncall_roster(schedule_id)
        if roster.get("error"):
            return roster
        ic = roster.get("incident_commander")
        if not ic:
            return {
                "success": False,
                "alerted": True,
                "message": "No on-call user to assign as incident commander",
            }
        return {
            "success": True,
            "role": "incident_commander",
            "commander": ic,
            "message": f"Incident commander is {ic.get('name')} (current on-call)",
        }

    async def update_status_page(
        self,
        name: str,
        body: str,
        status: str = "investigating",
        impact: str = "minor",
    ) -> dict:
        if is_emergency_stop_active():
            return emergency_stop_block("Status page updates disabled during emergency stop.")
        page_id = os.getenv("STATUSPAGE_PAGE_ID", "")
        token = os.getenv("STATUSPAGE_API_KEY", "")
        if not page_id or not token:
            return {"error": "STATUSPAGE_PAGE_ID and STATUSPAGE_API_KEY are required"}
        allowed = {
            "investigating",
            "identified",
            "monitoring",
            "resolved",
            "scheduled",
        }
        if status not in allowed:
            return {"error": f"Invalid status {status!r}. Use: {sorted(allowed)}"}
        url = f"https://api.statuspage.io/v1/pages/{page_id}/incidents"
        headers = {"Authorization": f"OAuth {token}", "Content-Type": "application/json"}
        owns = self._client is None
        client = await self._http()
        try:
            resp = await client.post(
                url,
                headers=headers,
                json={
                    "incident": {
                        "name": name[:255],
                        "status": status,
                        "impact_override": impact,
                        "body": body[:1400],
                    }
                },
            )
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns and self._client is None:
                await client.aclose()
        if resp.status_code not in (200, 201):
            return {"error": f"Statuspage error {resp.status_code}: {resp.text}"}
        data = resp.json()
        return {
            "success": True,
            "incident_id": data.get("id"),
            "shortlink": data.get("shortlink") or data.get("url"),
            "status": data.get("status"),
            "message": f"Status page incident {status}",
        }

    async def _prometheus(self, query, start, end, step) -> dict:
        base = os.getenv("PROMETHEUS_URL", "").rstrip("/")
        if not base:
            return {"error": "PROMETHEUS_URL not configured"}
        headers = _bearer("PROMETHEUS_TOKEN")
        if start is not None and end is not None:
            url = urljoin(base + "/", "api/v1/query_range")
            params = {"query": query, "start": start, "end": end, "step": step}
        else:
            url = urljoin(base + "/", "api/v1/query")
            params = {"query": query}
        payload = await self._get_json(url, params=params, headers=headers or None)
        if payload.get("status") == "success" or payload.get("data"):
            return {"success": True, "provider": "prometheus", "data": payload.get("data", payload)}
        return payload if payload.get("error") else {"error": "Prometheus query failed", "raw": payload}

    async def _grafana_prometheus(self, query: str) -> dict:
        base = os.getenv("GRAFANA_URL", "").rstrip("/")
        if not base:
            return {"error": "GRAFANA_URL not configured"}
        uid = os.getenv("GRAFANA_DATASOURCE_UID", "prometheus")
        url = f"{base}/api/datasources/proxy/uid/{uid}/api/v1/query"
        headers = _bearer("GRAFANA_TOKEN")
        payload = await self._get_json(url, params={"query": query}, headers=headers or None)
        if payload.get("status") == "success" or payload.get("data"):
            return {"success": True, "provider": "grafana", "data": payload.get("data", payload)}
        return payload if payload.get("error") else {"error": "Grafana query failed", "raw": payload}

    async def _datadog(self, query: str, start, end) -> dict:
        api_key = os.getenv("DATADOG_API_KEY", "")
        app_key = os.getenv("DATADOG_APP_KEY", "")
        if not api_key or not app_key:
            return {"error": "DATADOG_API_KEY and DATADOG_APP_KEY are required"}
        site = os.getenv("DATADOG_SITE", "datadoghq.com")
        now = int(time.time())
        params = {
            "query": query,
            "from": int(start) if start is not None else now - 300,
            "to": int(end) if end is not None else now,
        }
        url = f"https://api.{site}/api/v1/query"
        headers = {"DD-API-KEY": api_key, "DD-APPLICATION-KEY": app_key}
        payload = await self._get_json(url, params=params, headers=headers)
        if payload.get("error") and "series" not in payload:
            return payload
        return {"success": True, "provider": "datadog", "data": payload}

    async def _datadog_traces(self, service: str, limit: int) -> dict:
        api_key = os.getenv("DATADOG_API_KEY", "")
        app_key = os.getenv("DATADOG_APP_KEY", "")
        if not api_key or not app_key:
            return {"error": "DATADOG_API_KEY and DATADOG_APP_KEY are required"}
        site = os.getenv("DATADOG_SITE", "datadoghq.com")
        url = f"https://api.{site}/api/v2/spans/events/search"
        headers = {
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "Content-Type": "application/json",
        }
        owns = self._client is None
        client = await self._http()
        try:
            resp = await client.post(
                url,
                headers=headers,
                json={
                    "data": {
                        "type": "search_request",
                        "attributes": {
                            "filter": {"query": f"service:{service}"},
                            "page": {"limit": limit},
                        },
                    }
                },
            )
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns and self._client is None:
                await client.aclose()
        if resp.status_code not in (200, 201):
            return {"error": f"Datadog traces {resp.status_code}: {resp.text}"}
        return {"success": True, "backend": "datadog", "data": resp.json()}

    async def _newrelic(self, nrql: str) -> dict:
        key = os.getenv("NEW_RELIC_API_KEY", "")
        account = os.getenv("NEW_RELIC_ACCOUNT_ID", "")
        if not key or not account:
            return {"error": "NEW_RELIC_API_KEY and NEW_RELIC_ACCOUNT_ID are required"}
        graphql = {
            "query": (
                "query($id: Int!, $nrql: Nrql!) { actor { account(id: $id) "
                "{ nrql(query: $nrql) { results } } } }"
            ),
            "variables": {"id": int(account), "nrql": nrql},
        }
        owns = self._client is None
        client = await self._http()
        try:
            resp = await client.post(
                "https://api.newrelic.com/graphql",
                headers={"API-Key": key, "Content-Type": "application/json"},
                json=graphql,
            )
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns and self._client is None:
                await client.aclose()
        if resp.status_code != 200:
            return {"error": f"New Relic {resp.status_code}: {resp.text}"}
        data = resp.json()
        if data.get("errors"):
            return {"error": data["errors"]}
        results = (
            ((data.get("data") or {}).get("actor") or {})
            .get("account", {})
            .get("nrql", {})
            .get("results")
        )
        return {"success": True, "provider": "newrelic", "data": results}

    async def _get_json(self, url, params=None, headers=None) -> dict:
        owns = self._client is None
        client = await self._http()
        try:
            resp = await client.get(url, params=params, headers=headers)
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns and self._client is None:
                await client.aclose()
        if resp.status_code != 200:
            return {"error": f"{resp.status_code} from {url}: {resp.text[:500]}"}
        try:
            return resp.json()
        except Exception:
            return {"error": "Non-JSON response", "text": resp.text[:500]}


def _bearer(env_name: str) -> dict:
    token = os.getenv(env_name, "").strip()
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def _scalar(payload: dict) -> Optional[float]:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data") or payload
    result = data.get("result") if isinstance(data, dict) else None
    if isinstance(result, list) and result:
        first = result[0]
        value = first.get("value") or first.get("values")
        if isinstance(value, list) and len(value) >= 2:
            try:
                return float(value[1] if not isinstance(value[1], list) else value[1][-1])
            except (TypeError, ValueError):
                return None
        if isinstance(value, list) and value and isinstance(value[0], list):
            try:
                return float(value[-1][1])
            except (TypeError, ValueError, IndexError):
                return None
    series = payload.get("series") or (data.get("series") if isinstance(data, dict) else None)
    if isinstance(series, list) and series:
        pointlist = series[0].get("pointlist") or []
        if pointlist:
            try:
                return float(pointlist[-1][1])
            except (TypeError, ValueError, IndexError):
                return None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        for key in ("count", "value", "score"):
            if key in data[0]:
                try:
                    return float(data[0][key])
                except (TypeError, ValueError):
                    continue
    return None
