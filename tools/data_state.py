"""
Data-store diagnostics: databases, snapshots/DR, Kafka, Elasticsearch, Redis.

Mutating restore/failover is never auto-applied. Collection stays behind
ENABLE_DATABASE_COLLECTION / ENABLE_DATA_STORE_COLLECTION.
"""
from __future__ import annotations

import os
import socket
import time
from typing import Optional

import httpx
import structlog

from collectors.database_policy import is_database_collection_enabled
from tools.safety import emergency_stop_block, is_emergency_stop_active

log = structlog.get_logger()

_BLOCKED_SQL = (
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "truncate",
    "create",
    "grant",
    "revoke",
    "vacuum full",
    "failover",
)


def data_store_collection_enabled() -> bool:
    raw = os.getenv("ENABLE_DATA_STORE_COLLECTION", "")
    if raw:
        return raw.lower() in ("true", "1", "yes")
    return is_database_collection_enabled()


class DataStateTools:
    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self._client = client

    def _db_guard(self) -> Optional[dict]:
        if is_database_collection_enabled():
            return None
        return {
            "blocked": True,
            "error": "Database collection is disabled",
            "enable_if_allowed": "Set ENABLE_DATABASE_COLLECTION=true after security review",
        }

    def _store_guard(self) -> Optional[dict]:
        if data_store_collection_enabled():
            return None
        return {
            "blocked": True,
            "error": "Data-store collection is disabled",
            "enable_if_allowed": "Set ENABLE_DATA_STORE_COLLECTION=true (or ENABLE_DATABASE_COLLECTION=true)",
        }

    async def check_database_health(
        self,
        resource_type: str = "rds",
        resource_id: Optional[str] = None,
        query: str = "SELECT 1",
    ) -> dict:
        blocked = self._db_guard()
        if blocked:
            return blocked
        sql = (query or "SELECT 1").strip()
        if not _is_readonly_sql(sql):
            return {
                "blocked": True,
                "alerted": True,
                "message": "Only read-only SQL (SELECT/SHOW/pg_is_in_recovery) is allowed",
            }
        dsn = os.getenv("DATABASE_URL", "")
        if dsn:
            ping = await _sql_ping(dsn, sql)
            if ping.get("success") is not None:
                return ping
        if resource_type.lower() == "rds" and resource_id:
            from collectors.aws import AWSCollector

            return await AWSCollector().collect("rds", resource_id)
        if resource_type.lower() in ("cloud_sql", "sql") and resource_id:
            return {
                "success": True,
                "message": "Use get_cloud_resource for Cloud SQL / Azure SQL status; no app SQL run",
                "resource_id": resource_id,
            }
        return {
            "success": False,
            "message": "Set DATABASE_URL for SELECT 1, or pass resource_type+resource_id for cloud describe",
        }

    async def list_snapshots(self, resource_id: str, engine: str = "rds") -> dict:
        blocked = self._db_guard()
        if blocked:
            return blocked
        try:
            import boto3

            region = os.getenv("AWS_REGION", "us-east-1")
            if engine == "rds":
                client = boto3.client("rds", region_name=region)
                resp = client.describe_db_snapshots(
                    DBInstanceIdentifier=resource_id, MaxRecords=20
                )
                snaps = [
                    {
                        "id": s.get("DBSnapshotIdentifier"),
                        "status": s.get("Status"),
                        "created": str(s.get("SnapshotCreateTime")),
                        "type": s.get("SnapshotType"),
                    }
                    for s in resp.get("DBSnapshots", [])
                ]
                return {"success": True, "snapshots": snaps, "count": len(snaps)}
            if engine == "ebs":
                client = boto3.client("ec2", region_name=region)
                resp = client.describe_snapshots(
                    Filters=[{"Name": "volume-id", "Values": [resource_id]}],
                    MaxResults=20,
                    OwnerIds=["self"],
                )
                snaps = [
                    {
                        "id": s.get("SnapshotId"),
                        "state": s.get("State"),
                        "start": str(s.get("StartTime")),
                    }
                    for s in resp.get("Snapshots", [])
                ]
                return {"success": True, "snapshots": snaps, "count": len(snaps)}
            return {"error": f"Unsupported snapshot engine {engine}"}
        except ImportError:
            return {"error": "boto3 not installed"}
        except Exception as e:
            return {"error": str(e)}

    async def create_snapshot(
        self, resource_id: str, snapshot_id: Optional[str] = None, engine: str = "rds"
    ) -> dict:
        blocked = self._db_guard()
        if blocked:
            return blocked
        if is_emergency_stop_active():
            return emergency_stop_block("Snapshot create disabled during emergency stop.")
        name = snapshot_id or f"agent-{resource_id}-{int(time.time())}"[:60]
        try:
            import boto3

            region = os.getenv("AWS_REGION", "us-east-1")
            if engine == "rds":
                client = boto3.client("rds", region_name=region)
                resp = client.create_db_snapshot(
                    DBSnapshotIdentifier=name, DBInstanceIdentifier=resource_id
                )
                snap = resp.get("DBSnapshot") or {}
                return {
                    "success": True,
                    "snapshot_id": snap.get("DBSnapshotIdentifier", name),
                    "status": snap.get("Status"),
                    "message": f"RDS snapshot {name} creating (additive, no restore)",
                }
            if engine == "ebs":
                client = boto3.client("ec2", region_name=region)
                resp = client.create_snapshot(VolumeId=resource_id, Description=name)
                return {
                    "success": True,
                    "snapshot_id": resp.get("SnapshotId"),
                    "state": resp.get("State"),
                    "message": f"EBS snapshot of {resource_id} creating",
                }
            return {"error": f"Unsupported snapshot engine {engine}"}
        except ImportError:
            return {"error": "boto3 not installed"}
        except Exception as e:
            return {"error": str(e)}

    async def restore_from_snapshot(self, snapshot_id: str, target_id: str) -> dict:
        return {
            "success": False,
            "blocked": True,
            "requires_approval": True,
            "alerted": True,
            "message": (
                f"Restore of snapshot {snapshot_id} onto {target_id} is never auto-applied. "
                "A DBA must restore. Agent will only list/create snapshots."
            ),
        }

    async def dr_readiness_check(
        self, resource_id: str, resource_type: str = "rds", max_snapshot_age_hours: int = 24
    ) -> dict:
        blocked = self._db_guard()
        if blocked:
            return blocked
        from collectors.aws import AWSCollector

        describe = await AWSCollector().collect(resource_type, resource_id)
        snaps = await self.list_snapshots(
            resource_id, engine="rds" if resource_type == "rds" else "ebs"
        )
        alerts = []
        if describe.get("error"):
            alerts.append(describe["error"])
        if resource_type == "rds" and describe.get("multi_az") is False:
            alerts.append("RDS is not Multi-AZ")
        count = snaps.get("count") if snaps.get("success") else 0
        if not count:
            alerts.append("No snapshots found")
        return {
            "success": not alerts,
            "resource": describe,
            "snapshots": snaps,
            "alerts": alerts,
            "drill": "read-only — no failover executed",
            "message": "DR ready" if not alerts else "; ".join(alerts),
        }

    async def kafka_health(self, bootstrap: Optional[str] = None) -> dict:
        blocked = self._store_guard()
        if blocked:
            return blocked
        rest = os.getenv("KAFKA_REST_URL", "").rstrip("/")
        if rest:
            payload = await self._http_get(f"{rest}/topics")
            if isinstance(payload, dict) and payload.get("error"):
                return payload
            return {"success": True, "topics": payload.get("value", payload), "message": "Kafka REST reachable"}
        hostport = bootstrap or os.getenv("KAFKA_BOOTSTRAP", "")
        if not hostport:
            return {"error": "KAFKA_REST_URL or KAFKA_BOOTSTRAP is required"}
        host, _, port = hostport.partition(":")
        ok, err = _tcp_check(host, int(port or "9092"))
        return {
            "success": ok,
            "bootstrap": hostport,
            "error": err,
            "message": "Kafka broker TCP open" if ok else f"Kafka TCP failed: {err}",
        }

    async def elasticsearch_health(self, url: Optional[str] = None) -> dict:
        blocked = self._store_guard()
        if blocked:
            return blocked
        base = (url or os.getenv("ELASTICSEARCH_URL", "")).rstrip("/")
        if not base:
            return {"error": "ELASTICSEARCH_URL not configured"}
        headers = {}
        token = os.getenv("ELASTICSEARCH_API_KEY", "")
        if token:
            headers["Authorization"] = f"ApiKey {token}"
        payload = await self._http_get(f"{base}/_cluster/health", headers=headers)
        if payload.get("error") and "status" not in payload:
            return payload
        status = payload.get("status")
        return {
            "success": status in ("green", "yellow"),
            "status": status,
            "data": payload,
            "alerted": status == "red",
            "message": f"Elasticsearch cluster {status}",
        }

    async def redis_health(self, host: Optional[str] = None, port: int = 6379) -> dict:
        blocked = self._db_guard()
        if blocked:
            return blocked
        target = host or os.getenv("REDIS_HOST", "")
        port = int(os.getenv("REDIS_PORT", str(port)) or port)
        if not target:
            return {"error": "REDIS_HOST not configured"}
        try:
            with socket.create_connection((target, port), timeout=5) as sock:
                sock.sendall(b"PING\r\n")
                reply = sock.recv(32).decode("utf-8", errors="replace")
            ok = "+PONG" in reply
            return {
                "success": ok,
                "host": target,
                "port": port,
                "reply": reply.strip(),
                "message": "Redis PONG" if ok else f"Unexpected Redis reply: {reply!r}",
            }
        except Exception as e:
            return {"success": False, "error": str(e), "host": target, "port": port}

    async def _http_get(self, url: str, headers: Optional[dict] = None) -> dict:
        owns = self._client is None
        client = self._client or httpx.AsyncClient(timeout=30)
        try:
            resp = await client.get(url, headers=headers)
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns and self._client is None:
                await client.aclose()
        if resp.status_code != 200:
            return {"error": f"{resp.status_code}: {resp.text[:400]}"}
        try:
            data = resp.json()
        except Exception:
            return {"text": resp.text[:400]}
        return data if isinstance(data, dict) else {"value": data}


def _is_readonly_sql(sql: str) -> bool:
    lowered = sql.lower().rstrip(";")
    if any(tok in lowered for tok in _BLOCKED_SQL):
        return False
    return lowered.startswith(("select", "show", "explain")) or "pg_is_in_recovery" in lowered


async def _sql_ping(dsn: str, sql: str) -> dict:
    # Optional drivers; never log the DSN.
    try:
        if dsn.startswith("postgres"):
            import asyncpg

            conn = await asyncpg.connect(dsn, timeout=5)
            try:
                value = await conn.fetchval(sql)
            finally:
                await conn.close()
            return {"success": True, "engine": "postgres", "result": str(value)}
        if dsn.startswith("mysql"):
            return {
                "success": False,
                "message": "MySQL DSN present — use cloud describe or a DBA; no mysql driver bundled",
            }
    except ImportError:
        return {"success": False, "message": "SQL driver not installed; used cloud describe instead"}
    except Exception as e:
        return {"success": False, "error": "database ping failed", "detail": str(e)}
    return {"success": False, "message": "Unsupported DATABASE_URL scheme"}


def _tcp_check(host: str, port: int) -> tuple[bool, Optional[str]]:
    try:
        with socket.create_connection((host, port), timeout=5):
            return True, None
    except Exception as e:
        return False, str(e)
