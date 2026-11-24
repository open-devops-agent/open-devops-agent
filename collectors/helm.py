"""
Helm Context Collector
Gathers Helm release status, history, values, and manifest for diagnosis.
"""
import asyncio
import json
import os
from typing import Optional

import structlog
from services.org_env import subprocess_env

log = structlog.get_logger()


class HelmCollector:
    """Read-only Helm diagnostics via helm CLI."""

    async def _run(self, command: str, timeout: int = 30) -> dict:
        helm_bin = os.getenv("HELM_BIN", "helm")
        full_cmd = f"{helm_bin} {command}"
        log.info("Helm command", command=full_cmd)
        try:
            proc = await asyncio.create_subprocess_shell(
                full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=subprocess_env(),
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode().strip()
            err = stderr.decode().strip()
            if proc.returncode != 0:
                return {"error": err or out or f"exit code {proc.returncode}", "command": full_cmd}
            return {"stdout": out, "stderr": err, "command": full_cmd}
        except asyncio.TimeoutError:
            return {"error": f"timeout: {full_cmd}"}
        except FileNotFoundError:
            return {"error": "helm CLI not found. Install helm or set HELM_BIN."}
        except Exception as e:
            return {"error": str(e)}

    async def collect(
        self,
        release_name: str,
        namespace: str = "default",
    ) -> dict:
        """Full snapshot for a Helm release."""
        ns_flag = f"-n {namespace}"
        result = {
            "release": release_name,
            "namespace": namespace,
        }

        status = await self._run(f"status {release_name} {ns_flag}")
        result["status"] = status.get("stdout") or status.get("error")

        history = await self._run(f"history {release_name} {ns_flag} --max 10")
        result["history"] = history.get("stdout") or history.get("error")

        values = await self._run(f"get values {release_name} {ns_flag}")
        result["values"] = values.get("stdout") or values.get("error")

        manifest = await self._run(f"get manifest {release_name} {ns_flag}")
        if manifest.get("stdout"):
            # Truncate very large manifests
            text = manifest["stdout"]
            result["manifest_preview"] = text[:8000] + ("..." if len(text) > 8000 else "")
        else:
            result["manifest_preview"] = manifest.get("error")

        hooks = await self._run(f"get hooks {release_name} {ns_flag}")
        result["hooks"] = hooks.get("stdout") or hooks.get("error")

        if status.get("error"):
            result["error"] = status["error"]

        return result

    async def list_releases(self, namespace: Optional[str] = None) -> dict:
        """List releases in a namespace or all namespaces."""
        if namespace:
            cmd = f"list -n {namespace} -o json"
        else:
            cmd = "list -A -o json"
        raw = await self._run(cmd)
        if raw.get("error"):
            return raw
        try:
            releases = json.loads(raw.get("stdout") or "[]")
            return {"releases": releases, "count": len(releases)}
        except json.JSONDecodeError:
            return {"releases_raw": raw.get("stdout"), "parse_error": True}
