"""
Safe Command Executor
Enforces command whitelists and human approval gates before running anything.
"""

import asyncio
import base64
import os
from typing import Optional

import structlog
from services.org_env import subprocess_env

from services.approval_store import APPROVAL_REFERENCE_PREFIX, CommandApprovalStore
from tools.safety import (
    emergency_stop_block,
    is_emergency_stop_active,
    requires_configured_approval,
)
from tools.ssh_utils import build_ssh_argv, build_ssh_command

log = structlog.get_logger()


# Commands that can always auto-run (read-only or safe restarts)
ALWAYS_SAFE = [
    "kubectl get",
    "kubectl describe",
    "kubectl logs",
    "kubectl rollout status",
    "kubectl rollout history",
    "kubectl top",
    "kubectl version",
    "df ",
    "df -",
    "free ",
    "uptime",
    "ps aux",
    "ss -",
    "journalctl",
    "systemctl status",
    "systemctl is-active",
    "nginx -t",
    "docker ps",
    "docker images",
    "docker logs",
    "docker inspect",
    "docker stats",
]

# Commands allowed when AUTO_APPLY=true
ALLOWED_WITH_AUTO_APPLY = [
    "kubectl rollout restart",
    "kubectl scale",
    "kubectl apply",
    "kubectl rollout undo",
    "systemctl restart",
    "systemctl reload",
    "nginx -s reload",
    "nginx -s reopen",
    "docker restart",
    "docker start",
    "docker stop",
]

# Commands that ALWAYS need human approval
ALWAYS_REQUIRE_APPROVAL = [
    "kubectl delete",
    "kubectl exec",
    "rm ",
    "rm -",
    "dd ",
    "mkfs",
    "fdisk",
    "kill -9",
    "shutdown",
    "reboot",
]


class SafeExecutor:
    def __init__(self):
        self.auto_apply = os.getenv("AUTO_APPLY", "false").lower() == "true"

    def _classify(self, command: str) -> str:
        """Returns 'safe', 'allowed', 'requires_approval', or 'blocked'."""
        cmd = command.strip().lower()

        if requires_configured_approval(command):
            return "requires_approval"

        for blocked in ALWAYS_REQUIRE_APPROVAL:
            if blocked in cmd:
                return "requires_approval"

        for safe in ALWAYS_SAFE:
            if cmd.startswith(safe.lower()) or safe.lower() in cmd:
                return "safe"

        for allowed in ALLOWED_WITH_AUTO_APPLY:
            if cmd.startswith(allowed.lower()):
                return "allowed"

        return "requires_approval"

    async def run(self, command: str, host: Optional[str] = None) -> dict:
        """Run a command, bypassing safety for internal approved calls."""
        if is_emergency_stop_active():
            return emergency_stop_block(
                "Agent emergency stop is active. Approved actions cannot run."
            )
        if command.startswith(APPROVAL_REFERENCE_PREFIX):
            # Resolve in the approving process so memory-backed storage works,
            # too. The retained operation already binds its target host.
            try:
                retained = None if host else CommandApprovalStore().resolve(command)
            except RuntimeError:
                retained = None
            if retained is None:
                return {
                    "blocked": True,
                    "success": False,
                    "returncode": 1,
                    "command": command,
                    "message": "Approval reference is unavailable or does not match this organisation/target.",
                }
            command, host = retained, None
        return await self._exec(command, host)

    async def run_safe(self, command: str, host: Optional[str] = None) -> dict:
        """Run with full safety checks."""
        classification = self._classify(command)

        if is_emergency_stop_active() and classification != "safe":
            return emergency_stop_block()

        if classification == "requires_approval":
            if not self.auto_apply:
                encoded = base64.b64encode(command.encode()).decode()
                return {
                    "blocked": True,
                    "requires_approval": True,
                    "command": command,
                    "approval_payload": encoded,
                    "message": f"Command requires human approval: `{command}`",
                }

        if classification == "allowed" and not self.auto_apply:
            encoded = base64.b64encode(command.encode()).decode()
            return {
                "blocked": True,
                "requires_approval": True,
                "command": command,
                "approval_payload": encoded,
                "message": f"AUTO_APPLY=false. Approval needed for: `{command}`",
            }

        return await self._exec(command, host)

    async def _exec(self, command: str, host: Optional[str] = None) -> dict:
        """Execute the command."""
        run_argv = None
        if host and host not in ("localhost", "127.0.0.1", ""):
            run_argv = build_ssh_argv(host, command)
            display_command = build_ssh_command(host, command)
        else:
            display_command = command

        log.info("Executing command", command=display_command)

        try:
            if run_argv:
                proc = await asyncio.create_subprocess_exec(
                    *run_argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=subprocess_env(),
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=subprocess_env(),
                )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout.decode().strip()[-3000:],  # Truncate
                "stderr": stderr.decode().strip()[-1000:],
                "command": display_command,
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": "Command timed out after 60s",
                "command": display_command,
            }
        except Exception as e:
            return {"success": False, "error": str(e), "command": display_command}
