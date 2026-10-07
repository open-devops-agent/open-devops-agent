"""
Apply unattended security updates only. Never dist-upgrade or reboot.
"""
from __future__ import annotations

from typing import Callable, Optional

from tools.safety import emergency_stop_block, is_emergency_stop_active


class SecurityUpdates:
    def __init__(self, runner: Optional[Callable] = None):
        self._runner = runner

    async def _run(self, command: str, host: Optional[str] = None) -> dict:
        if self._runner:
            return await self._runner(command, host)
        from tools.executor import SafeExecutor

        return await SafeExecutor().run(command, host=host)

    async def apply(self, host: Optional[str] = None, dry_run: bool = True) -> dict:
        if is_emergency_stop_active() and not dry_run:
            return emergency_stop_block("Agent emergency stop is active. Security updates are disabled.")
        command = (
            "unattended-upgrade --dry-run 2>/dev/null || apt-get -s upgrade"
            if dry_run
            else "unattended-upgrade 2>/dev/null || apt-get -y upgrade --only-upgrade"
        )
        result = await self._run(command, host)
        text = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
        needs_reboot = "restart" in text.lower() and "kernel" in text.lower()
        return {
            "success": bool(result.get("success")),
            "dry_run": dry_run,
            "command": command,
            "result": result,
            "needs_reboot": needs_reboot,
            "alerted": needs_reboot,
            "alerts": (
                ["Kernel or service restart required after security updates — reboot is NOT performed automatically."]
                if needs_reboot
                else []
            ),
            "message": (
                "Security update dry-run complete"
                if dry_run
                else ("Security updates applied" if result.get("success") else "Security updates failed")
            ),
        }
