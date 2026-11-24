"""
Infrastructure-as-Code Tools — read-only Terraform diagnostics (no apply/destroy).
"""
import asyncio
import os
import re
from pathlib import Path
from typing import Optional

import structlog
from services.org_env import subprocess_env

log = structlog.get_logger()

BLOCKED_TERRAFORM = [
    r"\bapply\b",
    r"\bdestroy\b",
    r"\bimport\b",
    r"\btaint\b",
    r"\buntaint\b",
    r"\bforce-unlock\b",
]

ALLOWED_TERRAFORM_SUBCOMMANDS = {
    "validate",
    "plan",
    "fmt",
    "show",
    "state",
    "output",
    "providers",
    "version",
}


class IaCTools:
    """Safe, read-only IaC operations."""

    def __init__(self):
        self.terraform_bin = os.getenv("TERRAFORM_BIN", "terraform")
        self.default_workspace = os.getenv("TERRAFORM_WORKSPACE_DIR", "")

    def _resolve_workspace(self, workspace_path: Optional[str]) -> tuple[Optional[Path], Optional[dict]]:
        path_str = workspace_path or self.default_workspace
        if not path_str:
            return None, {
                "error": "No Terraform workspace path. Set TERRAFORM_WORKSPACE_DIR or pass workspace_path.",
            }
        path = Path(path_str).resolve()
        if not path.is_dir():
            return None, {"error": f"Workspace not found: {path}"}
        return path, None

    def _validate_subcommand(self, subcommand: str, extra_args: str = "") -> Optional[dict]:
        sub = subcommand.strip().lower()
        if sub not in ALLOWED_TERRAFORM_SUBCOMMANDS:
            return {"blocked": True, "error": f"Terraform subcommand not allowed: {subcommand}"}

        combined = f"terraform {subcommand} {extra_args}".lower()
        for pattern in BLOCKED_TERRAFORM:
            if re.search(pattern, combined):
                return {"blocked": True, "error": f"Blocked Terraform operation: {pattern}"}
        return None

    async def _run_in_workspace(self, workspace: Path, command: str, timeout: int = 120) -> dict:
        log.info("Terraform command", cwd=str(workspace), command=command)
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=str(workspace),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=subprocess_env(),
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
                "exit_code": proc.returncode,
                "workspace": str(workspace),
                "command": command,
                "success": proc.returncode == 0,
            }
        except asyncio.TimeoutError:
            return {"error": f"timeout: {command}", "workspace": str(workspace)}
        except FileNotFoundError:
            return {"error": "terraform CLI not found. Install terraform or set TERRAFORM_BIN."}
        except Exception as e:
            return {"error": str(e)}

    async def terraform_validate(self, workspace_path: Optional[str] = None) -> dict:
        workspace, err = self._resolve_workspace(workspace_path)
        if err:
            return err
        blocked = self._validate_subcommand("validate")
        if blocked:
            return blocked
        return await self._run_in_workspace(workspace, f"{self.terraform_bin} validate")

    async def terraform_plan(
        self,
        workspace_path: Optional[str] = None,
        extra_args: str = "-input=false",
    ) -> dict:
        workspace, err = self._resolve_workspace(workspace_path)
        if err:
            return err
        blocked = self._validate_subcommand("plan", extra_args)
        if blocked:
            return blocked
        cmd = f"{self.terraform_bin} plan {extra_args}".strip()
        result = await self._run_in_workspace(workspace, cmd, timeout=180)
        if result.get("stdout"):
            # Truncate huge plans
            out = result["stdout"]
            if len(out) > 12000:
                result["stdout"] = out[:12000] + "\n... (truncated)"
        return result

    async def terraform_state_list(self, workspace_path: Optional[str] = None) -> dict:
        workspace, err = self._resolve_workspace(workspace_path)
        if err:
            return err
        blocked = self._validate_subcommand("state", "list")
        if blocked:
            return blocked
        return await self._run_in_workspace(workspace, f"{self.terraform_bin} state list")
