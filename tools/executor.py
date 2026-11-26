"""
Safe Command Executor
Enforces command whitelists and human approval gates before running anything.
"""

import asyncio
import base64
import os
import re
import signal
from typing import List, Optional, Tuple

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


# Irreversible destruction: never run, not even with approval or AUTO_APPLY.
# Matched on the lower-cased command; "(?=\s|$)" keeps names such as a pod
# called "delete-me" from matching.
_ARG = r"[^|;&\n]{0,200}?"
NEVER_ALLOWED: List[Tuple[re.Pattern, str]] = [
    (re.compile(rf"\bkubectl\b{_ARG}\s(?:delete|drain)(?=\s|$)"), "Kubernetes delete/drain"),
    (re.compile(rf"\bhelm\b{_ARG}\s(?:uninstall|delete|del)(?=\s|$)"), "Helm uninstall"),
    (re.compile(rf"\brm\b{_ARG}(?:\s-[a-z]*r[a-z]*(?=\s|$)|\s--recursive\b|--no-preserve-root)"), "recursive delete"),
    (re.compile(rf"\brm\b{_ARG}\s/\*?(?=\s|$)"), "delete at filesystem root"),
    (re.compile(r"\bmkfs(?:\.[a-z0-9]+)?(?=\s|$)|\bwipefs\b"), "filesystem format/wipe"),
    (re.compile(rf"\bdd\b{_ARG}\bof=/dev/"), "raw write to a device"),
    (re.compile(r">\s{0,5}/dev/(?:sd|nvme|xvd|vd|hd)[a-z0-9]*"), "raw write to a device"),
    (re.compile(r"\bdrop\s{1,5}(?:database|schema|table)\b|\btruncate\s{1,5}table\b|\bdelete\s{1,5}from\b"), "destructive SQL"),
    (re.compile(rf"\baws\b{_ARG}\s(?:delete|terminate|deregister)-[a-z0-9-]+"), "AWS delete/terminate"),
    (re.compile(rf"\b(?:gcloud|az)\b{_ARG}\sdelete(?=\s|$)"), "GCP/Azure delete"),
    (re.compile(rf"\bterraform\b{_ARG}\s(?:destroy(?=\s|$)|-destroy\b)"), "Terraform destroy"),
    (re.compile(r"--replicas(?:=|\s{1,5})0(?=\s|$)"), "scale to zero"),
    (re.compile(r"\bdocker\s{1,5}(?:volume\s{1,5}(?:rm|prune)|system\s{1,5}prune)\b"), "Docker volume/system prune"),
]

# Reading Secret *values* (#191): "kubectl get secret(s) ... -o yaml|json|jsonpath|..."
# returns base64 data that would flow to the LLM, logs and audit storage. Listing
# names ("kubectl get secrets", "-o name", "-o wide") and "kubectl describe secret"
# (sizes only) stay safe.
_SECRET_RESOURCE = r"(?:[a-z0-9.,/-]*,)?secrets?(?:\.v1)?(?:/[a-z0-9.-]+)?(?:,[a-z0-9.,/-]*)?"
_VALUE_OUTPUT = (
    r"(?:(?:-o\s*=?\s*|--output(?:=|\s+))['\"]?(?:ya?ml|json|jsonpath|go-template|template|custom-columns)"
    r"|--template\b)"
)
SECRET_READ = re.compile(
    rf"\bkubectl\b{_ARG}\sget\s{_ARG}(?<=\s)" + _SECRET_RESOURCE + rf"(?![a-z0-9-])(?=[^|;&\n]*?{_VALUE_OUTPUT})"
)


def reads_secret_values(command: str) -> bool:
    return bool(SECRET_READ.search(command.lower()))


# Shell features that make a command more than one command.
_SUBSTITUTION_OR_REDIRECT = re.compile(r"`|\$\(|<|>")
_COMMAND_SEPARATOR = re.compile(r"&&|\|\||;|\n")
# Read-only filters allowed after a pipe from a safe command.
PIPE_FILTERS = ("grep", "egrep", "head", "tail", "wc", "sort", "uniq", "cut", "jq", "less", "column")

_RANK = {"safe": 0, "allowed": 1, "requires_approval": 2, "blocked": 3}


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def default_timeout() -> int:
    return _int_env("EXECUTOR_TIMEOUT_SEC", 60)


def default_max_output() -> int:
    """Characters of stdout returned to the agent (the model's context), head and tail kept."""
    return _int_env("EXECUTOR_MAX_OUTPUT_CHARS", 4000)


def clip_output(text: str, limit: int) -> str:
    """Keep the start and the end of long output with a marker in between (#206).

    The first lines usually hold the command's header or the first error, the last
    lines the final state; keeping only the tail lost the former.
    """
    if len(text) <= limit:
        return text
    head = limit // 4
    tail = limit - head
    dropped = len(text) - head - tail
    return f"{text[:head]}\n…[truncated {dropped} characters]…\n{text[-tail:]}"


def never_allowed_reason(command: str) -> Optional[str]:
    """Why ``command`` is permanently blocked, or None."""
    cmd = command.lower()
    for pattern, reason in NEVER_ALLOWED:
        if pattern.search(cmd):
            return reason
    return None


class SafeExecutor:
    def __init__(self):
        self.auto_apply = os.getenv("AUTO_APPLY", "false").lower() == "true"

    def _classify(self, command: str) -> str:
        """Returns 'safe', 'allowed', 'requires_approval', or 'blocked'.

        Chained commands (;, &&, ||, newlines) are classified per command and
        the most restrictive wins; after a pipe only read-only filters keep a
        command safe. Substitution and redirection always need approval.
        """
        cmd = command.strip().lower()

        if never_allowed_reason(cmd):
            return "blocked"
        if requires_configured_approval(command):
            return "requires_approval"
        if reads_secret_values(cmd):
            return "requires_approval"
        if _SUBSTITUTION_OR_REDIRECT.search(cmd):
            return "requires_approval"

        worst = "safe"
        for part in _COMMAND_SEPARATOR.split(cmd):
            part = part.strip()
            if not part:
                continue
            level = self._classify_pipeline(part)
            if _RANK[level] > _RANK[worst]:
                worst = level
        return worst

    @staticmethod
    def _classify_single(part: str) -> str:
        for risky in ALWAYS_REQUIRE_APPROVAL:
            if risky in part:
                return "requires_approval"
        for safe in ALWAYS_SAFE:
            if part.startswith(safe.lower()):
                return "safe"
        for allowed in ALLOWED_WITH_AUTO_APPLY:
            if part.startswith(allowed.lower()):
                return "allowed"
        return "requires_approval"

    def _classify_pipeline(self, part: str) -> str:
        stages = [stage.strip() for stage in part.split("|")]
        level = self._classify_single(stages[0])
        for stage in stages[1:]:
            name = stage.split()[0] if stage.split() else ""
            if name not in PIPE_FILTERS:
                return "requires_approval"
        return level

    async def run(
        self,
        command: str,
        host: Optional[str] = None,
        *,
        timeout: Optional[int] = None,
        max_output: Optional[int] = None,
    ) -> dict:
        """Run a command, bypassing safety for internal approved calls.

        ``timeout`` (seconds) and ``max_output`` (characters kept, head and tail)
        default to EXECUTOR_TIMEOUT_SEC / EXECUTOR_MAX_OUTPUT_CHARS; evidence
        capture passes larger values.
        """
        if is_emergency_stop_active():
            return emergency_stop_block(
                "Agent emergency stop is active. Approved actions cannot run."
            )
        reason = None if command.startswith(APPROVAL_REFERENCE_PREFIX) else never_allowed_reason(command)
        if reason:
            # Defence in depth: even an approved or internal call never destroys data.
            return await self._permanently_blocked(command, reason, host)
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
        limits = {k: v for k, v in (("timeout", timeout), ("max_output", max_output)) if v is not None}
        return await self._exec(command, host, **limits)

    async def run_safe(self, command: str, host: Optional[str] = None) -> dict:
        """Run with full safety checks."""
        classification = self._classify(command)

        if classification == "blocked":
            return await self._permanently_blocked(command, never_allowed_reason(command) or "destructive", host)

        if is_emergency_stop_active() and classification != "safe":
            return emergency_stop_block()

        if classification == "requires_approval":
            # Always, whatever AUTO_APPLY says: AUTO_APPLY only covers "allowed".
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

    async def _permanently_blocked(self, command: str, reason: str, host: Optional[str]) -> dict:
        """Refuse a destructive command and alert the team by email (if enabled)."""
        log.warning("Permanently blocked command", reason=reason, command=command, host=host)
        email_sent = False
        try:
            from tools.email_notifier import send_dangerous_operation_alert

            email_sent = bool(
                await asyncio.to_thread(
                    send_dangerous_operation_alert,
                    incident_id="n/a",
                    operation=command,
                    reason=f"Permanently blocked by the agent: {reason}",
                    recommended_commands=[command],
                    context={"host": host or "localhost"},
                    severity="HIGH",
                )
            )
        except Exception as exc:  # alerting must never turn a block into a failure
            log.warning("dangerous_operation_alert_failed", error=str(exc))
        return {
            "blocked": True,
            "permanently_blocked": True,
            "requires_approval": False,
            "success": False,
            "command": command,
            "reason": reason,
            "email_sent": email_sent,
            "message": (
                f"Permanently blocked ({reason}): the agent never runs this, even with approval. "
                "If it is really intended, a human must run it manually."
            ),
        }

    async def _exec(
        self,
        command: str,
        host: Optional[str] = None,
        *,
        timeout: Optional[int] = None,
        max_output: Optional[int] = None,
    ) -> dict:
        """Execute the command."""
        timeout = timeout or default_timeout()
        max_output = max_output or default_max_output()
        proc = None
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
                    start_new_session=True,  # own process group, so a timeout stops children too
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=subprocess_env(),
                    start_new_session=True,  # own process group, so a timeout stops children too
                )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode(errors="replace").strip()
            err = stderr.decode(errors="replace").strip()
            result = {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": clip_output(out, max_output),
                "stderr": clip_output(err, max(1000, max_output // 4)),
                "command": display_command,
            }
            if len(out) > max_output:
                result["stdout_truncated_chars"] = len(out) - max_output
            return result
        except asyncio.TimeoutError:
            # Don't leave the command running in the background.
            if proc is not None and proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass
            return {
                "success": False,
                "error": f"Command timed out after {timeout}s and was stopped",
                "command": display_command,
            }
        except Exception as e:
            return {"success": False, "error": str(e), "command": display_command}
