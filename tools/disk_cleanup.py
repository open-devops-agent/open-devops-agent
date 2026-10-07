"""
Safe disk cleanup: shrink journals and delete stale rotated logs only.

Never deletes production, database, or in-use application data. Anything that
looks important is returned as an alert instead of being removed.
"""
from __future__ import annotations

import os
import re
import shlex
from typing import Callable, List, Optional

import structlog

from tools.disk_policy import classify_cleanup_target, is_safe_stale_log
from tools.safety import emergency_stop_block, is_emergency_stop_active

log = structlog.get_logger()

DEFAULT_LOG_MIN_AGE_DAYS = 14
DEFAULT_JOURNAL_MAX_AGE_DAYS = 7
DEFAULT_JOURNAL_MAX_SIZE = "500M"
DEFAULT_CRON = "0 3 * * *"

_FIND_STALE_LOGS = (
    "find /var/log -type f "
    "\\( -name '*.gz' -o -name '*.xz' -o -name '*.bz2' "
    "-o -name '*.1' -o -name '*.old' -o -name '*.rotated' \\) "
    "-mtime +{days} -print"
)


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def cleanup_settings() -> dict:
    return {
        "log_min_age_days": _int_env("CLEANUP_LOG_MIN_AGE_DAYS", DEFAULT_LOG_MIN_AGE_DAYS),
        "journal_max_age_days": _int_env(
            "CLEANUP_JOURNAL_MAX_AGE_DAYS", DEFAULT_JOURNAL_MAX_AGE_DAYS
        ),
        "journal_max_size": os.getenv("CLEANUP_JOURNAL_MAX_SIZE", DEFAULT_JOURNAL_MAX_SIZE),
        "cron": os.getenv("LOG_CLEANUP_CRON", DEFAULT_CRON),
    }


def journal_vacuum_commands(settings: Optional[dict] = None) -> List[str]:
    cfg = settings or cleanup_settings()
    size = re.sub(r"[^0-9A-Za-z]", "", str(cfg["journal_max_size"])) or DEFAULT_JOURNAL_MAX_SIZE
    days = int(cfg["journal_max_age_days"])
    return [
        f"journalctl --vacuum-time={days}d",
        f"journalctl --vacuum-size={size}",
    ]


def cron_script(settings: Optional[dict] = None) -> str:
    """Locked-down cron body: journal shrink + aged rotated logs only."""
    cfg = settings or cleanup_settings()
    days = int(cfg["log_min_age_days"])
    vacuums = "\n".join(journal_vacuum_commands(cfg))
    return f"""#!/bin/sh
# Managed by devops-ai-agent. Do not add extra rm/find paths.
set -eu
{vacuums}
{_FIND_STALE_LOGS.format(days=days)} | while IFS= read -r path; do
  case "$path" in
    /var/log/*.gz|/var/log/*.xz|/var/log/*.bz2|/var/log/*.1|/var/log/*.old|/var/log/*.rotated|/var/log/*/*.gz|/var/log/*/*.xz|/var/log/*/*.bz2|/var/log/*/*.1|/var/log/*/*.old|/var/log/*/*.rotated)
      rm -f -- "$path"
      ;;
    *)
      echo "skip unprotected-unknown: $path" >&2
      ;;
  esac
done
"""


def classify_candidates(paths: List[str]) -> dict:
    safe, alerts = [], []
    for path in paths:
        verdict = classify_cleanup_target(path)
        if verdict["status"] == "safe":
            safe.append(verdict)
        else:
            alerts.append(verdict)
    return {"safe": safe, "alerts": alerts}


class DiskCleanup:
    def __init__(self, runner: Optional[Callable] = None):
        self._runner = runner

    async def _run(self, command: str, host: Optional[str] = None) -> dict:
        if self._runner:
            return await self._runner(command, host)
        from tools.executor import SafeExecutor

        return await SafeExecutor().run(command, host=host)

    async def inspect(self, host: Optional[str] = None) -> dict:
        """Read disk, journal, and large-log pressure without deleting anything."""
        disk = await self._run("df -h / /var /var/log 2>/dev/null || df -h", host)
        inodes = await self._run("df -i / /var /var/log 2>/dev/null || df -i", host)
        journal = await self._run("journalctl --disk-usage 2>/dev/null || true", host)
        large_logs = await self._run(
            "du -sh /var/log/* 2>/dev/null | sort -hr | head -20", host
        )
        return {
            "host": host or "localhost",
            "disk": disk.get("stdout") or disk.get("error"),
            "inodes": inodes.get("stdout") or inodes.get("error"),
            "journal": journal.get("stdout") or journal.get("error"),
            "large_logs": large_logs.get("stdout") or large_logs.get("error"),
        }

    async def plan(self, host: Optional[str] = None) -> dict:
        """List what would be cleaned. Protected/unknown paths become alerts."""
        settings = cleanup_settings()
        find_cmd = _FIND_STALE_LOGS.format(days=settings["log_min_age_days"])
        listed = await self._run(find_cmd, host)
        raw = listed.get("stdout") or ""
        paths = [line.strip() for line in raw.splitlines() if line.strip()]
        classified = classify_candidates(paths)
        return {
            "host": host or "localhost",
            "settings": settings,
            "journal_commands": journal_vacuum_commands(settings),
            "safe_deletes": classified["safe"],
            "alerts": classified["alerts"],
            "message": (
                "Will shrink journals and delete only aged rotated logs. "
                "Protected or unknown paths are listed under alerts and will not be deleted."
            ),
        }

    async def apply(self, host: Optional[str] = None, dry_run: bool = True) -> dict:
        """Apply journal shrink + safe stale-log deletes. dry_run defaults to True."""
        if is_emergency_stop_active() and not dry_run:
            return emergency_stop_block(
                "Agent emergency stop is active. Disk cleanup is disabled."
            )
        plan = await self.plan(host)
        if dry_run:
            return {
                **plan,
                "applied": False,
                "dry_run": True,
                "message": "Dry run — no files deleted. Re-run with dry_run=false after reviewing alerts.",
            }

        if plan["alerts"]:
            log.warning(
                "Cleanup skipped protected or unknown paths",
                count=len(plan["alerts"]),
                host=host,
            )

        results = []
        for command in plan["journal_commands"]:
            results.append(await self._run(command, host))

        deleted, skipped = [], []
        for item in plan["safe_deletes"]:
            path = item["path"]
            if not is_safe_stale_log(path):
                skipped.append({**item, "reason": "re-check failed; refusing delete"})
                continue
            outcome = await self._run(f"rm -f -- {shlex.quote(path)}", host)
            if outcome.get("success"):
                deleted.append(path)
            else:
                skipped.append({"path": path, "error": outcome.get("error") or outcome.get("stderr")})

        return {
            "applied": True,
            "dry_run": False,
            "host": host or "localhost",
            "journal": results,
            "deleted": deleted,
            "skipped": skipped,
            "alerts": plan["alerts"],
            "alerted": bool(plan["alerts"]),
            "message": (
                f"Deleted {len(deleted)} stale rotated logs and vacuumed journals. "
                f"{len(plan['alerts'])} protected/unknown path(s) were not touched."
            ),
        }

    async def install_cron(self, host: Optional[str] = None, dry_run: bool = True) -> dict:
        """Install a daily cron that only vacuums journals and aged rotated logs."""
        if is_emergency_stop_active() and not dry_run:
            return emergency_stop_block(
                "Agent emergency stop is active. Cron install is disabled."
            )
        settings = cleanup_settings()
        script = cron_script(settings)
        cron_line = f"{settings['cron']} root /usr/local/sbin/devops-log-cleanup"
        if dry_run:
            return {
                "dry_run": True,
                "applied": False,
                "cron_line": cron_line,
                "script": script,
                "message": "Dry run — cron not installed. Review the script, then re-run with dry_run=false.",
            }

        write_script = (
            "cat > /usr/local/sbin/devops-log-cleanup << 'EOF'\n"
            f"{script}"
            "EOF\n"
            "chmod 750 /usr/local/sbin/devops-log-cleanup"
        )
        write_cron = (
            "cat > /etc/cron.d/devops-log-cleanup << 'EOF'\n"
            f"{cron_line}\n"
            "EOF\n"
            "chmod 644 /etc/cron.d/devops-log-cleanup"
        )
        script_result = await self._run(write_script, host)
        cron_result = await self._run(write_cron, host)
        ok = bool(script_result.get("success") and cron_result.get("success"))
        return {
            "applied": ok,
            "dry_run": False,
            "cron_line": cron_line,
            "script_result": script_result,
            "cron_result": cron_result,
            "message": "Installed journal + stale-log cleanup cron" if ok else "Failed to install cron",
        }
