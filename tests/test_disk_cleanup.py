"""Safe disk cleanup: never delete prod/in-use data; alert instead."""
import pytest

from tools.disk_policy import classify_cleanup_target, is_protected_path, is_safe_stale_log
from tools.disk_cleanup import DiskCleanup, cron_script, journal_vacuum_commands


class TestDiskPolicy:
    def test_protects_production_and_database_paths(self):
        for path in (
            "/var/www/html/index.html",
            "/home/ubuntu/app.db",
            "/var/lib/mysql/ibdata1",
            "/opt/acme/data",
            "/data/prod/customers.csv",
            "/etc/nginx/nginx.conf",
            "/root/.ssh/id_rsa",
        ):
            assert is_protected_path(path), path
            verdict = classify_cleanup_target(path)
            assert verdict["status"] == "protected"
            assert verdict["alert"] is True

    def test_allows_only_rotated_var_log_archives(self):
        assert is_safe_stale_log("/var/log/nginx/access.log.1")
        assert is_safe_stale_log("/var/log/syslog.1.gz")
        assert classify_cleanup_target("/var/log/kern.log.old")["status"] == "safe"

    def test_rejects_live_logs_and_unknown_paths(self):
        assert classify_cleanup_target("/var/log/nginx/access.log")["status"] == "rejected"
        assert classify_cleanup_target("/tmp/scratch.bin")["status"] == "rejected"
        assert classify_cleanup_target("/var/log/production.log.1")["status"] == "protected"

    def test_extra_protected_prefixes(self, monkeypatch):
        monkeypatch.setenv("CLEANUP_PROTECTED_PATHS", "/custom/prod")
        assert is_protected_path("/custom/prod/db")


class TestCleanupPlan:
    @pytest.mark.asyncio
    async def test_apply_dry_run_does_not_delete(self):
        calls = []

        async def runner(command, host):
            calls.append(command)
            if command.startswith("find "):
                return {
                    "success": True,
                    "stdout": "/var/log/syslog.1.gz\n/var/www/html/index.html\n",
                }
            return {"success": True, "stdout": ""}

        result = await DiskCleanup(runner=runner).apply(dry_run=True)
        assert result["dry_run"] is True
        assert result["applied"] is False
        assert any(item["path"] == "/var/log/syslog.1.gz" for item in result["safe_deletes"])
        assert any(item["status"] == "protected" for item in result["alerts"])
        assert not any(cmd.startswith("rm ") for cmd in calls)
        assert not any("vacuum" in cmd for cmd in calls)

    @pytest.mark.asyncio
    async def test_apply_deletes_only_safe_logs_and_alerts_on_prod(self):
        deleted = []

        async def runner(command, host):
            if command.startswith("find "):
                return {
                    "success": True,
                    "stdout": "/var/log/auth.log.1\n/home/ubuntu/important.db\n",
                }
            if command.startswith("rm "):
                deleted.append(command)
            return {"success": True, "stdout": "ok"}

        result = await DiskCleanup(runner=runner).apply(dry_run=False)
        assert result["applied"] is True
        assert result["alerted"] is True
        assert "/var/log/auth.log.1" in result["deleted"]
        assert any("/home/ubuntu/important.db" in a["path"] for a in result["alerts"])
        assert all("important.db" not in cmd for cmd in deleted)

    def test_cron_script_is_journal_and_rotated_logs_only(self):
        script = cron_script()
        assert "journalctl --vacuum-time" in script
        assert "/var/log" in script
        assert "/var/www" not in script
        assert "rm -rf /" not in script
        vacuums = journal_vacuum_commands()
        assert vacuums[0].startswith("journalctl --vacuum-time=")
