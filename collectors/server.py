"""
Server Context Collector
Gathers system health metrics, service status, and logs from the target host
(locally or over SSH), with extra checks for the target's OS family:
RHEL-family (SELinux, firewalld, security updates), Debian-family (pending
upgrades, reboot-required, AppArmor) and Windows Server (services, event log,
firewall). The OS is detected on the target, not on the machine running the agent.
"""
import asyncio
import base64
from typing import Dict, List, Optional, Tuple

import structlog

from tools.ssh_utils import build_ssh_argv

log = structlog.get_logger()

RHEL_FAMILY = ("rhel", "centos", "fedora", "rocky", "almalinux", "amzn", "ol")
DEBIAN_FAMILY = ("debian", "ubuntu")


def _powershell(script: str) -> str:
    """A PowerShell command that survives SSH and cmd.exe quoting unchanged."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"


class ServerCollector:
    SAFE_COMMANDS = [
        ("disk_usage", "df -h"),
        ("memory", "free -m"),
        ("cpu_load", "uptime"),
        ("top_processes", "ps aux --sort=-%cpu | head -20"),
        ("systemd_failed", "systemctl list-units --state=failed --no-pager"),
        ("nginx_status", "systemctl status nginx --no-pager -l | tail -30"),
        ("disk_inodes", "df -i | head -10"),
        ("open_ports", "ss -tlnp | head -20"),
        ("recent_errors", "journalctl -p err -n 50 --no-pager"),
        ("journal_disk", "journalctl --disk-usage 2>/dev/null || true"),
        ("nginx_config_test", "nginx -t 2>&1 || true"),
        ("certbot_certs", "certbot certificates 2>/dev/null || echo 'certbot not available'"),
        ("kernel_errors", "dmesg --level=err,crit,alert,emerg 2>/dev/null | tail -20 || true"),
    ]

    DOCKER_COMMANDS = [
        (
            "docker_ps_all",
            "docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' 2>/dev/null || echo 'docker not available'",
        ),
        (
            "docker_unhealthy",
            "docker ps -a --filter 'status=restarting' --filter 'status=exited' --format '{{.Names}}: {{.Status}}' 2>/dev/null || true",
        ),
    ]

    RHEL_COMMANDS = [
        ("selinux", "sestatus 2>/dev/null || getenforce 2>/dev/null || echo 'SELinux tools not installed'"),
        ("firewalld", "firewall-cmd --state 2>&1; firewall-cmd --list-all 2>/dev/null | head -20"),
        (
            "security_updates",
            "(dnf -q updateinfo list --security 2>/dev/null || yum -q updateinfo list security 2>/dev/null) | head -20",
        ),
    ]

    DEBIAN_COMMANDS = [
        ("upgradable_packages", "apt list --upgradable 2>/dev/null | head -20"),
        (
            "reboot_required",
            "test -f /var/run/reboot-required && cat /var/run/reboot-required || echo 'no reboot required'",
        ),
        ("apparmor", "aa-status --enabled 2>/dev/null && echo 'AppArmor enabled' || echo 'AppArmor disabled or not installed'"),
    ]

    WINDOWS_COMMANDS = [
        (
            "os_info",
            _powershell(
                "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,LastBootUpTime,"
                "FreePhysicalMemory,TotalVisibleMemorySize | Format-List"
            ),
        ),
        (
            "cpu",
            _powershell("Get-CimInstance Win32_Processor | Select-Object Name,LoadPercentage,NumberOfCores | Format-List"),
        ),
        (
            "disk_usage",
            _powershell(
                "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,"
                "@{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}},@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}}"
                " | Format-Table -AutoSize"
            ),
        ),
        (
            "top_processes",
            _powershell("Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name,Id,CPU,WorkingSet | Format-Table -AutoSize"),
        ),
        (
            "stopped_auto_services",
            _powershell(
                "Get-CimInstance Win32_Service -Filter \"StartMode='Auto' AND State<>'Running'\""
                " | Select-Object Name,State,Status | Format-Table -AutoSize"
            ),
        ),
        (
            "system_errors",
            _powershell(
                "Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2} -MaxEvents 20 -ErrorAction SilentlyContinue"
                " | Format-Table TimeCreated,ProviderName,Id,Message -AutoSize -Wrap"
            ),
        ),
        (
            "application_errors",
            _powershell(
                "Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2} -MaxEvents 20 -ErrorAction SilentlyContinue"
                " | Format-Table TimeCreated,ProviderName,Id,Message -AutoSize -Wrap"
            ),
        ),
        ("listening_ports", "netstat -ano | findstr LISTENING"),
        ("firewall", "netsh advfirewall show allprofiles state"),
        (
            "iis",
            _powershell("Get-Service W3SVC -ErrorAction SilentlyContinue | Select-Object Name,Status | Format-List"),
        ),
    ]

    async def _run(self, cmd: str, host: Optional[str]) -> str:
        try:
            if host and host not in ("localhost", "127.0.0.1"):
                proc = await asyncio.create_subprocess_exec(
                    *build_ssh_argv(host, cmd),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            return stdout.decode(errors="replace").strip() or stderr.decode(errors="replace").strip()
        except asyncio.TimeoutError:
            return f"timeout running: {cmd}"
        except Exception as e:
            return f"error: {e}"

    async def detect_os(self, host: Optional[str] = None) -> str:
        """OS family of the target: rhel, debian, linux, darwin or windows."""
        kernel = (await self._run("uname -s", host)).lower()
        if "linux" in kernel:
            release = (await self._run("cat /etc/os-release", host)).lower()
            ids = " ".join(
                line.split("=", 1)[1].strip().strip('"')
                for line in release.splitlines()
                if line.startswith(("id=", "id_like="))
            ).split()
            if any(i in RHEL_FAMILY for i in ids):
                return "rhel"
            if any(i in DEBIAN_FAMILY for i in ids):
                return "debian"
            return "linux"
        if "darwin" in kernel:
            return "darwin"
        if "windows" in (await self._run("ver", host)).lower():
            return "windows"
        return "linux"

    def commands_for(self, os_family: str) -> List[Tuple[str, str]]:
        if os_family == "windows":
            return list(self.WINDOWS_COMMANDS)
        commands = list(self.SAFE_COMMANDS) + list(self.DOCKER_COMMANDS)
        if os_family == "rhel":
            commands += self.RHEL_COMMANDS
        elif os_family == "debian":
            commands += self.DEBIAN_COMMANDS
        return commands

    async def collect(self, host: Optional[str] = None) -> Dict[str, str]:
        """Collect a health snapshot. Use host= for remote servers (centralized agent)."""
        os_family = await self.detect_os(host)
        result: Dict[str, str] = {"target_host": host or "localhost", "os_family": os_family}
        for key, cmd in self.commands_for(os_family):
            result[key] = await self._run(cmd, host)
        return result
