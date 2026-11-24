"""ServerCollector detects the TARGET host's OS and runs the matching checks (#19)."""
import base64

import pytest

from collectors.server import ServerCollector


def fake_target(outputs: dict):
    """A collector whose commands answer like a given target host."""
    collector = ServerCollector()
    collector.ran = []

    async def run(cmd, host):
        collector.ran.append((cmd, host))
        for prefix, out in outputs.items():
            if cmd.startswith(prefix):
                return out
        return "ok"

    collector._run = run
    return collector


RHEL = {"uname -s": "Linux", "cat /etc/os-release": 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\n'}
UBUNTU = {"uname -s": "Linux", "cat /etc/os-release": 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n'}
AMAZON = {"uname -s": "Linux", "cat /etc/os-release": 'NAME="Amazon Linux"\nID="amzn"\nID_LIKE="fedora"\n'}
ALPINE = {"uname -s": "Linux", "cat /etc/os-release": "ID=alpine\n"}
WINDOWS = {"uname -s": "'uname' is not recognized as an internal or external command", "ver": "Microsoft Windows [Version 10.0.20348.2227]"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outputs, family",
    [(RHEL, "rhel"), (AMAZON, "rhel"), (UBUNTU, "debian"), (ALPINE, "linux"), (WINDOWS, "windows"),
     ({"uname -s": "Darwin"}, "darwin")],
)
async def test_detects_target_os(outputs, family):
    assert await fake_target(outputs).detect_os("10.0.0.5") == family


@pytest.mark.asyncio
async def test_detection_runs_on_the_target_not_locally():
    collector = fake_target(RHEL)
    await collector.collect(host="db-1.internal")
    assert collector.ran and all(host == "db-1.internal" for _, host in collector.ran)


@pytest.mark.asyncio
async def test_rhel_gets_selinux_firewalld_and_security_updates():
    result = await fake_target(RHEL).collect(host="10.0.0.5")
    assert result["os_family"] == "rhel"
    for key in ("selinux", "firewalld", "security_updates", "disk_usage", "systemd_failed", "kernel_errors"):
        assert key in result
    assert "upgradable_packages" not in result


@pytest.mark.asyncio
async def test_debian_gets_upgrades_reboot_and_apparmor():
    result = await fake_target(UBUNTU).collect(host="10.0.0.6")
    assert result["os_family"] == "debian"
    for key in ("upgradable_packages", "reboot_required", "apparmor", "docker_ps_all"):
        assert key in result
    assert "selinux" not in result


@pytest.mark.asyncio
async def test_windows_gets_windows_checks_only():
    collector = fake_target(WINDOWS)
    result = await collector.collect(host="win-01")
    assert result["os_family"] == "windows"
    for key in ("os_info", "disk_usage", "stopped_auto_services", "system_errors", "firewall", "iis"):
        assert key in result
    assert "systemd_failed" not in result and "docker_ps_all" not in result
    commands = [cmd for cmd, _ in collector.ran]
    assert not any(cmd.startswith(("df ", "journalctl", "systemctl")) for cmd in commands)


def test_windows_powershell_is_encoded_and_round_trips():
    cmd = dict(ServerCollector.WINDOWS_COMMANDS)["stopped_auto_services"]
    assert cmd.startswith("powershell -NoProfile -NonInteractive -EncodedCommand ")
    script = base64.b64decode(cmd.rsplit(" ", 1)[1]).decode("utf-16-le")
    assert "StartMode='Auto' AND State<>'Running'" in script
    assert '"' not in cmd and "'" not in cmd  # nothing for ssh or cmd.exe to mangle


@pytest.mark.asyncio
async def test_localhost_uses_shell_and_keeps_existing_keys():
    collector = fake_target(UBUNTU)
    result = await collector.collect()
    assert result["target_host"] == "localhost"
    assert {k for k, _ in ServerCollector.SAFE_COMMANDS} <= set(result)
