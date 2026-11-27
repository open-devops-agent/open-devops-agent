"""
Tests for FixVerifier stability monitoring.

Regression coverage for issue #55: every positive monitoring duration must pace
its observations with a delay strictly greater than zero, so their count is
governed by the requested time window rather than by event-loop throughput.
"""

import base64
from unittest.mock import AsyncMock, MagicMock, patch
import types

import pytest

from tools import fix_verifier
from tools.fix_verifier import FixVerifier


# Observations after which the harness forces its clock past the deadline, so
# that an unpaced loop fails an assertion instead of spinning forever.
RUNAWAY_ITERATION_GUARD = 50


class StabilityLoopHarness:
    """Drives _monitor_stability with a controlled clock and a sleep recorder."""

    def __init__(self, duration):
        self.duration = duration
        self.start = 1_000_000.0
        self.now = self.start
        self.sleeps = []
        self.checks = 0

    def time(self):
        """Replacement for tools.fix_verifier.time.time."""
        return self.now

    async def sleep(self, delay):
        """Replacement for tools.fix_verifier.asyncio.sleep; records the delay."""
        self.sleeps.append(delay)
        self.now += max(delay, 0)
        if len(self.sleeps) >= RUNAWAY_ITERATION_GUARD:
            self.now = self.start + self.duration + 1

    async def run_immediate_checks(self, incident_type, expected_state):
        """Stub for FixVerifier._run_immediate_checks; always passes."""
        self.checks += 1
        return {"check_type": "immediate", "passed": True, "details": {}}


async def drive_monitoring(monkeypatch, duration):
    """Run one _monitor_stability window and return the recording harness."""
    harness = StabilityLoopHarness(duration)
    monkeypatch.setattr(fix_verifier.time, "time", harness.time)
    monkeypatch.setattr(
        fix_verifier, "asyncio", types.SimpleNamespace(sleep=harness.sleep)
    )

    verifier = FixVerifier()
    verifier._run_immediate_checks = harness.run_immediate_checks

    result = await verifier._monitor_stability(
        "k8s", {"pod_status": "Running"}, duration
    )
    return harness, result


class TestStabilityMonitoringPacing:
    """Every positive monitoring duration must be paced by a positive delay."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("duration", [1, 2, 3, 4, 5, 6, 7, 8, 9])
    async def test_short_positive_durations_are_paced_by_a_positive_delay(
        self, monkeypatch, duration
    ):
        harness, result = await drive_monitoring(monkeypatch, duration)

        assert harness.sleeps, (
            f"duration={duration} performed no paced observation at all"
        )
        assert all(delay > 0 for delay in harness.sleeps), (
            f"duration={duration} awaited non-positive pacing delays: "
            f"{harness.sleeps}"
        )
        assert len(harness.sleeps) < RUNAWAY_ITERATION_GUARD, (
            f"duration={duration} performed {len(harness.sleeps)} observations; "
            "observation count must be bounded by the monitoring window"
        )
        assert result["checks_performed"] == len(harness.sleeps)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("duration", [300, 600, 900])
    async def test_long_durations_keep_the_thirty_second_maximum(
        self, monkeypatch, duration
    ):
        harness, _ = await drive_monitoring(monkeypatch, duration)

        assert harness.sleeps, f"duration={duration} performed no observation"
        assert set(harness.sleeps) == {30}, (
            f"duration={duration} must keep the 30 second maximum interval, "
            f"got {sorted(set(harness.sleeps))}"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "duration, expected_interval", [(10, 1), (100, 10), (250, 25)]
    )
    async def test_medium_durations_keep_the_proportional_interval(
        self, monkeypatch, duration, expected_interval
    ):
        harness, _ = await drive_monitoring(monkeypatch, duration)

        assert set(harness.sleeps) == {expected_interval}, (
            f"duration={duration} must keep its duration // 10 interval of "
            f"{expected_interval}, got {sorted(set(harness.sleeps))}"
        )


class TestFixVerifierStability:
    @pytest.mark.asyncio
    async def test_zero_monitoring_duration_is_not_verified(self, monkeypatch):
        """Issue #52: zero-duration monitoring must not report verified success."""
        async def immediate_pass(self, incident_type, expected_state):
            return {"check_type": "immediate", "passed": True, "details": {}}

        monkeypatch.setattr(FixVerifier, "_run_immediate_checks", immediate_pass)
        result = await FixVerifier().verify_fix(
            incident_type="cicd",
            fix_applied="rerun pipeline",
            expected_state={"pipeline": "ok"},
            monitoring_duration=0,
        )

        assert result["status"] != "success"
        assert result["verified"] is False
        stability = result["checks_performed"][1]
        assert stability["checks_performed"] == 0
        assert stability["stable"] is False


def _mock_http_get(json_data, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return patch("tools.fix_verifier.httpx.AsyncClient", return_value=client)


class TestCicdCloudArgocdVerification:
    """Issue #53: CI/CD, cloud, and ArgoCD verification must observe target systems."""

    @pytest.mark.asyncio
    async def test_empty_expected_state_does_not_pass(self):
        verifier = FixVerifier()
        cicd = await verifier._verify_cicd_fix({})
        cloud = await verifier._verify_cloud_fix("cloud_aws", {})
        argocd = await verifier._verify_argocd_fix({})

        assert cicd["passed"] is False
        assert cloud["passed"] is False
        assert argocd["passed"] is False

    @pytest.mark.asyncio
    async def test_github_run_success_observes_actions_api(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        with _mock_http_get({"conclusion": "success", "status": "completed", "html_url": "https://github.com/o/r/actions/runs/1"}) as mocked:
            result = await FixVerifier()._verify_cicd_fix(
                {"platform": "github", "repo": "o/r", "run_id": 1}
            )

        assert result["passed"] is True
        mocked.return_value.get.assert_awaited()
        url = mocked.return_value.get.await_args.args[0]
        assert url.endswith("/repos/o/r/actions/runs/1")

    @pytest.mark.asyncio
    async def test_github_run_failure_does_not_pass(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        with _mock_http_get({"conclusion": "failure", "status": "completed"}):
            result = await FixVerifier()._verify_cicd_fix(
                {"platform": "github", "repo": "o/r", "run_id": 1}
            )
        assert result["passed"] is False

    @pytest.mark.asyncio
    async def test_cloud_aws_observes_collector(self):
        verifier = FixVerifier()
        verifier._observe_cloud = AsyncMock(
            return_value={"resource_type": "ec2", "instance_id": "i-1", "state": "running"}
        )
        result = await verifier._verify_cloud_fix(
            "cloud_aws",
            {"resource_type": "ec2", "resource_id": "i-1", "state": "running"},
        )
        assert result["passed"] is True
        verifier._observe_cloud.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cloud_aws_collector_error_does_not_pass(self):
        verifier = FixVerifier()
        verifier._observe_cloud = AsyncMock(return_value={"error": "Instance i-1 not found"})
        result = await verifier._verify_cloud_fix(
            "cloud_aws",
            {"resource_type": "ec2", "resource_id": "i-1"},
        )
        assert result["passed"] is False

    @pytest.mark.asyncio
    async def test_argocd_observes_application_status(self):
        verifier = FixVerifier()
        verifier._observe_argocd = AsyncMock(
            return_value={
                "app_name": "frontend",
                "health": {"status": "Healthy"},
                "sync": {"status": "Synced"},
            }
        )
        result = await verifier._verify_argocd_fix({"app_name": "frontend"})
        assert result["passed"] is True
        verifier._observe_argocd.assert_awaited_once_with("frontend")

    @pytest.mark.asyncio
    async def test_argocd_unhealthy_does_not_pass(self):
        verifier = FixVerifier()
        verifier._observe_argocd = AsyncMock(
            return_value={
                "app_name": "frontend",
                "health": {"status": "Degraded"},
                "sync": {"status": "Synced"},
            }
        )
        result = await verifier._verify_argocd_fix({"app_name": "frontend"})
        assert result["passed"] is False


class TestFailClosedVerification:
    """
    Regression coverage for issue #69: verification must not report success
    without observing the target system.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "expected_state",
        [{}, {"pod_status": "Running"}, {"pod_name": "api"}, {"namespace": "prod"}],
    )
    async def test_k8s_without_pod_identifiers_does_not_pass(self, expected_state):
        verifier = FixVerifier()
        with patch("subprocess.run") as mock_run:
            result = await verifier._verify_k8s_fix(expected_state)
        assert result["passed"] is False
        assert "pod_name" in result["message"]
        assert "namespace" in result["message"]
        mock_run.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("expected_state", [{}, {"unrelated": "value"}])
    async def test_server_without_service_name_does_not_pass(self, expected_state):
        verifier = FixVerifier()
        with patch("subprocess.run") as mock_run:
            result = await verifier._verify_server_fix(expected_state)
        assert result["passed"] is False
        assert "service_name" in result["message"]
        mock_run.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("incident_type", ["helm", "terraform", "unknown_type"])
    async def test_unimplemented_incident_type_does_not_pass(self, incident_type):
        verifier = FixVerifier()
        with patch("subprocess.run"):
            result = await verifier._run_immediate_checks(incident_type, {})
        assert result["passed"] is False
        assert "not implemented" in result["message"]
        assert incident_type in result["message"]

    @pytest.mark.asyncio
    async def test_verify_fix_unimplemented_type_does_not_pass(self):
        verifier = FixVerifier()
        # Guard against a real 300s monitoring loop if the immediate check passes.
        verifier._monitor_stability = AsyncMock(return_value={"stable": True})
        with patch("subprocess.run"):
            result = await verifier.verify_fix(
                "helm", "helm rollback", {}, monitoring_duration=300
            )
        assert result["verified"] is False
        assert result["status"] == "failed"
        assert len(result["checks_performed"]) == 1
        verifier._monitor_stability.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_k8s_with_pod_identifiers_observes_pod(self):
        verifier = FixVerifier()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="Running\n")
            result = await verifier._verify_k8s_fix(
                {"pod_name": "api", "namespace": "prod", "pod_status": "Running"}
            )
        assert result["passed"] is True
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0][:4] == ["kubectl", "get", "pod", "api"]

    @pytest.mark.asyncio
    async def test_server_with_service_name_observes_service(self):
        verifier = FixVerifier()
        with patch(
            "collectors.server.ServerCollector.detect_os", AsyncMock(return_value="linux")
        ), patch(
            "collectors.server.ServerCollector._run", AsyncMock(return_value="active")
        ) as mock_run:
            result = await verifier._verify_server_fix({"service_name": "nginx"})
        assert result["passed"] is True
        mock_run.assert_awaited_once_with("systemctl is-active nginx", None)


class TestServerVerificationTarget:
    """
    Regression coverage for issue #193: server fixes are verified on the target
    server (over SSH), not on the host running the agent.
    """

    @pytest.mark.asyncio
    async def test_remote_server_service_is_checked_over_ssh(self, monkeypatch):
        monkeypatch.setenv("SSH_REMOTE_USER", "ops")
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"active\n", b""))
        with patch(
            "collectors.server.ServerCollector.detect_os", AsyncMock(return_value="debian")
        ), patch(
            "asyncio.create_subprocess_exec", AsyncMock(return_value=proc)
        ) as mock_exec, patch("subprocess.run") as mock_local:
            result = await FixVerifier()._verify_server_fix(
                {"service_name": "nginx", "target_host": "10.0.0.5"}
            )
        mock_local.assert_not_called()
        assert result["passed"] is True
        argv = mock_exec.call_args.args
        assert argv[0] == "ssh"
        assert "ops@10.0.0.5" in argv
        assert argv[-1] == "systemctl is-active nginx"

    @pytest.mark.asyncio
    async def test_remote_windows_service_uses_powershell(self):
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"Running\r\n", b""))
        with patch(
            "collectors.server.ServerCollector.detect_os", AsyncMock(return_value="windows")
        ), patch(
            "asyncio.create_subprocess_exec", AsyncMock(return_value=proc)
        ) as mock_exec, patch("subprocess.run") as mock_local:
            result = await FixVerifier()._verify_server_fix(
                {"service_name": "Spooler", "target_host": "10.0.0.7"}
            )
        mock_local.assert_not_called()
        assert result["passed"] is True
        assert result["details"]["os_family"] == "windows"
        argv = mock_exec.call_args.args
        assert argv[0] == "ssh"
        assert "10.0.0.7" in argv
        remote_cmd = argv[-1]
        assert remote_cmd.startswith("powershell -NoProfile -NonInteractive -EncodedCommand ")
        assert "systemctl" not in remote_cmd
        script = base64.b64decode(remote_cmd.rsplit(" ", 1)[1]).decode("utf-16-le")
        assert "Get-Service -Name 'Spooler'" in script

    @pytest.mark.asyncio
    async def test_local_service_check_runs_in_local_shell(self, monkeypatch):
        monkeypatch.delenv("SSH_REMOTE_USER", raising=False)
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"active\n", b""))
        with patch(
            "collectors.server.ServerCollector.detect_os", AsyncMock(return_value="debian")
        ), patch(
            "asyncio.create_subprocess_shell", AsyncMock(return_value=proc)
        ) as mock_shell, patch(
            "asyncio.create_subprocess_exec"
        ) as mock_exec:
            result = await FixVerifier()._verify_server_fix({"service_name": "nginx"})
        assert result["passed"] is True
        assert result["details"]["target_host"] == "localhost"
        mock_exec.assert_not_called()
        assert mock_shell.call_args.args[0] == "systemctl is-active nginx"
