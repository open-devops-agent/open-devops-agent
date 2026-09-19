"""
Tests for FixVerifier stability monitoring.

Regression coverage for issue #55: every positive monitoring duration must pace
its observations with a delay strictly greater than zero, so their count is
governed by the requested time window rather than by event-loop throughput.
"""

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
