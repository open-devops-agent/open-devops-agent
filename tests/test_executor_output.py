"""Executor output handling: no lost evidence, no crash on binary output, timeouts stop the command (#206)."""
import asyncio
import time

import pytest

from tools.executor import SafeExecutor, clip_output


@pytest.fixture(autouse=True)
def no_emergency_stop(monkeypatch):
    monkeypatch.delenv("AGENT_EMERGENCY_STOP", raising=False)
    monkeypatch.delenv("EXECUTOR_TIMEOUT_SEC", raising=False)
    monkeypatch.delenv("EXECUTOR_MAX_OUTPUT_CHARS", raising=False)


def test_clip_keeps_head_and_tail_with_marker():
    text = "FIRST-ERROR\n" + "x" * 10_000 + "\nFINAL-STATE"
    out = clip_output(text, 1000)
    assert out.startswith("FIRST-ERROR") and out.endswith("FINAL-STATE")
    assert "[truncated" in out and len(out) < 1100


def test_short_output_is_untouched():
    assert clip_output("hello", 1000) == "hello"


@pytest.mark.asyncio
async def test_non_utf8_output_does_not_fail_the_command():
    result = await SafeExecutor().run(r"printf 'ok \377\376 done'")
    assert result["success"] is True
    assert result["stdout"].startswith("ok") and result["stdout"].endswith("done")


@pytest.mark.asyncio
async def test_long_output_keeps_the_start_for_the_model():
    result = await SafeExecutor().run("seq 1 20000")
    lines = result["stdout"].splitlines()
    assert lines[0] == "1" and lines[-1] == "20000"
    assert "[truncated" in result["stdout"] and result["stdout_truncated_chars"] > 0


@pytest.mark.asyncio
async def test_evidence_limit_keeps_everything():
    result = await SafeExecutor().run("seq 1 20000", max_output=1_000_000)
    assert result["stdout"].count("\n") == 19999 and "stdout_truncated_chars" not in result


@pytest.mark.asyncio
async def test_output_limit_is_configurable(monkeypatch):
    monkeypatch.setenv("EXECUTOR_MAX_OUTPUT_CHARS", "200000")
    result = await SafeExecutor().run("seq 1 20000")
    assert "[truncated" not in result["stdout"]


@pytest.mark.asyncio
async def test_timeout_stops_the_command_and_its_children(tmp_path):
    marker = tmp_path / "still-running"
    started = time.monotonic()
    result = await SafeExecutor().run(f"sh -c 'sleep 2; touch {marker}'", timeout=1)
    assert time.monotonic() - started < 4
    assert result["success"] is False and "timed out after 1s" in result["error"]
    await asyncio.sleep(2.5)
    assert not marker.exists()  # the child shell was killed, not orphaned


@pytest.mark.asyncio
async def test_timeout_default_from_env(monkeypatch):
    monkeypatch.setenv("EXECUTOR_TIMEOUT_SEC", "1")
    result = await SafeExecutor().run("sleep 3")
    assert "timed out after 1s" in result["error"]


@pytest.mark.asyncio
async def test_containment_evidence_asks_for_full_output(monkeypatch):
    from unittest.mock import AsyncMock

    from tools.containment import EVIDENCE_MAX_OUTPUT_CHARS, ContainmentTools

    class Recorder:
        limits = []

        async def run(self, command, host=None, **limits):
            self.limits.append(limits)
            return {"success": True, "stdout": "x"}

    tools = ContainmentTools(Recorder(), AsyncMock(), None)
    await tools._evidence("INC-1", "a1", {"logs": "kubectl logs api -n prod"})
    assert tools.executor.limits[0]["max_output"] == EVIDENCE_MAX_OUTPUT_CHARS
    assert tools.executor.limits[0]["timeout"] >= 60
