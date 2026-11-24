"""Concurrent requests for different orgs never see each other's credentials (#63)."""
import asyncio
import os
import subprocess  # nosec B404 - runs a fixed printenv to inspect the child environment

import pytest

from agent.core import DevOpsAgent
from services.org_config import OrgConfig
from services.org_context import org_agent_credentials, org_credentials
from services.org_env import subprocess_env
from storage.memory_storage import MemoryStorage


@pytest.fixture
def orgs(monkeypatch):
    monkeypatch.setenv("ORG_ID", "default")
    monkeypatch.setenv("GITLAB_TOKEN", "default-gitlab")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy-test-key")
    config = OrgConfig(storage=MemoryStorage())
    for org in ("org-a", "org-b"):
        config.save(org, {"GITLAB_TOKEN": f"{org}-gitlab"})
    monkeypatch.setattr("services.org_context.OrgConfig", lambda: config)
    return config


@pytest.fixture
def agent(orgs):
    return DevOpsAgent()


def child_env(key):
    out = subprocess.run(["printenv", key], env=subprocess_env(), capture_output=True, text=True)  # nosec B603 B607
    return out.stdout.strip()


@pytest.mark.asyncio
async def test_overlapping_scopes_see_only_their_own_keys(orgs):
    seen = {}

    async def request(org, delay):
        with org_credentials(org):
            await asyncio.sleep(delay)  # the other org's scope opens meanwhile
            seen[org] = (os.getenv("GITLAB_TOKEN"), os.environ["GITLAB_TOKEN"], child_env("GITLAB_TOKEN"))

    # org-a reads while org-b's scope is still open (the case that leaked before #63)
    await asyncio.gather(request("org-a", 0.01), request("org-b", 0.05))
    assert seen["org-a"] == ("org-a-gitlab",) * 3
    assert seen["org-b"] == ("org-b-gitlab",) * 3


@pytest.mark.asyncio
async def test_process_environment_is_never_mutated(orgs):
    async def request(org):
        with org_credentials(org):
            await asyncio.sleep(0.01)
            # A child started without the org env inherits the untouched process env.
            out = subprocess.run(["printenv", "GITLAB_TOKEN"], capture_output=True, text=True)  # nosec B603 B607
            return out.stdout.strip()

    assert await asyncio.gather(request("org-a"), request("org-b")) == ["default-gitlab", "default-gitlab"]
    assert os.environ["GITLAB_TOKEN"] == "default-gitlab"


@pytest.mark.asyncio
async def test_slack_approver_lookup_does_not_leak_into_a_running_org(orgs, monkeypatch):
    from api import server

    orgs.save("org-b", {"GITLAB_TOKEN": "org-b-gitlab", "SLACK_APPROVER_IDS": "U_B"})
    monkeypatch.setenv("SLACK_APPROVER_IDS", "U_PLATFORM")

    async def org_a_work():
        with org_credentials("org-a"):
            await asyncio.sleep(0.02)
            return os.getenv("SLACK_APPROVER_IDS"), os.getenv("GITLAB_TOKEN")

    async def org_b_lookup():
        await asyncio.sleep(0.005)
        return server._slack_approvers("org-b")

    a, b = await asyncio.gather(org_a_work(), org_b_lookup())
    assert b == {"U_B"}
    assert a == ("U_PLATFORM", "org-a-gitlab")


@pytest.mark.asyncio
async def test_other_org_waits_so_cached_clients_are_never_swapped_mid_run(agent):
    events = []

    async def request(org, delay):
        async with org_agent_credentials(org, agent):
            events.append(("in", org))
            before = agent.gitlab_collector.token
            await asyncio.sleep(delay)
            after = agent.gitlab_collector.token
            events.append(("out", org))
            return before, after

    a, b = await asyncio.gather(request("org-a", 0.05), request("org-b", 0.01))
    assert a == ("org-a-gitlab", "org-a-gitlab")
    assert b == ("org-b-gitlab", "org-b-gitlab")
    assert events == [("in", "org-a"), ("out", "org-a"), ("in", "org-b"), ("out", "org-b")]
    assert agent.gitlab_collector.token == "default-gitlab"


@pytest.mark.asyncio
async def test_same_org_runs_concurrently_and_restores_after_the_last(agent):
    inside = []

    async def request(delay):
        async with org_agent_credentials("org-a", agent):
            inside.append(1)
            await asyncio.sleep(delay)
            token = agent.gitlab_collector.token
            inside.append(-1)
            return token

    first = asyncio.create_task(request(0.05))
    await asyncio.sleep(0.01)
    second = await request(0.0)  # finishes while the first is still inside
    assert second == "org-a-gitlab"
    assert inside[:2] == [1, 1]  # both were inside at once
    assert await first == "org-a-gitlab"  # not reset by the second one leaving
    assert agent.gitlab_collector.token == "default-gitlab"


@pytest.mark.asyncio
async def test_cancelled_request_releases_the_gate(agent):
    started = asyncio.Event()

    async def slow():
        async with org_agent_credentials("org-a", agent):
            started.set()
            await asyncio.sleep(10)

    task = asyncio.create_task(slow())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    async def other():
        async with org_agent_credentials("org-b", agent):
            return agent.gitlab_collector.token

    assert await asyncio.wait_for(other(), timeout=1) == "org-b-gitlab"
    assert agent.gitlab_collector.token == "default-gitlab"


@pytest.mark.asyncio
async def test_nested_switch_restores_the_outer_org(agent):
    async with org_agent_credentials("org-a", agent):
        async with org_agent_credentials("org-a", agent):  # re-entrant
            async with org_agent_credentials("org-b", agent):
                assert agent.gitlab_collector.token == "org-b-gitlab"
                assert os.getenv("GITLAB_TOKEN") == "org-b-gitlab"
            assert agent.gitlab_collector.token == "org-a-gitlab"
        assert agent.gitlab_collector.token == "org-a-gitlab"
        assert os.getenv("GITLAB_TOKEN") == "org-a-gitlab"
    assert agent.gitlab_collector.token == "default-gitlab"


@pytest.mark.asyncio
async def test_concurrent_tool_calls_for_two_orgs_use_their_own_tokens(agent, monkeypatch):
    used = []

    async def fake_execute(name, inputs, context):
        token_at_start = agent.gitlab_collector.token
        await asyncio.sleep(0.01)
        used.append((context["org_id"], token_at_start, agent.gitlab_collector.token, os.getenv("GITLAB_TOKEN")))
        return {"ok": True}

    monkeypatch.setattr(agent, "_execute_tool", fake_execute)
    await asyncio.gather(*[
        agent.execute_tool("get_gitlab_pipeline", {}, {"org_id": org})
        for org in ("org-a", "org-b", "org-a", "org-b")
    ])
    for org, start, end, env in used:
        assert start == end == env == f"{org}-gitlab"
