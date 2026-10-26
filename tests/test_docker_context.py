import os

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest

from collectors.docker import parse_build_error
from agent.core import DevOpsAgent
from services.pii_scrubber import scrub_dict


CONTEXT = {
    "type": "cicd",
    "labels": {"cicd_platform": "github"},
    "repo": "203.0.113.10/org/repo",
    "run_id": 12345,
}

FAILED_DOCKER_LOG = (
    "Step 1/2 : FROM python:3.11-slim\n"
    " ---> Using cache\n"
    "Step 2/2 : RUN pip install -r requirements.txt\n"
    + "Collecting application dependencies\n" * 100
    + "ERROR: Could not find a version that satisfies the requirement missing-package\n"
    "ERROR: No matching distribution found for missing-package\n"
    "failed to install application dependencies\n"
    "The command '/bin/sh -c pip install -r requirements.txt' returned a non-zero code: 1\n"
)


FAILED_BUILDKIT_STEP_LOG = (
    "#5 [1/5] FROM python:3.11-slim\n"
    "#5 DONE 0.1s\n"
    "#6 [2/5] COPY requirements.txt .\n"
    "#6 DONE 0.0s\n"
    "#7 [3/5] RUN pip install -r requirements.txt\n"
    "#7 0.526 Collecting application dependencies\n"
    "#7 0.789 ERROR: No matching distribution found for missing-package\n"
    '#7 ERROR: process "/bin/sh -c pip install -r requirements.txt" '
    "did not complete successfully: exit code: 1\n"
)

FAILED_BUILDKIT_LOG = (
    FAILED_BUILDKIT_STEP_LOG
    + "------\n"
    " > [3/5] RUN pip install -r requirements.txt:\n"
    "0.789 ERROR: No matching distribution found for missing-package\n"
    "------\n"
    "Dockerfile:4\n"
    "--------------------\n"
    "   2 |     FROM python:3.11-slim\n"
    "   3 |     COPY requirements.txt .\n"
    "   4 | >>> RUN pip install -r requirements.txt\n"
    "--------------------\n"
    'ERROR: failed to solve: process "/bin/sh -c pip install -r requirements.txt" '
    "did not complete successfully: exit code: 1\n"
)

SUCCESSFUL_BUILDKIT_LOG = (
    "#5 [1/3] FROM python:3.11-slim\n"
    "#5 DONE 0.1s\n"
    "#6 [2/3] COPY requirements.txt .\n"
    "#6 DONE 0.0s\n"
    "#7 [3/3] RUN pip install -r requirements.txt\n"
    "#7 0.526 Collecting application dependencies\n"
    "#7 0.789 Successfully installed application dependencies\n"
    "#7 DONE 1.0s\n"
)

FAILED_TO_SOLVE_LOG = "ERROR: failed to solve: no build stage in current context\n"

SUCCESSFUL_DOCKER_LOG = (
    "Step 1/2 : FROM python:3.11-slim\n"
    " ---> Using cache\n"
    "Step 2/2 : RUN pip install -r requirements.txt\n"
    "Successfully installed application dependencies\n"
    "Successfully built abc123\n"
)

# Each failing log carries a decoy step line after the failure so that neither
# "first step" nor "last step anywhere" selection can pass.
FAILED_DOCKER_RETRY_LOG = (
    "Step 1/2 : FROM python:3.11-slim\n"
    " ---> Using cache\n"
    "Step 2/2 : RUN pip install -r requirements.txt\n"
    "ERROR: Could not find a version that satisfies the requirement missing-package\n"
    "Retrying build\n"
    "Step 1/1 : FROM debian:bookworm\n"
)

# #8 runs in parallel with #7 and prints step lines between #7's start and its
# failure, so only the #7 ERROR line's step id picks the failing step. #70 sits
# above #7 so id-prefix matching without the delimiter would pick it, and the
# embedded "--- #9 ERROR ---" line is not a step-id anchor (only a line starting
# with the id is).
FAILED_BUILDKIT_PARALLEL_LOG = (
    "#5 [1/5] FROM python:3.11-slim\n"
    "#5 DONE 0.1s\n"
    "#6 [2/5] COPY requirements.txt .\n"
    "#6 DONE 0.0s\n"
    "#70 [4/5] RUN apt-get upgrade -y\n"
    "#7 [3/5] RUN pip install -r requirements.txt\n"
    "#8 [4/5] RUN apt-get update\n"
    "#7 0.526 Collecting application dependencies\n"
    "--- #9 ERROR ---\n"
    "#7 0.789 ERROR: No matching distribution found for missing-package\n"
    '#7 ERROR: process "/bin/sh -c pip install -r requirements.txt" '
    "did not complete successfully: exit code: 1\n"
    "Retrying build\n"
    "#9 [1/2] FROM debian:bookworm\n"
)

FAILED_BUILDKIT_NO_ERROR_LOG = (
    "#5 [1/5] FROM python:3.11-slim\n"
    "#5 DONE 0.1s\n"
    "#6 [2/5] COPY requirements.txt .\n"
    "#6 DONE 0.0s\n"
    "#7 [3/5] RUN pip install -r requirements.txt\n"
    "#7 0.526 Collecting application dependencies\n"
    "ERROR: No matching distribution found for missing-package\n"
    "Retrying build\n"
    "#9 [1/2] FROM debian:bookworm\n"
)

# No error lines: parse falls back to the marker ladder, classic before BuildKit.
MIXED_MARKERS_NO_ERROR_LOG = (
    "#5 [1/5] FROM python:3.11-slim\n"
    "#5 DONE 0.1s\n"
    "Step 1/2 : FROM python:3.11-slim\n"
    " ---> Using cache\n"
)

GHA_TIMESTAMP = "2026-10-23T12:00:00.1234567Z "


def timestamped(log: str) -> str:
    return "".join(GHA_TIMESTAMP + line + "\n" for line in log.splitlines())


# Near-miss prefixes that are not GitHub Actions timestamps: time-only (no date),
# a space instead of T, no space after Z, leading log text, a lowercase z, a tab
# after Z (the prefix ends with exactly one space), and letters inside the time
# part (the tail accepts only digits and : .).
TIMESTAMP_DECOY_LINES = (
    "12:00:00Z #7 [3/5] RUN pip install -r requirements.txt\n"
    "2026-10-23 12:00:00.1234567Z #7 [3/5] RUN pip install -r requirements.txt\n"
    "2026-10-23T12:00:00.1234567Z#7 [3/5] RUN pip install -r requirements.txt\n"
    "log 2026-10-23T12:00:00Z #7 [3/5] RUN pip install -r requirements.txt\n"
    "2026-10-23T12:00:00.1234567z #7 [3/5] RUN pip install -r requirements.txt\n"
    "2026-10-23T12:00:00.1234567Z\t#7 [3/5] RUN pip install -r requirements.txt\n"
    "2026-10-23T12a3Z #7 [3/5] RUN pip install -r requirements.txt\n"
)

# A warning line between steps carries none of the error keywords, so it is not
# an error line: the failing step stays the last step line before the first real
# error line.
WARNING_BETWEEN_STEPS_LOG = (
    "#5 [1/5] FROM python:3.11-slim\n"
    "#5 DONE 0.1s\n"
    "#6 [2/5] COPY requirements.txt .\n"
    "#6 0.100 deprecation warning: field X is deprecated\n"
    "#6 DONE 0.0s\n"
    "#7 [3/5] RUN pip install -r requirements.txt\n"
    "#7 0.526 Collecting application dependencies\n"
    "ERROR: No matching distribution found for missing-package\n"
)


@pytest.fixture
def ci_logs():
    return {
        "run_id": 12345,
        "workflow": "Build and test",
        "branch": "main",
        "commit": "abc12345",
        "trigger": "push",
        "url": "https://203.0.113.10/org/repo/actions/runs/12345",
        "failed_jobs": [
            {
                "name": "Build image",
                "steps": [{"name": "Build", "conclusion": "failure", "number": 2}],
                "logs": FAILED_DOCKER_LOG,
            }
        ],
    }


class TestDockerContext:
    @pytest.mark.asyncio
    async def test_docker_fragments_are_scrubbed_before_tail_slicing(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        begin = "-----BEGIN PRIVATE KEY-----"
        end = "-----END PRIVATE KEY-----"
        body_line = "A" * 64
        inline_body = "B" * 32
        log = (
            "Step 1/2 : FROM python:3.11-slim\n"
            + begin + "\n"
            + (body_line + "\n") * 60
            + end + "\n"
            "Step 2/2 : RUN make\n"
            + "ERROR: failed to build " + begin + inline_body + end + "\n"
        )
        # The raw tail loses BEGIN while retaining synthetic body lines.
        assert log.index(begin) < len(log) - 3000 < log.index(end)
        ci_logs["failed_jobs"][0]["logs"] = log

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)
        scrubbed = scrub_dict(enriched)

        assert scrubbed["docker_build_error"]["errors"] == [
            "ERROR: failed to build [REDACTED_PRIVATE_KEY]",
        ]

        def assert_scrubbed(value):
            if isinstance(value, dict):
                for child in value.values():
                    assert_scrubbed(child)
            elif isinstance(value, list):
                for child in value:
                    assert_scrubbed(child)
            elif isinstance(value, str):
                assert body_line not in value
                assert inline_body not in value

        assert_scrubbed(scrubbed["ci_logs"])
        assert_scrubbed(scrubbed["docker_build_error"])

    @pytest.mark.asyncio
    async def test_failed_docker_build_adds_parsed_error(self, ci_logs, monkeypatch):
        # Docker-failed direction: the first matching failed log supplies exact parser values.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"].insert(0, {
            "name": "Build and test",
            "steps": [{"name": "Test", "conclusion": "failure", "number": 3}],
            "logs": SUCCESSFUL_DOCKER_LOG,
        })
        ci_logs["failed_jobs"].append({
            "name": "Build another image",
            "steps": [{"name": "Build", "conclusion": "failure", "number": 2}],
            "logs": "Step 1 : RUN make\nERROR: make failed\n",
        })

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "Step 2/2 : RUN pip install -r requirements.txt",
            "errors": [
                "ERROR: Could not find a version that satisfies the requirement missing-package",
                "ERROR: No matching distribution found for missing-package",
                "failed to install application dependencies",
            ],
            "raw": FAILED_DOCKER_LOG[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_non_docker_failure_keeps_context(self, ci_logs, monkeypatch):
        # Non-Docker direction: a failing Docker-related test is not a Docker build log.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = (
            "============================= test session starts =============================\n"
            "collected 2 items\n"
            "tests/test_docker.py::test_container_health FAILED\n"
            "E   AssertionError: container did not become healthy\n"
            "========================= 1 failed, 1 passed in 0.42s =========================\n"
        )

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("ci_logs") == ci_logs
        assert "docker_build_error" not in enriched
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_collector_failure_keeps_collection_error(self, monkeypatch):
        # Collector-failure direction: collection errors remain non-fatal without Docker data.
        agent = DevOpsAgent()

        async def fake_collect(repo, run_id):
            raise RuntimeError("CI collection unavailable")

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("collection_error") == "CI collection unavailable"
        assert "docker_build_error" not in enriched
        assert "ci_logs" not in enriched

    @pytest.mark.asyncio
    async def test_successful_docker_build_keeps_context(self, ci_logs, monkeypatch):
        # Successful Docker build direction: step markers alone do not add an error.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = SUCCESSFUL_DOCKER_LOG

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("ci_logs") == ci_logs
        assert "docker_build_error" not in enriched
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_failed_buildkit_build_adds_parsed_error(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = FAILED_BUILDKIT_LOG

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "#7 [3/5] RUN pip install -r requirements.txt",
            "errors": [
                "#7 0.789 ERROR: No matching distribution found for missing-package",
                '#7 ERROR: process "/bin/sh -c pip install -r requirements.txt" '
                "did not complete successfully: exit code: 1",
                "0.789 ERROR: No matching distribution found for missing-package",
                'ERROR: failed to solve: process "/bin/sh -c pip install -r requirements.txt" '
                "did not complete successfully: exit code: 1",
            ],
            "raw": FAILED_BUILDKIT_LOG[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_buildkit_step_without_summary_adds_error(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = FAILED_BUILDKIT_STEP_LOG

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "#7 [3/5] RUN pip install -r requirements.txt",
            "errors": [
                "#7 0.789 ERROR: No matching distribution found for missing-package",
                '#7 ERROR: process "/bin/sh -c pip install -r requirements.txt" '
                "did not complete successfully: exit code: 1",
            ],
            "raw": FAILED_BUILDKIT_STEP_LOG[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_successful_buildkit_build_keeps_context(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = SUCCESSFUL_BUILDKIT_LOG

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("ci_logs") == ci_logs
        assert "docker_build_error" not in enriched
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_failed_to_solve_without_steps_adds_error(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = FAILED_TO_SOLVE_LOG

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "ERROR: failed to solve: no build stage in current context",
            "errors": ["ERROR: failed to solve: no build stage in current context"],
            "raw": FAILED_TO_SOLVE_LOG[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_non_docker_failed_to_solve_without_colon_keeps_context(
        self, ci_logs, monkeypatch
    ):
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = "ERROR: failed to solve linear system\n"

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("ci_logs") == ci_logs
        assert "docker_build_error" not in enriched
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_buildkit_steps_after_preamble_add_truncated_error(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        log = (
            "Building application image\n"
            "#7 [3/5] RUN pip install -r requirements.txt\n"
            + "#7 0.526 Collecting application dependencies\n" * 100
            + "#7 0.789 ERROR: No matching distribution found for missing-package\n"
        )
        assert len(log) > 3000
        ci_logs["failed_jobs"][0]["logs"] = log

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "#7 [3/5] RUN pip install -r requirements.txt",
            "errors": ["#7 0.789 ERROR: No matching distribution found for missing-package"],
            "raw": log[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_buildkit_near_miss_steps_keep_context(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = (
            "prefix #7 [3/5] RUN pip install -r requirements.txt\n"
            "#7 [3/x] RUN pip install -r requirements.txt\n"
            "ERROR: No matching distribution found for missing-package\n"
        )

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("ci_logs") == ci_logs
        assert "docker_build_error" not in enriched
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "log, step, errors",
        [
            (
                "ERROR: failed to solve: no build stage in current context\n"
                "#7 [3/5] RUN pip install -r requirements.txt\n",
                "#7 [3/5] RUN pip install -r requirements.txt",
                ["ERROR: failed to solve: no build stage in current context"],
            ),
            (
                "#7 [3/5] RUN pip install -r requirements.txt\n"
                "Step 1/2 : FROM python:3.11-slim\n"
                "ERROR: No matching distribution found for missing-package\n",
                "Step 1/2 : FROM python:3.11-slim",
                ["ERROR: No matching distribution found for missing-package"],
            ),
        ],
        ids=["summary-before-buildkit", "buildkit-before-classic"],
    )
    async def test_mixed_build_markers_follow_ladder_precedence(
        self, ci_logs, monkeypatch, log, step, errors
    ):
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = log

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": step,
            "errors": errors,
            "raw": log[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_buildkit_summary_skips_colonless_solver_error(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        log = (
            "ERROR: failed to solve linear system\n"
            'ERROR: failed to solve: process "/bin/sh -c pip install -r requirements.txt" '
            "did not complete successfully: exit code: 1\n"
        )
        ci_logs["failed_jobs"][0]["logs"] = log

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": (
                'ERROR: failed to solve: process "/bin/sh -c pip install -r requirements.txt" '
                "did not complete successfully: exit code: 1"
            ),
            "errors": [
                "ERROR: failed to solve linear system",
                'ERROR: failed to solve: process "/bin/sh -c pip install -r requirements.txt" '
                "did not complete successfully: exit code: 1",
            ],
            "raw": log[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_buildkit_step_skips_embedded_and_malformed_markers(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        log = (
            "prefix #7 [3/5] RUN pip install -r requirements.txt\n"
            "#7 [3/x] RUN pip install -r requirements.txt\n"
            "#6 [2/5] COPY requirements.txt .\n"
            "ERROR: No matching distribution found for missing-package\n"
        )
        ci_logs["failed_jobs"][0]["logs"] = log

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "#6 [2/5] COPY requirements.txt .",
            "errors": ["ERROR: No matching distribution found for missing-package"],
            "raw": log[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_failed_docker_build_reports_failing_step(self, ci_logs, monkeypatch):
        # A retry's Step lines after the failure must not displace the failing one.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = FAILED_DOCKER_RETRY_LOG

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "Step 2/2 : RUN pip install -r requirements.txt",
            "errors": [
                "ERROR: Could not find a version that satisfies the requirement missing-package"
            ],
            "raw": FAILED_DOCKER_RETRY_LOG[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_failed_buildkit_build_reports_failing_step(self, ci_logs, monkeypatch):
        # #8 runs in parallel with #7, so only the #7 ERROR line's id picks #7's step line.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = FAILED_BUILDKIT_PARALLEL_LOG

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "#7 [3/5] RUN pip install -r requirements.txt",
            "errors": [
                "--- #9 ERROR ---",
                "#7 0.789 ERROR: No matching distribution found for missing-package",
                '#7 ERROR: process "/bin/sh -c pip install -r requirements.txt" '
                "did not complete successfully: exit code: 1",
            ],
            "raw": FAILED_BUILDKIT_PARALLEL_LOG[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_buildkit_without_error_line_reports_last_step_before_error(
        self, ci_logs, monkeypatch
    ):
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = FAILED_BUILDKIT_NO_ERROR_LOG

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "#7 [3/5] RUN pip install -r requirements.txt",
            "errors": ["ERROR: No matching distribution found for missing-package"],
            "raw": FAILED_BUILDKIT_NO_ERROR_LOG[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "log, step",
        [
            (FAILED_DOCKER_RETRY_LOG, "Step 2/2 : RUN pip install -r requirements.txt"),
            (FAILED_BUILDKIT_PARALLEL_LOG, "#7 [3/5] RUN pip install -r requirements.txt"),
            (FAILED_BUILDKIT_NO_ERROR_LOG, "#7 [3/5] RUN pip install -r requirements.txt"),
        ],
        ids=["classic", "buildkit-error-id", "buildkit-last-before-error"],
    )
    async def test_timestamped_lines_change_neither_trigger_nor_step(
        self, ci_logs, monkeypatch, log, step
    ):
        agent = DevOpsAgent()
        holder = {"logs": log}

        async def fake_collect(repo, run_id):
            return {
                "run_id": 12345,
                "workflow": "Build and test",
                "branch": "main",
                "commit": "abc12345",
                "trigger": "push",
                "url": "https://203.0.113.10/org/repo/actions/runs/12345",
                "failed_jobs": [{
                    "name": "Build image",
                    "steps": [{"name": "Build", "conclusion": "failure", "number": 2}],
                    "logs": holder["logs"],
                }],
            }

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        bare = await agent._collect_context(CONTEXT)
        holder["logs"] = timestamped(log)
        stamped = await agent._collect_context(CONTEXT)

        assert bare.get("docker_build_error", {}).get("step") == step
        assert stamped.get("docker_build_error", {}).get("step") == step

    @pytest.mark.asyncio
    async def test_github_actions_timestamped_buildkit_log_parses(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = timestamped(FAILED_BUILDKIT_LOG)

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "#7 [3/5] RUN pip install -r requirements.txt",
            "errors": [
                GHA_TIMESTAMP
                + "#7 0.789 ERROR: No matching distribution found for missing-package",
                GHA_TIMESTAMP
                + '#7 ERROR: process "/bin/sh -c pip install -r requirements.txt" '
                "did not complete successfully: exit code: 1",
                GHA_TIMESTAMP + "0.789 ERROR: No matching distribution found for missing-package",
                GHA_TIMESTAMP
                + 'ERROR: failed to solve: process "/bin/sh -c pip install -r requirements.txt" '
                "did not complete successfully: exit code: 1",
            ],
            "raw": timestamped(FAILED_BUILDKIT_LOG)[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_timestamped_step_lines_trigger_without_summary(self, ci_logs, monkeypatch):
        # No "failed to solve:" line: only the timestamped step lines can fire the trigger.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = timestamped(FAILED_BUILDKIT_STEP_LOG)

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "#7 [3/5] RUN pip install -r requirements.txt",
            "errors": [
                GHA_TIMESTAMP
                + "#7 0.789 ERROR: No matching distribution found for missing-package",
                GHA_TIMESTAMP
                + '#7 ERROR: process "/bin/sh -c pip install -r requirements.txt" '
                "did not complete successfully: exit code: 1",
            ],
            "raw": timestamped(FAILED_BUILDKIT_STEP_LOG)[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_timestamp_prefix_decoys_do_not_trigger(self, ci_logs, monkeypatch):
        # Near-miss prefixes (time-only, space for T, no space after Z, leading text)
        # are not GitHub Actions timestamps and must not make a step line match.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = TIMESTAMP_DECOY_LINES + (
            "ERROR: No matching distribution found for missing-package\n"
        )

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("ci_logs") == ci_logs
        assert "docker_build_error" not in enriched
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "near_miss_line",
        [
            "2026-10-23T12:00:00.1234567z #7 [3/5] RUN pip install -r requirements.txt\n",
            "2026-10-23T12:00:00.1234567Z\t#7 [3/5] RUN pip install -r requirements.txt\n",
        ],
        ids=["lowercase-z", "tab-after-z"],
    )
    async def test_near_miss_timestamp_tail_does_not_change_step(
        self, ci_logs, monkeypatch, near_miss_line
    ):
        # A valid timestamped step line fires the trigger; a near-miss tail
        # must not become a step line and flip the failing-step selection.
        agent = DevOpsAgent()
        log = (
            "2026-10-23T12:00:00.1234567Z #5 [1/5] FROM python:3.11-slim\n"
            + near_miss_line
            + "2026-10-23T12:00:00.1234567Z ERROR: No matching distribution found for missing-package\n"
        )
        ci_logs["failed_jobs"][0]["logs"] = log

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "#5 [1/5] FROM python:3.11-slim",
            "errors": [
                "2026-10-23T12:00:00.1234567Z ERROR: No matching distribution found for missing-package"
            ],
            "raw": log[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched


class TestParseBuildError:
    @pytest.mark.parametrize(
        "log, step",
        [
            (FAILED_DOCKER_RETRY_LOG, "Step 2/2 : RUN pip install -r requirements.txt"),
            (FAILED_BUILDKIT_PARALLEL_LOG, "#7 [3/5] RUN pip install -r requirements.txt"),
            (FAILED_BUILDKIT_NO_ERROR_LOG, "#7 [3/5] RUN pip install -r requirements.txt"),
        ],
        ids=["classic", "buildkit-error-id", "buildkit-last-before-error"],
    )
    def test_failing_step_selection(self, log, step):
        assert parse_build_error(log)["step"] == step
        assert parse_build_error(timestamped(log))["step"] == step

    def test_timestamp_prefix_decoys_are_not_step_lines(self):
        parsed = parse_build_error(
            TIMESTAMP_DECOY_LINES + "ERROR: No matching distribution found for missing-package\n"
        )
        assert parsed["step"] == "Unknown step"

    def test_no_error_ladder_prefers_classic_markers(self):
        # Without error lines the ladder falls back to the first step line,
        # classic markers before BuildKit markers regardless of log order.
        parsed = parse_build_error(MIXED_MARKERS_NO_ERROR_LOG)
        assert parsed["step"] == "Step 1/2 : FROM python:3.11-slim"
        assert parsed["errors"] == []

    def test_warning_line_is_not_an_error_line(self):
        parsed = parse_build_error(WARNING_BETWEEN_STEPS_LOG)
        assert parsed["step"] == "#7 [3/5] RUN pip install -r requirements.txt"
        assert parsed["errors"] == [
            "ERROR: No matching distribution found for missing-package"
        ]

    def test_timestamp_without_fraction_matches(self):
        parsed = parse_build_error(
            "2026-10-23T12:00:00Z #7 [3/5] RUN pip install -r requirements.txt\n"
            "2026-10-23T12:00:00Z ERROR: No matching distribution found for missing-package\n"
        )
        assert parsed["step"] == "#7 [3/5] RUN pip install -r requirements.txt"
        assert parsed["errors"] == [
            "2026-10-23T12:00:00Z ERROR: No matching distribution found for missing-package"
        ]
