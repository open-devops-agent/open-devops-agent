"""Agent-level approval and emergency-stop boundaries for host operations."""

import ast
import asyncio
import base64
import importlib
import inspect
import json
import re
import runpy
import shlex
import sys
import textwrap

import pytest
import httpx

from agent.core import AGENT_TOOLS, DevOpsAgent
from tools.disk_cleanup import DiskCleanup
from tools.executor import SafeExecutor
from tools.nginx_tools import NginxTools
from tools.notify import SlackNotifier
from tools.safety import MUTATING_AGENT_TOOLS
from tools.security_updates import SecurityUpdates
from services.org_context import org_credentials
from storage.memory_storage import MemoryStorage

HOST_TOOL_TYPES = {
    "disk_cleanup": DiskCleanup,
    "nginx_tools": NginxTools,
    "security_updates": SecurityUpdates,
}
SCHEMAS = {tool["name"]: tool["input_schema"] for tool in AGENT_TOOLS}


def dispatched_tools():
    """Enumerate literal name branches and their directly referenced handlers."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(DevOpsAgent._execute_tool)))
    dispatch = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        test = node.test
        if not (
            isinstance(test.left, ast.Name)
            and test.left.id == "name"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.comparators[0], ast.Constant)
        ):
            continue
        dispatch[test.comparators[0].value] = {
            ref.attr
            for statement in node.body
            for ref in ast.walk(statement)
            if isinstance(ref, ast.Attribute)
            and isinstance(ref.value, ast.Name)
            and ref.value.id == "self"
        }
    return dispatch


DISPATCH = dispatched_tools()
HOST_MUTATIONS = sorted(
    name
    for name, handlers in DISPATCH.items()
    if name in MUTATING_AGENT_TOOLS and handlers & HOST_TOOL_TYPES.keys()
)
DRY_RUN_MUTATIONS = [
    name for name in HOST_MUTATIONS if "dry_run" in SCHEMAS[name]["properties"]
]

# Every new dispatch must be reviewed as mutating or explicitly exempted here.
# restore_from_snapshot always refuses execution; commander selection only reads
# the roster. Notifications and suggestions are deliberately available in a stop.
NON_MUTATING_DISPATCH = {
    "get_k8s_context",
    "get_github_logs",
    "get_cicd_logs",
    "get_argocd_status",
    "get_argocd_history",
    "get_helm_release",
    "terraform_validate",
    "terraform_plan",
    "get_cloud_resource",
    "inspect_disk_usage",
    "diagnose_nginx",
    "bamboo_check_version",
    "query_metrics",
    "evaluate_slo",
    "capacity_check",
    "query_traces",
    "query_logs",
    "detect_threats",
    "run_synthetic",
    "get_oncall_roster",
    "assign_incident_commander",
    "check_database_health",
    "list_snapshots",
    "restore_from_snapshot",
    "dr_readiness_check",
    "kafka_health",
    "elasticsearch_health",
    "redis_health",
    "fetch_code_change",
    "list_open_code_changes",
    "suggest_fix",
    "notify_slack",
}


def test_mutating_safety_set_reconciles_with_agent_dispatch_and_registration():
    assert set(DISPATCH) == set(SCHEMAS)
    assert not NON_MUTATING_DISPATCH & MUTATING_AGENT_TOOLS
    assert set(DISPATCH) - NON_MUTATING_DISPATCH == MUTATING_AGENT_TOOLS & set(DISPATCH)
    assert HOST_MUTATIONS
    assert DRY_RUN_MUTATIONS


class RecordingRunner:
    def __init__(self):
        self.calls = []
        self.allow_mutations = False
        self.forbid_all = False
        self.fail_prefix = None
        self.find_stdout = "/var/log/syslog.1.gz\n"

    async def __call__(self, command, host):
        self.calls.append((command, host))
        read_only = command in {
            "nginx -t",
            "systemctl is-active nginx 2>/dev/null || true",
            "systemctl status nginx --no-pager -l | tail -40",
            "journalctl -u nginx -n 40 --no-pager",
            "certbot certificates 2>/dev/null || echo 'certbot not available'",
            "certbot renew --dry-run --non-interactive --agree-tos",
            "unattended-upgrade --dry-run 2>/dev/null || apt-get -s upgrade",
        } or bool(
            re.fullmatch(
                r"find /var/log -type f \\\( -name '\*\.gz' -o -name '\*\.xz' "
                r"-o -name '\*\.bz2' -o -name '\*\.1' -o -name '\*\.old' "
                r"-o -name '\*\.rotated' \\\) -mtime \+[1-9][0-9]* -print",
                command,
            )
        )
        assert not self.forbid_all, f"Command ran before operation approval: {command}"
        assert self.allow_mutations or read_only, f"Unapproved mutation: {command}"
        stdout = self.find_stdout if command.startswith("find ") else "active"
        ok = not self.fail_prefix or not command.startswith(self.fail_prefix)
        return {
            "success": ok,
            "returncode": 0 if ok else 1,
            "stdout": stdout,
            "stderr": "",
        }


@pytest.fixture
def agent(monkeypatch):
    # Keep public execute_tool's real org scope, with isolated in-memory config.
    monkeypatch.setattr(
        "services.org_context.resolve_org_credentials", lambda *args: {}
    )
    monkeypatch.delenv("AGENT_EMERGENCY_STOP", raising=False)
    monkeypatch.delenv("AUTO_APPLY", raising=False)
    storage = MemoryStorage()
    monkeypatch.setattr("storage.factory.get_storage", lambda: storage)
    for key in ("CERTBOT_DNS_PLUGIN", "CERTBOT_WILDCARD_DOMAINS"):
        monkeypatch.delenv(key, raising=False)
    instance = DevOpsAgent.__new__(DevOpsAgent)
    runner = RecordingRunner()
    for attr, tool_type in HOST_TOOL_TYPES.items():
        setattr(instance, attr, tool_type(runner=runner))
    return instance, runner


@pytest.fixture
def approval_executor(agent, monkeypatch, tmp_path, capsys):
    """Keep SafeExecutor.run real; emulate only its subprocess exit boundary."""
    _, runner = agent
    for tool_type in HOST_TOOL_TYPES.values():
        monkeypatch.setattr(
            importlib.import_module(tool_type.__module__),
            tool_type.__name__,
            lambda cls=tool_type: cls(runner=runner),
        )

    async def approved_exec(command, host=None):
        argv = shlex.split(command)
        assert argv[:2] == [sys.executable, "-c"]
        assert len(argv) == 3
        assert host is None
        script = tmp_path / "approved_operation.py"
        script.write_text(argv[2])

        def run_script():
            try:
                runpy.run_path(str(script), run_name="__main__")
            except SystemExit as exc:
                return exc.code if isinstance(exc.code, int) else 1
            return 0

        capsys.readouterr()
        status = await asyncio.to_thread(run_script)
        return {
            "success": status == 0,
            "returncode": status,
            "stdout": capsys.readouterr().out,
            "stderr": "",
            "command": command,
        }

    executor = SafeExecutor()
    monkeypatch.setattr(executor, "_exec", approved_exec)
    return executor


def tool_inputs(name):
    values = {
        "file_path": "/etc/nginx/sites-enabled/app",
        "new_content": "server { listen 80; }\n",
    }
    return {key: values[key] for key in SCHEMAS[name].get("required", [])}


@pytest.mark.asyncio
@pytest.mark.parametrize("name", HOST_MUTATIONS)
@pytest.mark.parametrize("auto_apply", [None, "false"], ids=["default", "disabled"])
@pytest.mark.parametrize("host_source", ["inputs", "context"])
async def test_live_host_mutation_requires_approval(
    agent, monkeypatch, name, auto_apply, host_source
):
    instance, runner = agent
    if auto_apply is not None:
        monkeypatch.setenv("AUTO_APPLY", auto_apply)
    runner.forbid_all = True
    inputs = tool_inputs(name)
    if name in DRY_RUN_MUTATIONS:
        inputs["dry_run"] = False
    # A fake dry_run input cannot bypass operations without a dry_run schema.
    else:
        inputs["dry_run"] = True
    context = {}
    (inputs if host_source == "inputs" else context)["host"] = "203.0.113.10"

    result = await instance.execute_tool(name, inputs, context)

    assert runner.calls == [], result
    assert result.get("blocked") is True
    assert result.get("requires_approval") is True
    assert set(result) == {
        "blocked",
        "requires_approval",
        "command",
        "approval_payload",
        "message",
    }
    assert base64.b64decode(result["approval_payload"]).decode() == result["command"]
    assert "203.0.113.10" in result["command"]
    assert result["message"]


@pytest.mark.asyncio
async def test_approved_host_mutation_uses_agent_interpreter(agent, monkeypatch):
    instance, runner = agent
    monkeypatch.setenv("AUTO_APPLY", "false")
    runner.forbid_all = True
    approval = await instance.execute_tool("restart_nginx", {"host": "203.0.113.15"})
    assert approval["requires_approval"] is True
    assert runner.calls == []
    commands = []

    async def capture_command(command, host=None):
        commands.append(command)
        return {"success": True, "returncode": 0}

    executor = SafeExecutor()
    monkeypatch.setattr(executor, "_exec", capture_command)
    result = await executor.run(approval["command"])

    assert result["success"] is True
    assert len(commands) == 1
    assert commands[0].startswith(f"{shlex.quote(sys.executable)} -c ")
    assert shlex.split(commands[0])[:2] == [sys.executable, "-c"]


@pytest.mark.asyncio
async def test_approved_host_mutation_quotes_interpreter(agent, monkeypatch):
    instance, runner = agent
    monkeypatch.setenv("AUTO_APPLY", "false")
    interpreter = "python env's/bin/python3"
    monkeypatch.setattr("agent.core.sys.executable", interpreter)
    runner.forbid_all = True
    approval = await instance.execute_tool("restart_nginx", {"host": "203.0.113.16"})
    assert approval["requires_approval"] is True
    assert runner.calls == []
    commands = []

    async def capture_command(command, host=None):
        commands.append(command)
        return {"success": True, "returncode": 0}

    executor = SafeExecutor()
    monkeypatch.setattr(executor, "_exec", capture_command)
    result = await executor.run(approval["command"])

    assert result["success"] is True
    assert len(commands) == 1
    assert commands[0].startswith(f"{shlex.quote(interpreter)} -c ")
    assert shlex.split(commands[0])[:2] == [interpreter, "-c"]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", HOST_MUTATIONS)
async def test_auto_apply_allows_live_host_mutation(agent, monkeypatch, name):
    instance, runner = agent
    monkeypatch.setenv("AUTO_APPLY", "true")
    runner.allow_mutations = True
    inputs = {**tool_inputs(name), "host": "203.0.113.11"}
    if name in DRY_RUN_MUTATIONS:
        inputs["dry_run"] = False

    result = await instance.execute_tool(name, inputs)

    assert result.get("success", result.get("applied")) is True, result
    assert not result.get("blocked")
    assert runner.calls
    assert all(host == "203.0.113.11" for _, host in runner.calls)
    assert any(
        not command.startswith(
            (
                "find ",
                "nginx -t",
                "certbot certificates",
                "systemctl is-active",
                "systemctl status",
                "journalctl -u",
            )
        )
        for command, _ in runner.calls
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("name", HOST_MUTATIONS)
async def test_approval_replays_complete_host_operation(agent, approval_executor, name):
    instance, runner = agent
    runner.forbid_all = True
    inputs = {**tool_inputs(name), "host": "203.0.113.14"}
    if name in DRY_RUN_MUTATIONS:
        inputs["dry_run"] = False
    if name == "restart_nginx":
        inputs.update(
            config_path="/etc/nginx/sites-enabled/app",
            config_content="server { listen 80; }\n",
            reload_only=True,
        )
    approval = await instance.execute_tool(name, inputs)
    assert runner.calls == [], approval
    assert approval.get("requires_approval") is True

    runner.forbid_all = False
    runner.allow_mutations = True
    result = await approval_executor.run(approval["command"])

    assert result["success"] is True
    assert result["returncode"] == 0
    operation_result = json.loads(result["stdout"])
    assert operation_result.get("success", operation_result.get("applied")) is True
    assert runner.calls
    assert all(host == "203.0.113.14" for _, host in runner.calls)
    if name in {"apply_nginx_config", "restart_nginx"}:
        commands = [command for command, _ in runner.calls]
        write_index = next(
            i for i, command in enumerate(commands) if "write_bytes" in command
        )
        assert write_index < commands.index("nginx -t")
        assert commands[-1] == "systemctl reload nginx"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", DRY_RUN_MUTATIONS)
@pytest.mark.parametrize("dry_run", [None, True], ids=["default", "explicit"])
@pytest.mark.parametrize("auto_apply", ["false", "true"])
async def test_host_dry_run_remains_safe(agent, monkeypatch, name, dry_run, auto_apply):
    instance, runner = agent
    monkeypatch.setenv("AUTO_APPLY", auto_apply)
    inputs = {**tool_inputs(name), "host": "203.0.113.12"}
    if dry_run is not None:
        inputs["dry_run"] = dry_run

    result = await instance.execute_tool(name, inputs)

    assert result.get("dry_run") is True, result
    assert not result.get("blocked")
    assert not result.get("applied")


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(MUTATING_AGENT_TOOLS))
@pytest.mark.parametrize("auto_apply", ["false", "true"])
async def test_emergency_stop_blocks_every_mutating_agent_tool(
    agent, monkeypatch, name, auto_apply
):
    instance, runner = agent
    monkeypatch.setenv("AUTO_APPLY", auto_apply)
    monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
    runner.forbid_all = True

    result = await instance.execute_tool(
        name, {"dry_run": False, "host": "203.0.113.13"}
    )

    assert result.get("blocked") is True, result
    assert result.get("emergency_stop") is True, result
    assert result.get("requires_approval") is False
    assert runner.calls == []


@pytest.mark.asyncio
async def test_approved_nginx_rollback_signals_failure(agent, approval_executor):
    """Adapted reviewer reproducer: restored config must still exit nonzero."""
    instance, runner = agent
    runner.forbid_all = True
    approval = await instance.execute_tool(
        "apply_nginx_config",
        {
            "file_path": "/etc/nginx/sites-enabled/app",
            "new_content": "server { invalid_directive; }\n",
            "host": "203.0.113.23",
            "dry_run": True,
        },
    )
    assert approval["requires_approval"] is True
    assert runner.calls == []
    assert (
        base64.b64decode(approval["approval_payload"]).decode() == approval["command"]
    )
    runner.forbid_all = False
    runner.allow_mutations = True
    runner.fail_prefix = "nginx -t"

    result = await approval_executor.run(approval["command"])

    operation = json.loads(result["stdout"])
    assert operation["success"] is False and operation["restored"] is True
    commands = [command for command, host in runner.calls if host == "203.0.113.23"]
    assert len(commands) == len(runner.calls) == 4
    assert commands[0].startswith("cp ")
    assert "write_bytes" in commands[1]
    assert commands[2] == "nginx -t"
    assert commands[3].startswith("test -f ") and "mv " in commands[3]
    assert not any("systemctl reload" in command for command in commands)
    assert result["returncode"] != 0, operation
    assert result["success"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,arguments",
    [
        (
            "apply_nginx_config",
            {"file_path": "/opt/rejected.conf", "new_content": "server {}"},
        ),
        ("renew_certificates", {"dry_run": False, "domains": ["invalid domain"]}),
    ],
)
async def test_approved_invalid_arguments_fail_without_commands(
    agent, approval_executor, name, arguments
):
    instance, runner = agent
    runner.forbid_all = True
    approval = await instance.execute_tool(name, {**arguments, "host": "203.0.113.24"})
    assert runner.calls == []
    assert approval["requires_approval"] is True

    result = await approval_executor.run(approval["command"])

    assert json.loads(result["stdout"])["blocked"] is True
    assert result["returncode"] != 0
    assert result["success"] is False
    assert runner.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,fail_prefix,contract",
    [
        ("apply_security_updates", "unattended-upgrade", "success"),
        ("install_log_cleanup_cron", "cat >", "applied"),
    ],
)
async def test_approved_helper_command_failure_preserves_status(
    agent, approval_executor, name, fail_prefix, contract
):
    instance, runner = agent
    runner.forbid_all = True
    approval = await instance.execute_tool(
        name, {"dry_run": False, "host": "203.0.113.25"}
    )
    assert runner.calls == []
    runner.forbid_all = False
    runner.allow_mutations = True
    runner.fail_prefix = fail_prefix

    result = await approval_executor.run(approval["command"])

    assert json.loads(result["stdout"])[contract] is False
    assert result["returncode"] != 0
    assert result["success"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario,fail_prefix,expected_success",
    [
        ("vacuum-time", "journalctl --vacuum-time=", False),
        ("vacuum-size", "journalctl --vacuum-size=", False),
        ("delete", "rm -f --", False),
        ("protected", None, True),
        ("recheck", None, True),
    ],
)
async def test_approved_cleanup_result_controls_notification(
    agent, approval_executor, monkeypatch, scenario, fail_prefix, expected_success
):
    instance, runner = agent
    monkeypatch.setenv("AUTO_APPLY", "false")
    runner.forbid_all = True
    approval = await instance.execute_tool(
        "cleanup_stale_logs", {"dry_run": False, "host": "203.0.113.35"}
    )
    assert approval["requires_approval"] is True
    assert runner.calls == []
    if scenario == "protected":
        runner.find_stdout = "/var/log/production.log.1\n"
    elif scenario == "recheck":
        monkeypatch.setattr("tools.disk_cleanup.is_safe_stale_log", lambda path: False)
    runner.forbid_all = False
    runner.allow_mutations = True
    runner.fail_prefix = fail_prefix
    results, messages = [], []
    replay = approval_executor.run

    async def record_result(command, host=None):
        result = await replay(command, host=host)
        results.append(result)
        return result

    class Notifier:
        async def send_message(self, message):
            messages.append(message)

    monkeypatch.setattr(approval_executor, "run", record_result)
    instance.executor = approval_executor
    instance.notifier = Notifier()
    await instance.execute_approved_action("cleanup-approval", approval["command"])

    assert len(results) == 1
    result = results[0]
    assert result["success"] is expected_success, result
    assert (result["returncode"] == 0) is expected_success
    operation = json.loads(result["stdout"].splitlines()[-1])
    assert operation["applied"] is True
    assert len(messages) == 1
    if expected_success:
        assert "✅ Approved action executed" in messages[0]
        assert operation["deleted"] == []
        assert not any(command.startswith("rm ") for command, _ in runner.calls)
        if scenario == "protected":
            assert operation["alerts"][0]["status"] == "protected"
            assert operation["skipped"] == []
        else:
            assert operation["skipped"][0]["reason"]
            assert "error" not in operation["skipped"][0]
    else:
        assert "❌ Approved action failed" in messages[0]
        assert "Approved action executed" not in messages[0]
        assert any(command.startswith(fail_prefix) for command, _ in runner.calls)
        if scenario == "delete":
            assert "error" in operation["skipped"][0]
        else:
            assert any(item["success"] is False for item in operation["journal"])
    assert all(host == "203.0.113.35" for _, host in runner.calls)


@pytest.mark.asyncio
async def test_approved_failure_notification_reports_failure(agent, approval_executor):
    instance, runner = agent
    runner.forbid_all = True
    approval = await instance.execute_tool(
        "apply_security_updates", {"dry_run": False, "host": "203.0.113.25"}
    )
    assert runner.calls == []
    runner.forbid_all = False
    runner.allow_mutations = True
    runner.fail_prefix = "unattended-upgrade"
    messages = []

    class Notifier:
        async def send_message(self, message):
            messages.append(message)

    instance.executor = approval_executor
    instance.notifier = Notifier()
    await instance.execute_approved_action("approval-test", approval["command"])

    assert len(messages) == 1
    assert "❌ Approved action failed" in messages[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["apply_nginx_config", "restart_nginx"])
@pytest.mark.parametrize("comment_size", [2 * 1024, 32 * 1024])
async def test_large_config_approval_fits_slack_and_preserves_exact_operation(
    agent, approval_executor, monkeypatch, name, comment_size
):
    instance, runner = agent
    runner.forbid_all = True
    config = "# " + "x" * comment_size + "\nserver { listen 80; }\n"
    if name == "apply_nginx_config":
        inputs = {"file_path": "/etc/nginx/sites-enabled/app", "new_content": config}
    else:
        inputs = {
            "config_path": "/etc/nginx/sites-enabled/app",
            "config_content": config,
            "reload_only": True,
        }
    inputs["host"] = "203.0.113.26"
    approval = await instance.execute_tool(name, inputs, {"org_id": "approval-owner"})
    assert approval["requires_approval"] is True
    assert runner.calls == []
    requests = []

    def receive(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200)

    transport = httpx.MockTransport(receive)
    client_type = httpx.AsyncClient
    monkeypatch.setattr(
        "tools.notify.httpx.AsyncClient",
        lambda **kwargs: client_type(transport=transport, **kwargs),
    )
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://slack.example/webhook")
    with org_credentials("approval-owner"):
        await SlackNotifier().send_approval_request(
            "Apply reviewed nginx configuration",
            approval["command"],
            approval["approval_payload"],
        )
    buttons = [
        element
        for block in requests[0]["blocks"]
        if block["type"] == "actions"
        for element in block["elements"]
        if element["action_id"] == "approve_action"
    ]
    assert len(buttons) == 1
    assert len(buttons[0]["value"]) <= 2000
    envelope = json.loads(buttons[0]["value"])
    assert envelope["org_id"] == "approval-owner"
    command = base64.b64decode(envelope["command"]).decode()
    assert command == approval["command"]
    # Later caller edits cannot alter what this approval authorizes.
    inputs[next(key for key in inputs if key in {"new_content", "config_content"})] = (
        "changed"
    )
    inputs["host"] = "203.0.113.99"
    runner.forbid_all = False
    runner.allow_mutations = True
    with org_credentials("approval-owner"):
        result = await approval_executor.run(command)

    assert result["success"] is True
    encoded_config = base64.b64encode(config.encode()).decode()
    assert any(encoded_config in command for command, _ in runner.calls)
    assert all(host == "203.0.113.26" for _, host in runner.calls)
    assert runner.calls[-1][0] == "systemctl reload nginx"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "misuse", ["other-org", "other-host", "changed-reference", "missing-reference"]
)
async def test_retained_approval_rejects_rebinding(agent, approval_executor, misuse):
    instance, runner = agent
    runner.forbid_all = True
    approval = await instance.execute_tool(
        "restart_nginx", {"host": "203.0.113.27"}, {"org_id": "approval-owner"}
    )
    assert runner.calls == []
    command = approval["command"]
    if misuse == "changed-reference":
        command = command.replace("203.0.113.27", "203.0.113.28")
    elif misuse == "missing-reference":
        command = "agent-approval:" + "0" * 32 + " (203.0.113.27)"
    org = "different-org" if misuse == "other-org" else "approval-owner"
    with org_credentials(org):
        result = await approval_executor.run(
            command, host="203.0.113.28" if misuse == "other-host" else None
        )

    assert result.get("blocked") is True, result
    assert result.get("success") is False
    assert runner.calls == []


@pytest.mark.asyncio
async def test_emergency_stop_blocks_retained_approval_replay(
    agent, approval_executor, monkeypatch
):
    instance, runner = agent
    runner.forbid_all = True
    approval = await instance.execute_tool("restart_nginx", {"host": "203.0.113.29"})
    assert runner.calls == []
    monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")

    result = await approval_executor.run(approval["command"])

    assert result["blocked"] is True
    assert result["emergency_stop"] is True
    assert runner.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command",
    [
        "find /var/log -type f -delete",
        "find /var/log -type f -exec rm {} ;",
        "certbot renew --dry-run; systemctl restart nginx",
        "nginx -t; systemctl restart nginx",
        "unattended-upgrade --dry-run && systemctl restart nginx",
    ],
)
async def test_recording_runner_rejects_mutating_read_only_lookalikes(command):
    runner = RecordingRunner()
    with pytest.raises(AssertionError, match="Unapproved mutation"):
        await runner(command, "203.0.113.30")
