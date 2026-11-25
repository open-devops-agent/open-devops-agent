"""Secret values never reach the model, logs or Slack without a human approving the read (#191)."""
import pytest

from services.pii_scrubber import REDACTED_SECRET, scrub_text, scrub_value
from tools.executor import SafeExecutor, reads_secret_values

NEEDS_APPROVAL = [
    "kubectl get secret db-creds -o yaml",
    "kubectl get secrets -A -o json",
    "kubectl -n prod get secret/db -ojson",
    "kubectl get secret db -o jsonpath={.data.password}",
    "kubectl get secret db -o go-template={{.data}}",
    "kubectl get secret db --template={{.data}}",
    "kubectl get secrets --output=json",
    "kubectl get secrets.v1 -o json",
    "kubectl get all,secrets -n prod -o yaml",
    "kubectl get secret,pods -o yaml",
    "kubectl get secret db --output yaml | grep pass",
    "uptime; kubectl get secret x -o yaml",
]

STAYS_SAFE = [
    "kubectl get secrets",
    "kubectl get secrets -n prod",
    "kubectl get secrets -o name",
    "kubectl get secret -o wide",
    "kubectl describe secret db",
    "kubectl get pods -o yaml",
    "kubectl get pod my-secrets-app -o yaml",
    "kubectl get configmap secret-config -o yaml",
    "kubectl logs secret-rotator",
    "kubectl get deploy -l app=secrets -o json",
]


@pytest.mark.parametrize("command", NEEDS_APPROVAL)
def test_reading_secret_values_requires_approval(command):
    assert reads_secret_values(command)
    assert SafeExecutor()._classify(command) == "requires_approval"


@pytest.mark.parametrize("command", STAYS_SAFE)
def test_names_and_ordinary_reads_stay_safe(command):
    assert not reads_secret_values(command)
    assert SafeExecutor()._classify(command) == "safe"


@pytest.mark.asyncio
async def test_secret_read_does_not_auto_run(monkeypatch):
    monkeypatch.delenv("AGENT_EMERGENCY_STOP", raising=False)
    executor = SafeExecutor()
    executor.auto_apply = True
    ran = []

    async def fake_exec(command, host=None):
        ran.append(command)
        return {"success": True}

    executor._exec = fake_exec
    result = await executor.run_safe("kubectl get secrets -A -o yaml")
    assert ran == [] and result["requires_approval"] is True


YAML_SECRET = """apiVersion: v1
data:
  password: aHVudGVyMg==
  username: YWRtaW4=
kind: Secret
metadata:
  name: db-creds
type: Opaque"""

JSON_SECRET = (
    '{"apiVersion": "v1", "kind": "Secret", "data": {"password": "aHVudGVyMg==", '
    '"username": "YWRtaW4="}, "metadata": {"name": "db"}}'
)

LIST_SECRET = """apiVersion: v1
items:
- apiVersion: v1
  data:
    tls.crt: LS0tLS1CRUdJTiBDRVJU
    tls.key: LS0tLS1CRUdJTiBQUklW
  kind: Secret
  metadata:
    name: tls
kind: List"""


def test_yaml_secret_data_is_redacted_but_keys_kept():
    out = scrub_text(YAML_SECRET)
    assert "aHVudGVyMg==" not in out and "YWRtaW4=" not in out
    assert f"password: {REDACTED_SECRET}" in out and f"username: {REDACTED_SECRET}" in out
    assert "name: db-creds" in out


def test_json_secret_data_is_redacted():
    out = scrub_text(JSON_SECRET)
    assert "aHVudGVyMg==" not in out and '"password": "[REDACTED_SECRET]"' in out
    assert '"name": "db"' in out


def test_secret_list_items_are_redacted():
    out = scrub_text(LIST_SECRET)
    assert "LS0tLS1" not in out and f"tls.key: {REDACTED_SECRET}" in out


def test_configmap_data_is_untouched():
    cm = "kind: ConfigMap\ndata:\n  level: debug"
    assert scrub_text(cm) == cm


@pytest.mark.parametrize("text, leaked", [
    ("    env:\n    - name: DB_PASSWORD\n      value: hunter2\n    - name: LOG_LEVEL\n      value: debug", "hunter2"),
    ('{"name": "STRIPE_API_KEY", "value": "abc123xyz"}', "abc123xyz"),
    ('"Env": ["DB_PASSWORD=hunter2", "PATH=/usr/bin"]', "hunter2"),
    ("GITHUB_TOKEN=abcdef123456\nHOME=/root", "abcdef123456"),
])
def test_secret_named_env_values_are_redacted(text, leaked):
    out = scrub_text(text)
    assert leaked not in out and REDACTED_SECRET in out


def test_non_secret_env_values_are_kept():
    text = '"Env": ["PATH=/usr/bin", "LOG_LEVEL=debug"]'
    assert scrub_text(text) == text


def test_tool_results_are_redacted_recursively():
    result = {"success": True, "stdout": YAML_SECRET, "nested": [JSON_SECRET]}
    out = scrub_value(result)
    assert "aHVudGVyMg==" not in str(out)


@pytest.mark.asyncio
async def test_approved_secret_read_is_redacted_in_slack(monkeypatch):
    from unittest.mock import AsyncMock

    from agent.core import DevOpsAgent

    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy-test-key")
    agent = DevOpsAgent()
    agent.executor.run = AsyncMock(return_value={"success": True, "stdout": YAML_SECRET})
    agent.notifier.send_message = AsyncMock()
    await agent.execute_approved_action("INC-1", "kubectl get secret db-creds -o yaml", org_id="default")
    message = agent.notifier.send_message.call_args.args[0]
    assert "aHVudGVyMg==" not in message and REDACTED_SECRET in message
