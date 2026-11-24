"""Incident documentation is rendered in memory and stored with the incident's logs (#19)."""
from unittest.mock import MagicMock

from services.incident_store import IncidentStore
from storage.memory_storage import MemoryStorage
from tools.documentation_generator import render_incident_docs

CONTEXT = {"type": "k8s", "alertname": "PodCrashLooping", "severity": "critical", "source": "alertmanager"}
RESULT = {
    "resolved": True,
    "issue_type": "k8s",
    "diagnosis": "api pod OOMKilled: memory limit 256Mi is below the working set.",
    "fix_applied": True,
    "actions": [
        {"tool": "get_k8s_context", "input": {"namespace": "prod"}, "result": {"pods": []}},
        {"tool": "run_command", "input": {"command": "kubectl rollout restart deployment/api -n prod"},
         "result": {"executed": True, "success": True}},
        {"tool": "run_command", "input": {"command": "kubectl delete ns prod"},
         "result": {"permanently_blocked": True}},
    ],
    "suggested_fixes": [{"title": "Raise memory limit", "description": "Set limit to 512Mi",
                         "commands": ["kubectl set resources deployment/api --limits=memory=512Mi -n prod"],
                         "verification_steps": ["Pod stays Running for 10 minutes"]}],
    "verification": {"verified": True},
}


def test_renders_three_documents_from_the_real_run():
    docs = render_incident_docs("inc-1", CONTEXT, RESULT)
    assert set(docs) == {"postmortem.md", "runbook.md", "kb.md"}
    pm = docs["postmortem.md"]
    assert "PodCrashLooping" in pm and "OOMKilled" in pm and "Resolved" in pm
    assert "kubectl rollout restart deployment/api -n prod" in pm
    assert "kubectl delete ns prod" not in pm  # only commands that actually executed
    assert "Automatic verification passed" in pm
    assert "--limits=memory=512Mi" in docs["runbook.md"]
    assert "Pod stays Running for 10 minutes" in docs["runbook.md"]
    assert "kubectl rollout undo" in docs["runbook.md"]


def test_handles_a_sparse_failed_result():
    docs = render_incident_docs("inc-2", {"type": "server"}, {"resolved": False})
    assert "Unresolved" in docs["postmortem.md"]
    assert "No diagnosis recorded" in docs["kb.md"]


def test_security_findings_are_called_out():
    result = {**RESULT, "issue_type": "security", "resolved": False,
              "threat_findings": [{"rule": "crypto_mining", "severity": "critical", "mitre_technique": "T1496"}]}
    pm = render_incident_docs("inc-3", CONTEXT, result)["postmortem.md"]
    assert "crypto_mining (critical, T1496)" in pm and "preserve evidence" in pm


def test_save_document_stores_scrubbed_markdown_under_incident_logs():
    storage = MemoryStorage()
    store = IncidentStore(storage=storage)
    key = store.save_document("acme", "inc-1", "postmortem.md", "contact ops@example.com\n")
    assert key == storage.log_key("acme", "inc-1", "postmortem.md")
    assert "/logs/" in key and key.endswith("/inc-1/postmortem.md")
    assert "ops@example.com" not in storage.get_bytes(key).decode()


def _patched_server(monkeypatch, env):
    import api.server as server
    store = MagicMock()
    monkeypatch.setattr(server, "incident_store", store)
    if env is None:
        monkeypatch.delenv("AUTO_DOCUMENTATION", raising=False)
    else:
        monkeypatch.setenv("AUTO_DOCUMENTATION", env)
    return server, store


def test_server_saves_docs_by_default(monkeypatch):
    server, store = _patched_server(monkeypatch, None)
    server._save_incident_docs("acme", "inc-1", CONTEXT, RESULT)
    saved = [c.args[2] for c in store.save_document.call_args_list]
    assert saved == ["postmortem.md", "runbook.md", "kb.md"]


def test_server_respects_flag_and_skips_code_review(monkeypatch):
    server, store = _patched_server(monkeypatch, "false")
    server._save_incident_docs("acme", "inc-1", CONTEXT, RESULT)
    monkeypatch.setenv("AUTO_DOCUMENTATION", "true")
    server._save_incident_docs("acme", "inc-2", {"type": "code_review"}, {"issue_type": "code_review"})
    store.save_document.assert_not_called()


def test_storage_failure_never_breaks_the_incident(monkeypatch):
    server, store = _patched_server(monkeypatch, "true")
    store.save_document.side_effect = RuntimeError("bucket gone")
    server._save_incident_docs("acme", "inc-1", CONTEXT, RESULT)  # must not raise
