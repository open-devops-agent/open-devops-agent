"""SecurityScanner wiring + compliance checks (issue #6)."""

import os

import pytest

from collectors.security_scanner import SecurityScanner


@pytest.fixture
def scanner(monkeypatch):
    monkeypatch.setenv("ENABLE_SECURITY_SCANNING", "true")
    monkeypatch.setenv("ENABLE_COMPLIANCE_CHECKS", "true")
    monkeypatch.setenv("COMPLIANCE_FRAMEWORKS", "CIS,SOC2,PCI")
    return SecurityScanner()


def test_scanner_disabled_skips(monkeypatch):
    monkeypatch.setenv("ENABLE_SECURITY_SCANNING", "false")
    s = SecurityScanner()
    result = s.scan_configuration({"password": "secret123"})
    assert result["scanned"] is False


def test_cis_compliance_detects_privileged(scanner):
    findings = scanner._check_cis_compliance({"spec": {"privileged": True}})
    # string form used by implementation
    findings = scanner._check_cis_compliance("privileged: true\n")
    types = {f["type"] for f in findings}
    assert "cis_privileged_container" in types


@pytest.mark.parametrize(
    ("manifest", "expected"),
    [
        ("securityContext:\\n  allowPrivilegeEscalation: false\\n", False),
        ("securityContext:\\n  allowPrivilegeEscalation:  false\\n", False),
        ("securityContext:\\n  allowPrivilegeEscalation: true\\n", True),
        ("securityContext:\\n  runAsNonRoot: true\\n", True),
    ],
)
def test_cis_allow_privilege_escalation_finding(scanner, manifest, expected):
    findings = scanner._check_cis_compliance(manifest)
    hits = [f for f in findings if f["type"] == "cis_allow_privilege_escalation"]
    assert bool(hits) is expected, findings


def test_soc2_detects_http(scanner):
    findings = scanner._check_soc2_compliance("url: http://example.com/api")
    assert any(f["type"] == "soc2_unencrypted_transport" for f in findings)


def test_pci_detects_http(scanner):
    findings = scanner._check_pci_compliance("endpoint: http://pay.example")
    assert any(f["type"] == "pci_unencrypted_transport" for f in findings)


def test_compliance_disabled_skips_framework_checks(monkeypatch):
    monkeypatch.setenv("ENABLE_SECURITY_SCANNING", "true")
    monkeypatch.setenv("ENABLE_COMPLIANCE_CHECKS", "false")
    monkeypatch.setenv("COMPLIANCE_FRAMEWORKS", "CIS,SOC2")
    s = SecurityScanner()
    assert s.compliance_enabled is False
    assert s._check_compliance("privileged: true\nurl: http://x") == []


def test_scan_incident_context_on_manifest(scanner):
    ctx = {
        "type": "k8s",
        "manifest": """
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
""",
    }
    result = scanner.scan_incident_context(ctx)
    assert result["scanned"] is True
    assert result["total_findings"] >= 1
    assert "severity_summary" in result


def test_scan_configuration_includes_compliance(scanner):
    result = scanner.scan_configuration(
        {"url": "http://remote.example", "note": "privileged: true"}
    )
    assert result["scanned"] is True
    types = {f["type"] for f in result["findings"]}
    # at least one of secret/http/cis style findings
    assert result["total_findings"] >= 1
    assert types  # non-empty
