"""
Security scanner collector for DevSecOps practices.

This collector scans for security issues, compliance violations,
and configuration problems that could lead to security incidents.
"""

import os
import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SecurityScanner:
    """
    Scans for security issues and compliance violations.
    """
    
    def __init__(self):
        self.enabled = os.getenv('ENABLE_SECURITY_SCANNING', 'true').lower() == 'true'
        self.compliance_enabled = (
            os.getenv('ENABLE_COMPLIANCE_CHECKS', 'true').lower() == 'true'
        )
        raw_frameworks = os.getenv('COMPLIANCE_FRAMEWORKS', 'CIS')
        self.compliance_frameworks = [
            f.strip() for f in raw_frameworks.split(',') if f.strip()
        ]

        logger.info(f"SecurityScanner initialized (enabled={self.enabled})")
        if self.enabled:
            logger.info(
                "Compliance checks=%s frameworks=%s",
                self.compliance_enabled,
                ', '.join(self.compliance_frameworks) or '(none)',
            )
    
    def scan_configuration(self, config: Dict) -> Dict:
        """
        Scan configuration for security issues.
        
        Args:
            config: Configuration to scan (K8s manifest, Dockerfile, etc.)
        
        Returns:
            Dictionary with findings
        """
        if not self.enabled:
            return {"scanned": False, "reason": "Security scanning disabled"}
        
        findings = []
        
        # Check for exposed secrets
        secret_findings = self._check_for_secrets(config)
        findings.extend(secret_findings)
        
        # Check for insecure configurations
        config_findings = self._check_insecure_configs(config)
        findings.extend(config_findings)
        
        # Check compliance
        compliance_findings = self._check_compliance(config)
        findings.extend(compliance_findings)
        
        return {
            "scanned": True,
            "total_findings": len(findings),
            "findings": findings,
            "severity_summary": self._summarize_severity(findings)
        }
    
    def scan_kubernetes_manifest(self, manifest: str) -> Dict:
        """
        Scan Kubernetes manifest for security issues.
        
        Args:
            manifest: YAML manifest content
        
        Returns:
            Security findings
        """
        findings = []
        
        # Check for privileged containers
        if 'privileged: true' in manifest.lower():
            findings.append({
                "type": "privileged_container",
                "severity": "HIGH",
                "description": "Container running with privileged mode",
                "recommendation": "Remove privileged mode unless absolutely necessary",
                "cis_benchmark": "CIS-K8s-5.2.1"
            })
        
        # Check for hostNetwork
        if 'hostNetwork: true' in manifest.lower():
            findings.append({
                "type": "host_network",
                "severity": "MEDIUM",
                "description": "Pod using host network",
                "recommendation": "Avoid hostNetwork unless required for network plugins",
                "cis_benchmark": "CIS-K8s-5.2.4"
            })
        
        # Check for missing resource limits
        if 'resources:' not in manifest:
            findings.append({
                "type": "missing_resource_limits",
                "severity": "MEDIUM",
                "description": "Container missing resource limits",
                "recommendation": "Set CPU and memory limits to prevent resource exhaustion",
                "cis_benchmark": "CIS-K8s-5.2.8"
            })
        
        # Check for latest tag
        if re.search(r'image:.*:latest', manifest, re.IGNORECASE):
            findings.append({
                "type": "latest_tag",
                "severity": "MEDIUM",
                "description": "Container using 'latest' tag",
                "recommendation": "Use specific version tags for reproducibility",
                "best_practice": "Always pin to specific versions"
            })
        
        # Check for missing security context
        if 'securityContext' not in manifest:
            findings.append({
                "type": "missing_security_context",
                "severity": "HIGH",
                "description": "Missing security context",
                "recommendation": "Add securityContext with runAsNonRoot and read-only root filesystem",
                "cis_benchmark": "CIS-K8s-5.2.6"
            })
        
        # Check for capabilities
        if 'capabilities' in manifest and 'add' in manifest.lower():
            findings.append({
                "type": "added_capabilities",
                "severity": "MEDIUM",
                "description": "Container adding Linux capabilities",
                "recommendation": "Drop all capabilities and add only required ones",
                "cis_benchmark": "CIS-K8s-5.2.9"
            })
        
        return {
            "resource_type": "kubernetes_manifest",
            "findings": findings,
            "total_findings": len(findings),
            "severity_summary": self._summarize_severity(findings)
        }
    
    def scan_dockerfile(self, dockerfile_content: str) -> Dict:
        """
        Scan Dockerfile for security issues.
        
        Args:
            dockerfile_content: Dockerfile content
        
        Returns:
            Security findings
        """
        findings = []
        
        # Check for root user
        if 'USER root' in dockerfile_content or 'USER' not in dockerfile_content:
            findings.append({
                "type": "root_user",
                "severity": "HIGH",
                "description": "Container running as root",
                "recommendation": "Add 'USER nonroot' after creating a non-root user",
                "best_practice": "Always run containers as non-root user"
            })
        
        # Check for latest base image
        if re.search(r'FROM.*:latest', dockerfile_content, re.IGNORECASE):
            findings.append({
                "type": "latest_base_image",
                "severity": "MEDIUM",
                "description": "Using 'latest' tag for base image",
                "recommendation": "Pin to specific version tag",
                "best_practice": "Use specific versions for reproducibility"
            })
        
        # Check for secrets in ENV
        if re.search(r'ENV.*(?:PASSWORD|SECRET|KEY|TOKEN)=', dockerfile_content, re.IGNORECASE):
            findings.append({
                "type": "hardcoded_secrets",
                "severity": "CRITICAL",
                "description": "Possible hardcoded secret in ENV",
                "recommendation": "Use secrets management (e.g., Kubernetes Secrets, AWS Secrets Manager)",
                "security_risk": "Secrets in images can be extracted"
            })
        
        # Check for apt-get without cleanup
        if 'apt-get' in dockerfile_content and 'rm -rf /var/lib/apt/lists/*' not in dockerfile_content:
            findings.append({
                "type": "no_apt_cleanup",
                "severity": "LOW",
                "description": "apt-get used without cleanup",
                "recommendation": "Add '&& rm -rf /var/lib/apt/lists/*' to reduce image size",
                "best_practice": "Clean up package manager caches"
            })
        
        # Check for HEALTHCHECK
        if 'HEALTHCHECK' not in dockerfile_content:
            findings.append({
                "type": "missing_healthcheck",
                "severity": "LOW",
                "description": "Missing HEALTHCHECK instruction",
                "recommendation": "Add HEALTHCHECK for better container orchestration",
                "best_practice": "Always define health checks"
            })
        
        return {
            "resource_type": "dockerfile",
            "findings": findings,
            "total_findings": len(findings),
            "severity_summary": self._summarize_severity(findings)
        }
    
    def _check_for_secrets(self, config: Dict) -> List[Dict]:
        """Check for exposed secrets in configuration."""
        findings = []
        
        # Convert config to string for pattern matching
        config_str = str(config).lower()
        
        # Patterns that might indicate secrets
        secret_patterns = [
            (r'password\s*[:=]\s*["\']?(?!<|{)[^\s"\']+', 'Possible password'),
            (r'api[_-]?key\s*[:=]\s*["\']?(?!<|{)[^\s"\']+', 'Possible API key'),
            (r'secret\s*[:=]\s*["\']?(?!<|{)[^\s"\']+', 'Possible secret'),
            (r'token\s*[:=]\s*["\']?(?!<|{)[^\s"\']+', 'Possible token'),
            (r'aws[_-]?secret', 'AWS secret reference'),
        ]
        
        for pattern, description in secret_patterns:
            if re.search(pattern, config_str, re.IGNORECASE):
                findings.append({
                    "type": "exposed_secret",
                    "severity": "CRITICAL",
                    "description": f"{description} found in configuration",
                    "recommendation": "Use secrets management system (K8s Secrets, HashiCorp Vault, etc.)",
                    "security_risk": "Exposed secrets can be compromised"
                })
        
        return findings
    
    def _check_insecure_configs(self, config: Dict) -> List[Dict]:
        """Check for insecure configurations."""
        findings = []
        
        config_str = str(config).lower()
        
        # Check for unencrypted protocols
        if re.search(r'http://(?!localhost|127\.0\.0\.1)', config_str):
            findings.append({
                "type": "unencrypted_http",
                "severity": "MEDIUM",
                "description": "HTTP used instead of HTTPS",
                "recommendation": "Use HTTPS for all external communication",
                "compliance": "Required by PCI-DSS, SOC2"
            })
        
        # Check for debug mode
        if 'debug' in config_str and ('true' in config_str or 'enabled' in config_str):
            findings.append({
                "type": "debug_mode_enabled",
                "severity": "MEDIUM",
                "description": "Debug mode may be enabled",
                "recommendation": "Disable debug mode in production",
                "security_risk": "Debug mode may expose sensitive information"
            })
        
        return findings
    
    def _check_compliance(self, config: Dict) -> List[Dict]:
        """Check for compliance violations (gated by ENABLE_COMPLIANCE_CHECKS)."""
        if not self.compliance_enabled:
            return []

        findings = []
        for framework in self.compliance_frameworks:
            name = framework.upper()
            if name == 'CIS':
                findings.extend(self._check_cis_compliance(config))
            elif name in ('SOC2', 'SOC-2'):
                findings.extend(self._check_soc2_compliance(config))
            elif name in ('PCI', 'PCI-DSS', 'PCIDSS'):
                findings.extend(self._check_pci_compliance(config))
        return findings

    def _check_cis_compliance(self, config: Dict) -> List[Dict]:
        """CIS Kubernetes Benchmark-oriented checks on config/manifest text."""
        findings = []
        text = str(config)
        lower = text.lower()

        if 'privileged: true' in lower:
            findings.append({
                "type": "cis_privileged_container",
                "severity": "HIGH",
                "framework": "CIS",
                "description": "Privileged container violates CIS K8s 5.2.1",
                "recommendation": "Set privileged: false and drop capabilities",
                "cis_benchmark": "CIS-K8s-5.2.1",
            })

        if 'runasnonroot: true' not in lower and 'runasnonroot:true' not in lower:
            findings.append({
                "type": "cis_run_as_non_root",
                "severity": "MEDIUM",
                "framework": "CIS",
                "description": "No runAsNonRoot: true found (CIS K8s 5.2.6)",
                "recommendation": "Set securityContext.runAsNonRoot: true",
                "cis_benchmark": "CIS-K8s-5.2.6",
            })

        # The text is lowercased but NOT space-stripped here: searching a
        # space-stripped string for a needle that still contained a space made the
        # condition always true, so every manifest got a CIS-K8s-5.2.5 false positive.
        if not re.search(r"allowprivilegeescalation\s*:\s*false", lower):
            findings.append({
                "type": "cis_allow_privilege_escalation",
                "severity": "MEDIUM",
                "framework": "CIS",
                "description": "allowPrivilegeEscalation not explicitly false (CIS K8s 5.2.5)",
                "recommendation": "Set allowPrivilegeEscalation: false",
                "cis_benchmark": "CIS-K8s-5.2.5",
            })

        return findings

    def _check_soc2_compliance(self, config: Dict) -> List[Dict]:
        """SOC2-oriented checks: encryption in transit, auditability of secrets."""
        findings = []
        lower = str(config).lower()

        if re.search(r'http://(?!localhost|127\.0\.0\.1)', lower):
            findings.append({
                "type": "soc2_unencrypted_transport",
                "severity": "HIGH",
                "framework": "SOC2",
                "description": "Plain HTTP endpoint detected (SOC2 CC6.1 encryption in transit)",
                "recommendation": "Use HTTPS/TLS for all non-local endpoints",
                "compliance": "SOC2-CC6.1",
            })

        if re.search(r'(password|secret|api[_-]?key)\s*[:=]\s*["\']?(?!<|{)[^\s"\']+', lower):
            findings.append({
                "type": "soc2_secret_in_config",
                "severity": "CRITICAL",
                "framework": "SOC2",
                "description": "Possible secret material embedded in configuration (SOC2 CC6.1)",
                "recommendation": "Store secrets in a vault / secret manager, not config files",
                "compliance": "SOC2-CC6.1",
            })

        return findings

    def _check_pci_compliance(self, config: Dict) -> List[Dict]:
        """PCI-DSS-oriented checks: no card data patterns, TLS required."""
        findings = []
        text = str(config)
        lower = text.lower()

        # Very coarse PAN-like digit run (not a Luhn check — signal only)
        if re.search(r'\b(?:\d[ -]*?){13,19}\b', text):
            findings.append({
                "type": "pci_possible_pan",
                "severity": "CRITICAL",
                "framework": "PCI",
                "description": "Long digit sequence resembling payment card data",
                "recommendation": "Never store PAN/CVV in configs or logs; tokenize via PCI-compliant vault",
                "compliance": "PCI-DSS-3.4",
            })

        if re.search(r'http://(?!localhost|127\.0\.0\.1)', lower):
            findings.append({
                "type": "pci_unencrypted_transport",
                "severity": "HIGH",
                "framework": "PCI",
                "description": "HTTP (non-TLS) endpoint may violate PCI-DSS transmission requirements",
                "recommendation": "Enforce TLS 1.2+ for all cardholder-data environments",
                "compliance": "PCI-DSS-4.1",
            })

        return findings

    def scan_incident_context(self, context: Dict) -> Dict:
        """Scan an agent incident context blob for security/compliance issues.

        Invoked from the agent loop when ENABLE_SECURITY_SCANNING=true.
        """
        if not self.enabled:
            return {"scanned": False, "reason": "Security scanning disabled"}

        # Prefer explicit manifests/dockerfiles in context; else scan whole context.
        findings: List[Dict] = []

        manifest = context.get("manifest") or context.get("k8s_manifest") or ""
        if isinstance(manifest, str) and manifest.strip():
            result = self.scan_kubernetes_manifest(manifest)
            findings.extend(result.get("findings", []))

        dockerfile = context.get("dockerfile") or context.get("dockerfile_content") or ""
        if isinstance(dockerfile, str) and dockerfile.strip():
            result = self.scan_dockerfile(dockerfile)
            findings.extend(result.get("findings", []))

        # Always run config-level checks on the full context
        cfg_result = self.scan_configuration(context)
        if cfg_result.get("scanned"):
            findings.extend(cfg_result.get("findings", []))

        # Deduplicate by (type, description)
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("type"), f.get("description"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)

        return {
            "scanned": True,
            "total_findings": len(unique),
            "findings": unique,
            "severity_summary": self._summarize_severity(unique),
            "compliance_enabled": self.compliance_enabled,
            "frameworks": list(self.compliance_frameworks),
        }

    def _summarize_severity(self, findings: List[Dict]) -> Dict:
        """Summarize findings by severity."""
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for finding in findings:
            severity = finding.get('severity', 'MEDIUM')
            summary[severity] = summary.get(severity, 0) + 1

        return summary


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    scanner = SecurityScanner()
    
    # Test Kubernetes manifest
    test_manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
"""
    
    print("\n=== Scanning Kubernetes Manifest ===")
    k8s_results = scanner.scan_kubernetes_manifest(test_manifest)
    print(f"Total findings: {k8s_results['total_findings']}")
    print(f"Severity summary: {k8s_results['severity_summary']}")
    
    for finding in k8s_results['findings']:
        print(f"\n[{finding['severity']}] {finding['type']}")
        print(f"  Description: {finding['description']}")
        print(f"  Recommendation: {finding['recommendation']}")
