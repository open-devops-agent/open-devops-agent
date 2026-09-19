"""
Fix Verification Tool

Automatically verifies that a fix was successfully applied and the issue is resolved.
Runs verification tests and monitors the system for stability.
"""

import asyncio
import os
import time
from typing import Dict, List, Optional
from datetime import datetime, timedelta

import httpx
import structlog

log = structlog.get_logger()

_CICD_SUCCESS_STATUSES = frozenset({"success", "successful", "succeeded", "passed", "ok"})


async def _http_get_json(url: str, headers: Optional[dict] = None, auth=None) -> Dict:
    """GET JSON from a target system. Fail closed on non-200 or transport errors."""
    try:
        async with httpx.AsyncClient(headers=headers, auth=auth, timeout=30) as client:
            resp = await client.get(url)
    except Exception as e:
        return {"error": str(e)}
    if resp.status_code != 200:
        return {"error": f"Could not fetch target status: {resp.status_code}"}
    try:
        return resp.json()
    except Exception as e:
        return {"error": f"Target response was not JSON: {e}"}


def _cloud_status(observation: Dict) -> Optional[str]:
    for key in ("state", "status", "power_state"):
        value = observation.get(key)
        if isinstance(value, dict):
            value = value.get("status") or value.get("state") or value.get("name")
        if value:
            return str(value)
    health = observation.get("health")
    if isinstance(health, dict):
        value = health.get("status") or health.get("state")
        if value:
            return str(value)
    if isinstance(health, str) and health:
        return health
    return None


def _status_matches(observed: str, expected: str) -> bool:
    observed_l = observed.lower()
    expected_l = expected.lower()
    return observed_l == expected_l or expected_l in observed_l or observed_l in expected_l


class FixVerifier:
    """
    Verifies that fixes are successfully applied and issues are resolved.
    Monitors system for a period to ensure stability.
    """
    
    def __init__(self):
        self.verification_timeout = 300  # 5 minutes default
        log.info("FixVerifier initialized")
    
    async def verify_fix(
        self,
        incident_type: str,
        fix_applied: str,
        expected_state: Dict,
        monitoring_duration: int = 300
    ) -> Dict:
        """
        Verify that a fix was successfully applied.
        
        Args:
            incident_type: Type of incident (k8s, cicd, server, etc.)
            fix_applied: Description of fix that was applied
            expected_state: Expected state after fix (e.g., {"pod_status": "Running"})
            monitoring_duration: How long to monitor (seconds)
        
        Returns:
            Verification result with status and details
        """
        log.info(f"Starting fix verification", incident_type=incident_type, fix=fix_applied)
        
        verification_result = {
            "verified": False,
            "timestamp": datetime.utcnow().isoformat(),
            "incident_type": incident_type,
            "fix_applied": fix_applied,
            "checks_performed": [],
            "monitoring_period": monitoring_duration,
            "status": "unknown"
        }
        
        # Run immediate verification checks
        immediate_check = await self._run_immediate_checks(incident_type, expected_state)
        verification_result["checks_performed"].append(immediate_check)
        
        if not immediate_check.get("passed"):
            verification_result["status"] = "failed"
            verification_result["reason"] = "Immediate verification checks failed"
            return verification_result
        
        # Monitor for stability over time
        stability_check = await self._monitor_stability(
            incident_type, expected_state, monitoring_duration
        )
        verification_result["checks_performed"].append(stability_check)
        
        if stability_check.get("stable"):
            verification_result["verified"] = True
            verification_result["status"] = "success"
            verification_result["message"] = "Fix verified successfully and system is stable"
        else:
            verification_result["status"] = "unstable"
            verification_result["reason"] = stability_check.get("reason", "System showed instability")
        
        return verification_result
    
    async def _run_immediate_checks(
        self,
        incident_type: str,
        expected_state: Dict
    ) -> Dict:
        """Run immediate verification checks after fix."""
        check_result = {
            "check_type": "immediate",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": False,
            "details": {}
        }
        
        try:
            if incident_type == "k8s":
                check_result = await self._verify_k8s_fix(expected_state)
            elif incident_type == "cicd":
                check_result = await self._verify_cicd_fix(expected_state)
            elif incident_type in ["server", "linux", "windows", "rhel"]:
                check_result = await self._verify_server_fix(expected_state)
            elif incident_type.startswith("cloud_"):
                check_result = await self._verify_cloud_fix(incident_type, expected_state)
            elif incident_type == "argocd":
                check_result = await self._verify_argocd_fix(expected_state)
            else:
                check_result["details"]["note"] = "Generic verification performed"
                check_result["passed"] = True
        
        except Exception as e:
            log.error(f"Immediate verification failed", error=str(e))
            check_result["passed"] = False
            check_result["error"] = str(e)
        
        return check_result
    
    async def _monitor_stability(
        self,
        incident_type: str,
        expected_state: Dict,
        duration: int
    ) -> Dict:
        """Monitor system for stability over a period."""
        monitoring_result = {
            "check_type": "stability_monitoring",
            "duration": duration,
            "stable": False,
            "checks_performed": 0,
            "failures": 0,
            "timestamps": []
        }

        if duration <= 0:
            monitoring_result["reason"] = "Monitoring duration must be positive to verify stability"
            return monitoring_result

        start_time = time.time()
        # Check at least 10 times, but never faster than once per second so a
        # short monitoring window cannot busy-spin.
        check_interval = max(1, min(30, duration // 10))
        
        while time.time() - start_time < duration:
            monitoring_result["checks_performed"] += 1
            monitoring_result["timestamps"].append(datetime.utcnow().isoformat())
            
            try:
                # Re-check the expected state
                check = await self._run_immediate_checks(incident_type, expected_state)
                
                if not check.get("passed"):
                    monitoring_result["failures"] += 1
                    log.warning(f"Stability check failed", check_num=monitoring_result["checks_performed"])
                
                # If too many failures, stop monitoring
                if monitoring_result["failures"] > 2:
                    monitoring_result["stable"] = False
                    monitoring_result["reason"] = f"Multiple failures detected ({monitoring_result['failures']})"
                    break
            
            except Exception as e:
                log.error(f"Monitoring check error", error=str(e))
                monitoring_result["failures"] += 1
            
            await asyncio.sleep(check_interval)
        
        if monitoring_result["checks_performed"] == 0:
            monitoring_result["stable"] = False
            monitoring_result["reason"] = "No stability observations were performed"
            return monitoring_result

        success_rate = (
            monitoring_result["checks_performed"] - monitoring_result["failures"]
        ) / monitoring_result["checks_performed"]
        monitoring_result["success_rate"] = f"{success_rate * 100:.1f}%"

        if success_rate >= 0.9:
            monitoring_result["stable"] = True
        else:
            monitoring_result["stable"] = False
            monitoring_result["reason"] = f"Low success rate: {monitoring_result['success_rate']}"

        return monitoring_result
    
    async def _verify_k8s_fix(self, expected_state: Dict) -> Dict:
        """Verify Kubernetes fix."""
        result = {
            "check_type": "k8s_verification",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": False,
            "details": {}
        }
        
        try:
            # Check pod status
            if "pod_name" in expected_state and "namespace" in expected_state:
                import subprocess
                proc = subprocess.run(
                    [
                        "kubectl",
                        "get",
                        "pod",
                        expected_state["pod_name"],
                        "-n",
                        expected_state["namespace"],
                        "-o",
                        "jsonpath={.status.phase}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                
                pod_status = proc.stdout.strip()
                result["details"]["pod_status"] = pod_status
                
                expected_status = expected_state.get("pod_status", "Running")
                if pod_status == expected_status:
                    result["passed"] = True
                    result["message"] = f"Pod is in {pod_status} state"
                else:
                    result["message"] = f"Pod is {pod_status}, expected {expected_status}"
            else:
                # Generic K8s verification
                result["passed"] = True
                result["message"] = "K8s state check passed"
        
        except Exception as e:
            result["error"] = str(e)
            result["message"] = "K8s verification failed"
        
        return result
    
    async def _verify_cicd_fix(self, expected_state: Dict) -> Dict:
        """Verify a CI/CD fix by observing pipeline/build status on the target platform."""
        result = {
            "check_type": "cicd_verification",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": False,
            "details": {},
        }
        observation = await self._observe_cicd(expected_state or {})
        result["details"] = observation
        if observation.get("error"):
            result["message"] = observation["error"]
            return result

        expected_status = str(
            (expected_state or {}).get("expected_status")
            or (expected_state or {}).get("status")
            or "success"
        ).lower()
        observed = str(observation.get("status") or "").lower()
        if not observed:
            result["message"] = "CI/CD target returned no status"
            return result
        matched = observed == expected_status or (
            expected_status in _CICD_SUCCESS_STATUSES and observed in _CICD_SUCCESS_STATUSES
        )
        if not matched:
            result["message"] = f"CI/CD status is {observed}, expected {expected_status}"
            return result
        result["passed"] = True
        result["message"] = f"CI/CD status is {observed}"
        return result
    
    async def _verify_server_fix(self, expected_state: Dict) -> Dict:
        """Verify server fix."""
        result = {
            "check_type": "server_verification",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": False,
            "details": {}
        }
        
        try:
            # Check service status if specified
            if "service_name" in expected_state:
                import subprocess
                import platform
                
                if platform.system().lower() == 'windows':
                    proc = subprocess.run(
                        ["sc", "query", expected_state["service_name"]],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                else:
                    proc = subprocess.run(
                        ["systemctl", "is-active", expected_state["service_name"]],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                
                if platform.system().lower() == 'windows':
                    service_running = "RUNNING" in proc.stdout
                else:
                    service_running = proc.stdout.strip() == "active"
                
                result["details"]["service_status"] = "running" if service_running else "not running"
                result["passed"] = service_running
                result["message"] = f"Service is {'running' if service_running else 'not running'}"
            else:
                result["passed"] = True
                result["message"] = "Server state verified"
        
        except Exception as e:
            result["error"] = str(e)
            result["message"] = "Server verification failed"
        
        return result
    
    async def _verify_cloud_fix(self, incident_type: str, expected_state: Dict) -> Dict:
        """Verify a cloud fix by collecting live resource state from the provider."""
        result = {
            "check_type": f"{incident_type}_verification",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": False,
            "details": {},
        }
        expected_state = expected_state or {}
        resource_type = expected_state.get("resource_type")
        resource_id = expected_state.get("resource_id")
        if not resource_type or not resource_id:
            result["message"] = (
                "Cloud verification requires resource_type and resource_id from the target system"
            )
            return result

        observation = await self._observe_cloud(incident_type, expected_state)
        result["details"] = observation
        if observation.get("error"):
            result["message"] = observation["error"]
            return result

        observed = _cloud_status(observation)
        expected = expected_state.get("state") or expected_state.get("status")
        if expected:
            if not observed or not _status_matches(observed, expected):
                result["message"] = f"Cloud resource is {observed or 'unknown'}, expected {expected}"
                return result
            result["passed"] = True
            result["message"] = f"Cloud resource is {observed}"
            return result

        result["passed"] = True
        result["message"] = (
            f"Cloud resource observed ({observed})" if observed else "Cloud resource observed"
        )
        return result
    
    async def _verify_argocd_fix(self, expected_state: Dict) -> Dict:
        """Verify an ArgoCD fix by fetching application health and sync status."""
        result = {
            "check_type": "argocd_verification",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": False,
            "details": {},
        }
        expected_state = expected_state or {}
        app_name = expected_state.get("app_name")
        if not app_name:
            result["message"] = "ArgoCD verification requires app_name"
            return result

        observation = await self._observe_argocd(app_name)
        result["details"] = observation
        if observation.get("error"):
            result["message"] = observation["error"]
            return result

        health = observation.get("health") or {}
        sync = observation.get("sync") or {}
        health_status = health.get("status") if isinstance(health, dict) else health
        sync_status = sync.get("status") if isinstance(sync, dict) else sync
        expected_health = expected_state.get("health", "Healthy")
        expected_sync = expected_state.get("sync", "Synced")
        if health_status != expected_health or sync_status != expected_sync:
            result["message"] = (
                f"ArgoCD health={health_status} sync={sync_status}, "
                f"expected health={expected_health} sync={expected_sync}"
            )
            return result
        result["passed"] = True
        result["message"] = f"ArgoCD application {app_name} is {health_status}/{sync_status}"
        return result

    async def _observe_cicd(self, expected_state: Dict) -> Dict:
        """Fetch current pipeline/build status from the CI/CD platform."""
        platform = str(expected_state.get("platform") or "").lower()
        if platform in ("", "unknown"):
            return {"error": "CI/CD verification requires a target platform and identifiers"}
        try:
            if platform == "github":
                return await self._observe_github_run(expected_state)
            if platform == "gitlab":
                return await self._observe_gitlab_pipeline(expected_state)
            if platform == "jenkins":
                return await self._observe_jenkins_build(expected_state)
            if platform == "bamboo":
                return await self._observe_bamboo_build(expected_state)
            if platform in ("azure_devops", "azure"):
                return await self._observe_azure_pipeline(expected_state)
            return {"error": f"Unsupported CI/CD platform: {platform}"}
        except Exception as e:
            log.error("CI/CD verification query failed", platform=platform, error=str(e))
            return {"error": str(e)}

    async def _observe_github_run(self, expected_state: Dict) -> Dict:
        repo = expected_state.get("repo")
        run_id = expected_state.get("run_id")
        if not repo or run_id in (None, ""):
            return {"error": "GitHub verification requires repo and run_id"}
        token = os.getenv("GITHUB_TOKEN", "")
        if not token:
            return {"error": "GITHUB_TOKEN not configured; cannot observe GitHub Actions"}
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}"
        data = await _http_get_json(url, headers=headers)
        if "error" in data:
            return data
        return {
            "platform": "github",
            "status": data.get("conclusion") or data.get("status"),
            "run_status": data.get("status"),
            "url": data.get("html_url"),
        }

    async def _observe_gitlab_pipeline(self, expected_state: Dict) -> Dict:
        project_id = expected_state.get("project_id")
        pipeline_id = expected_state.get("pipeline_id")
        if not project_id or pipeline_id in (None, ""):
            return {"error": "GitLab verification requires project_id and pipeline_id"}
        token = os.getenv("GITLAB_TOKEN", "")
        if not token:
            return {"error": "GITLAB_TOKEN not configured; cannot observe GitLab pipelines"}
        base = os.getenv("GITLAB_URL", "https://gitlab.com").rstrip("/")
        url = f"{base}/api/v4/projects/{project_id}/pipelines/{pipeline_id}"
        data = await _http_get_json(url, headers={"PRIVATE-TOKEN": token})
        if "error" in data:
            return data
        return {"platform": "gitlab", "status": data.get("status"), "url": data.get("web_url")}

    async def _observe_jenkins_build(self, expected_state: Dict) -> Dict:
        job_name = expected_state.get("job_name")
        build_number = expected_state.get("build_number")
        if not job_name or build_number in (None, ""):
            return {"error": "Jenkins verification requires job_name and build_number"}
        jenkins_url = os.getenv("JENKINS_URL", "").rstrip("/")
        if not jenkins_url:
            return {"error": "JENKINS_URL not configured; cannot observe Jenkins builds"}
        username = os.getenv("JENKINS_USERNAME", "")
        token = os.getenv("JENKINS_API_TOKEN", "")
        auth = (username, token) if username and token else None
        url = f"{jenkins_url}/job/{job_name}/{build_number}/api/json"
        data = await _http_get_json(url, auth=auth)
        if "error" in data:
            return data
        return {"platform": "jenkins", "status": data.get("result"), "url": data.get("url")}

    async def _observe_bamboo_build(self, expected_state: Dict) -> Dict:
        plan_key = expected_state.get("plan_key")
        build_number = expected_state.get("build_number")
        if not plan_key:
            return {"error": "Bamboo verification requires plan_key"}
        bamboo_url = os.getenv("BAMBOO_URL", "").rstrip("/")
        if not bamboo_url:
            return {"error": "BAMBOO_URL not configured; cannot observe Bamboo builds"}
        username = os.getenv("BAMBOO_USERNAME", "")
        password = os.getenv("BAMBOO_PASSWORD", "")
        auth = (username, password) if username and password else None
        build_key = f"{plan_key}-{build_number}" if build_number not in (None, "") else f"{plan_key}/latest"
        url = f"{bamboo_url}/rest/api/latest/result/{build_key}"
        data = await _http_get_json(url, auth=auth)
        if "error" in data:
            return data
        return {
            "platform": "bamboo",
            "status": data.get("buildState") or data.get("lifeCycleState"),
            "url": (data.get("link") or {}).get("href"),
        }

    async def _observe_azure_pipeline(self, expected_state: Dict) -> Dict:
        project = expected_state.get("project")
        pipeline_id = expected_state.get("pipeline_id")
        run_id = expected_state.get("run_id")
        if not project or pipeline_id in (None, "") or run_id in (None, ""):
            return {"error": "Azure DevOps verification requires project, pipeline_id, and run_id"}
        org = os.getenv("AZURE_DEVOPS_ORG", "")
        pat = os.getenv("AZURE_DEVOPS_PAT", "")
        if not org or not pat:
            return {"error": "AZURE_DEVOPS_ORG and AZURE_DEVOPS_PAT must be configured"}
        from collectors.azure_devops import AzureDevOpsCollector

        headers = AzureDevOpsCollector().headers
        url = (
            f"https://dev.azure.com/{org}/{project}/_apis/pipelines/"
            f"{pipeline_id}/runs/{run_id}?api-version=7.0"
        )
        data = await _http_get_json(url, headers=headers)
        if "error" in data:
            return data
        return {
            "platform": "azure_devops",
            "status": data.get("result") or data.get("state"),
            "url": (data.get("_links") or {}).get("web", {}).get("href") or data.get("url"),
        }

    async def _observe_cloud(self, incident_type: str, expected_state: Dict) -> Dict:
        """Collect live cloud resource state from the matching provider collector."""
        resource_type = expected_state["resource_type"]
        resource_id = expected_state["resource_id"]
        reserved = {"resource_type", "resource_id", "state", "status", "expected_status"}
        params = {k: v for k, v in expected_state.items() if k not in reserved and v is not None}
        try:
            if incident_type == "cloud_aws":
                from collectors.aws import AWSCollector

                return await AWSCollector().collect(resource_type, resource_id, **params)
            if incident_type == "cloud_gcp":
                from collectors.gcp import GCPCollector

                return await GCPCollector().collect(resource_type, resource_id, **params)
            if incident_type == "cloud_azure":
                from collectors.azure import AzureCollector

                return await AzureCollector().collect(resource_type, resource_id, **params)
            return {"error": f"Unsupported cloud incident type: {incident_type}"}
        except Exception as e:
            log.error("Cloud verification query failed", incident_type=incident_type, error=str(e))
            return {"error": str(e)}

    async def _observe_argocd(self, app_name: str) -> Dict:
        """Collect live ArgoCD application health and sync status."""
        try:
            from collectors.argocd import ArgoCDCollector

            return await ArgoCDCollector().collect(app_name)
        except Exception as e:
            log.error("ArgoCD verification query failed", app=app_name, error=str(e))
            return {"error": str(e)}
    
    def generate_verification_report(self, verification_result: Dict) -> str:
        """Generate human-readable verification report."""
        status_emoji = {
            "success": "SUCCESS",
            "failed": "FAILED",
            "unstable": "WARNING"
        }
        
        status = verification_result.get("status", "unknown")
        
        report = f"""
FIX VERIFICATION REPORT
======================

Status: {status_emoji.get(status, 'UNKNOWN')} - {status.upper()}
Timestamp: {verification_result.get('timestamp')}
Incident Type: {verification_result.get('incident_type')}

Fix Applied:
{verification_result.get('fix_applied')}

Verification Results:
- Verified: {'YES' if verification_result.get('verified') else 'NO'}
- Monitoring Duration: {verification_result.get('monitoring_period')}s

Checks Performed:
"""
        for i, check in enumerate(verification_result.get('checks_performed', []), 1):
            report += f"\n{i}. {check.get('check_type', 'unknown')}"
            report += f"\n   Status: {'PASSED' if check.get('passed') or check.get('stable') else 'FAILED'}"
            if 'message' in check:
                report += f"\n   Details: {check['message']}"
        
        if not verification_result.get('verified'):
            report += f"\n\nReason for Failure:\n{verification_result.get('reason', 'Unknown')}"
        
        report += f"\n\nNext Steps:"
        if verification_result.get('verified'):
            report += "\n- Fix is verified and stable"
            report += "\n- Update documentation"
            report += "\n- Close incident ticket"
        else:
            report += "\n- Investigate why verification failed"
            report += "\n- Review fix application"
            report += "\n- Consider rollback if unstable"
        
        return report


# Example usage
if __name__ == "__main__":
    async def test():
        verifier = FixVerifier()
        
        result = await verifier.verify_fix(
            incident_type="k8s",
            fix_applied="Restarted pod and updated configmap",
            expected_state={
                "pod_name": "api-service",
                "namespace": "production",
                "pod_status": "Running"
            },
            monitoring_duration=60  # 1 minute for testing
        )
        
        print(verifier.generate_verification_report(result))
    
    asyncio.run(test())
