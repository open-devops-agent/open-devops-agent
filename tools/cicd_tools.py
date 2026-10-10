"""
CI/CD Tools for GitLab, Jenkins, Bamboo, Azure DevOps
Provides safe operations for CI/CD platforms.
"""
import os
from typing import Optional
import re

import httpx
import structlog

log = structlog.get_logger()


class CICDTools:
    """Unified CI/CD tools for multiple platforms."""
    
    def __init__(self):
        self.gitlab_token = os.getenv("GITLAB_TOKEN", "")
        self.gitlab_url = os.getenv("GITLAB_URL", "https://gitlab.com")
        self.jenkins_url = os.getenv("JENKINS_URL", "")
        self.jenkins_username = os.getenv("JENKINS_USERNAME", "")
        self.jenkins_token = os.getenv("JENKINS_API_TOKEN", "")
        self.bamboo_url = os.getenv("BAMBOO_URL", "")
        self.bamboo_username = os.getenv("BAMBOO_USERNAME", "")
        self.bamboo_password = os.getenv("BAMBOO_PASSWORD", "")
        self.azure_org = os.getenv("AZURE_DEVOPS_ORG", "")
        self.azure_pat = os.getenv("AZURE_DEVOPS_PAT", "")
        self.bitbucket_user = os.getenv("BITBUCKET_USERNAME", "")
        self.bitbucket_token = os.getenv("BITBUCKET_APP_PASSWORD", "") or os.getenv(
            "BITBUCKET_TOKEN", ""
        )
        self.bitbucket_api = os.getenv(
            "BITBUCKET_API_URL", "https://api.bitbucket.org/2.0"
        ).rstrip("/")

    async def retry_pipeline(
        self,
        platform: str,
        project_id: str,
        pipeline_id: Optional[str] = None,
        **kwargs
    ) -> dict:
        """
        Retry a failed pipeline/build.
        
        Args:
            platform: 'github', 'gitlab', 'jenkins', 'bamboo', 'azure_devops'
            project_id: Project/job/repo identifier
            pipeline_id: Pipeline/build/run identifier (optional for some platforms)
        """
        if platform in ("github", "github_actions"):
            run_id = pipeline_id or kwargs.get("run_id")
            if run_id is None:
                return {"error": "GitHub retry requires pipeline_id or run_id"}
            return await self._retry_github_workflow(
                project_id,
                int(run_id),
                failed_jobs_only=bool(kwargs.get("failed_jobs_only", True)),
            )
        if platform == "gitlab":
            return await self._retry_gitlab_pipeline(project_id, int(pipeline_id))
        elif platform == "jenkins":
            return await self._retry_jenkins_build(project_id)
        elif platform == "bamboo":
            return await self._retry_bamboo_build(project_id)
        elif platform == "azure_devops":
            return await self._retry_azure_pipeline(
                kwargs.get("project") or os.getenv("AZURE_DEVOPS_PROJECT") or project_id,
                int(pipeline_id),
                int(kwargs.get("run_id") or pipeline_id)
            )
        else:
            return {"error": f"Unsupported platform: {platform}"}

    async def create_fix_pr(
        self,
        platform: str,
        repo: str,
        file_path: str,
        new_content: str,
        pr_title: str,
        pr_body: str,
        **kwargs
    ) -> dict:
        """
        Create a PR/MR with a fix.
        
        Args:
            platform: 'github', 'gitlab', 'azure_devops', 'bitbucket', 'jenkins', 'bamboo'
            repo: Repository identifier (Jenkins/Bamboo: SCM repo, not the job/plan key)
            file_path: File to update
            new_content: New file content
            pr_title: PR/MR title
            pr_body: PR/MR description
        """
        if platform in ("github", "github_actions"):
            from tools.github_tools import GitHubTools

            return await GitHubTools().create_fix_pr(
                repo, file_path, new_content, pr_title, pr_body
            )
        if platform == "gitlab":
            return await self._create_gitlab_mr(
                repo, file_path, new_content, pr_title, pr_body
            )
        if platform == "azure_devops":
            return await self._create_azure_pr(
                kwargs.get("project") or os.getenv("AZURE_DEVOPS_PROJECT"),
                repo,
                file_path,
                new_content,
                pr_title,
                pr_body
            )
        if platform in ("bitbucket", "bitbucket_cloud"):
            return await self._create_bitbucket_pr(
                repo, file_path, new_content, pr_title, pr_body
            )
        if platform == "jenkins":
            return await self._create_scm_pr(
                kwargs.get("scm_provider") or os.getenv("JENKINS_SCM_PROVIDER") or "github",
                kwargs.get("scm_repo") or os.getenv("JENKINS_SCM_REPO") or repo,
                file_path,
                new_content,
                pr_title,
                pr_body,
                project=kwargs.get("project"),
            )
        if platform == "bamboo":
            return await self._create_scm_pr(
                kwargs.get("scm_provider") or os.getenv("BAMBOO_SCM_PROVIDER") or "bitbucket",
                kwargs.get("scm_repo") or os.getenv("BAMBOO_SPECS_REPO") or repo,
                file_path,
                new_content,
                pr_title,
                pr_body,
                project=kwargs.get("project"),
            )
        return {"error": f"PR creation not supported for {platform}"}

    async def _create_scm_pr(
        self,
        provider: str,
        repo: str,
        file_path: str,
        new_content: str,
        pr_title: str,
        pr_body: str,
        project: Optional[str] = None,
    ) -> dict:
        """Open a PR on the Git host Jenkins/Bamboo builds from (they have no PR API)."""
        if not repo or repo in ("", "none"):
            return {
                "error": (
                    "Set JENKINS_SCM_REPO or BAMBOO_SPECS_REPO (and scm_provider) "
                    "to the Git repo that holds Jenkinsfile / bamboo-specs."
                )
            }
        provider = (provider or "github").lower()
        if provider in ("github", "github_actions"):
            from tools.github_tools import GitHubTools

            return await GitHubTools().create_fix_pr(
                repo, file_path, new_content, pr_title, pr_body
            )
        if provider in ("gitlab", "gitlab_ci"):
            return await self._create_gitlab_mr(
                repo, file_path, new_content, pr_title, pr_body
            )
        if provider in ("azure_devops", "azure"):
            return await self._create_azure_pr(
                project or os.getenv("AZURE_DEVOPS_PROJECT"),
                repo,
                file_path,
                new_content,
                pr_title,
                pr_body,
            )
        if provider in ("bitbucket", "bitbucket_cloud", "bb"):
            return await self._create_bitbucket_pr(
                repo, file_path, new_content, pr_title, pr_body
            )
        return {
            "error": (
                f"Unsupported SCM provider {provider!r}. "
                "Use github, gitlab, bitbucket, or azure_devops."
            )
        }

    async def _retry_github_workflow(
        self, repo: str, run_id: int, failed_jobs_only: bool = True
    ) -> dict:
        from tools.github_tools import GitHubTools

        return await GitHubTools().rerun_workflow(repo, run_id, failed_jobs_only=failed_jobs_only)

    # ─── GitLab ───────────────────────────────────────────────────────────────

    async def _retry_gitlab_pipeline(self, project_id: str, pipeline_id: int) -> dict:
        """Retry a failed GitLab pipeline."""
        if not self.gitlab_token:
            return {"error": "GITLAB_TOKEN not configured"}

        url = f"{self.gitlab_url}/api/v4/projects/{project_id}/pipelines/{pipeline_id}/retry"
        headers = {"PRIVATE-TOKEN": self.gitlab_token}

        async with httpx.AsyncClient(headers=headers, timeout=30) as client:
            try:
                resp = await client.post(url)
                if resp.status_code in [200, 201]:
                    return {
                        "success": True,
                        "message": f"GitLab pipeline {pipeline_id} retry triggered",
                        "pipeline": resp.json(),
                    }
                else:
                    return {"error": f"Failed to retry pipeline: {resp.status_code}"}
            except Exception as e:
                return {"error": str(e)}

    async def _create_gitlab_mr(
        self, project_id: str, file_path: str, new_content: str, title: str, description: str
    ) -> dict:
        """Create a GitLab merge request with a fix."""
        if not self.gitlab_token:
            return {"error": "GITLAB_TOKEN not configured"}

        headers = {"PRIVATE-TOKEN": self.gitlab_token, "Content-Type": "application/json"}
        base_url = f"{self.gitlab_url}/api/v4/projects/{project_id}"

        async with httpx.AsyncClient(headers=headers, timeout=60) as client:
            try:
                # 1. Get default branch
                project_resp = await client.get(base_url)
                default_branch = project_resp.json().get("default_branch", "main")

                # 2. Create a new branch
                branch_name = f"fix-{file_path.replace('/', '-')}-{__import__('time').time_ns()}"
                create_branch_resp = await client.post(
                    f"{base_url}/repository/branches",
                    json={"branch": branch_name, "ref": default_branch}
                )
                
                if create_branch_resp.status_code not in [200, 201]:
                    return {"error": f"Failed to create branch: {create_branch_resp.status_code}"}

                # 3. Update file
                import base64
                content_b64 = base64.b64encode(new_content.encode()).decode()
                
                update_resp = await client.put(
                    f"{base_url}/repository/files/{file_path.replace('/', '%2F')}",
                    json={
                        "branch": branch_name,
                        "content": content_b64,
                        "commit_message": f"Fix: {title}",
                        "encoding": "base64",
                    }
                )
                
                if update_resp.status_code not in [200, 201]:
                    return {"error": f"Failed to update file: {update_resp.status_code}"}

                # 4. Create MR
                mr_resp = await client.post(
                    f"{base_url}/merge_requests",
                    json={
                        "source_branch": branch_name,
                        "target_branch": default_branch,
                        "title": title,
                        "description": description,
                    }
                )
                
                if mr_resp.status_code in [200, 201]:
                    mr_data = mr_resp.json()
                    return {
                        "success": True,
                        "merge_request_url": mr_data.get("web_url"),
                        "merge_request_iid": mr_data.get("iid"),
                        "branch": branch_name,
                    }
                else:
                    return {"error": f"Failed to create MR: {mr_resp.status_code}"}

            except Exception as e:
                return {"error": str(e)}

    # ─── Bitbucket Cloud ──────────────────────────────────────────────────────

    def _bitbucket_auth(self) -> Optional[tuple]:
        if self.bitbucket_user and self.bitbucket_token:
            return (self.bitbucket_user, self.bitbucket_token)
        return None

    def _bitbucket_headers(self) -> dict:
        if self.bitbucket_token and not self.bitbucket_user:
            return {"Authorization": f"Bearer {self.bitbucket_token}"}
        return {}

    async def _create_bitbucket_pr(
        self,
        repo: str,
        file_path: str,
        new_content: str,
        title: str,
        description: str,
    ) -> dict:
        """Create a branch, commit a file, and open a Bitbucket Cloud pull request.

        repo format: workspace/repo_slug
        """
        if not self.bitbucket_token:
            return {"error": "BITBUCKET_APP_PASSWORD or BITBUCKET_TOKEN not configured"}
        if "/" not in (repo or ""):
            return {"error": "Bitbucket repo must be workspace/repo_slug"}

        from datetime import datetime, timezone

        branch_name = f"devops-ai-fix/{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        base = f"{self.bitbucket_api}/repositories/{repo}"
        auth = self._bitbucket_auth()
        headers = self._bitbucket_headers()

        async with httpx.AsyncClient(timeout=60) as client:
            try:
                repo_resp = await client.get(base, auth=auth, headers=headers)
                if repo_resp.status_code != 200:
                    return {
                        "error": (
                            f"Bitbucket repo not found: {repo_resp.status_code} "
                            f"{repo_resp.text[:300]}"
                        )
                    }
                mainbranch = (repo_resp.json().get("mainbranch") or {}).get("name") or "main"

                # Create branch from main tip
                tip = await client.get(
                    f"{base}/refs/branches/{mainbranch}", auth=auth, headers=headers
                )
                if tip.status_code != 200:
                    return {
                        "error": f"Failed to read branch {mainbranch}: {tip.status_code}"
                    }
                target_hash = ((tip.json().get("target") or {}).get("hash")) or ""
                if not target_hash:
                    return {"error": f"No commit hash for branch {mainbranch}"}

                branch_resp = await client.post(
                    f"{base}/refs/branches",
                    auth=auth,
                    headers={**headers, "Content-Type": "application/json"},
                    json={"name": branch_name, "target": {"hash": target_hash}},
                )
                if branch_resp.status_code not in (200, 201):
                    return {
                        "error": (
                            f"Failed to create Bitbucket branch: "
                            f"{branch_resp.status_code} {branch_resp.text[:300]}"
                        )
                    }

                # Commit file via /src (multipart)
                commit_resp = await client.post(
                    f"{base}/src",
                    auth=auth,
                    headers=headers,
                    data={
                        "message": f"fix: {title}",
                        "branch": branch_name,
                        file_path: new_content,
                    },
                )
                if commit_resp.status_code not in (200, 201):
                    return {
                        "error": (
                            f"Failed to commit to Bitbucket: "
                            f"{commit_resp.status_code} {commit_resp.text[:400]}"
                        )
                    }

                pr_resp = await client.post(
                    f"{base}/pullrequests",
                    auth=auth,
                    headers={**headers, "Content-Type": "application/json"},
                    json={
                        "title": f"[AI Fix] {title}",
                        "description": (
                            f"{description}\n\n"
                            "Opened by the DevOps AI Agent. Review before merging."
                        ),
                        "source": {"branch": {"name": branch_name}},
                        "destination": {"branch": {"name": mainbranch}},
                        "close_source_branch": True,
                    },
                )
                if pr_resp.status_code not in (200, 201):
                    return {
                        "error": (
                            f"Failed to create Bitbucket PR: "
                            f"{pr_resp.status_code} {pr_resp.text[:400]}"
                        )
                    }
                pr = pr_resp.json()
                return {
                    "success": True,
                    "pr_id": pr.get("id"),
                    "pr_url": (pr.get("links") or {}).get("html", {}).get("href"),
                    "branch": branch_name,
                    "repository": repo,
                    "message": f"Bitbucket PR {pr.get('id')} created",
                }
            except Exception as e:
                return {"error": str(e)}

    # ─── Jenkins ──────────────────────────────────────────────────────────────

    async def _retry_jenkins_build(self, job_name: str) -> dict:
        """Trigger a new Jenkins build."""
        if not self.jenkins_url:
            return {"error": "JENKINS_URL not configured"}

        url = f"{self.jenkins_url}/job/{job_name}/build"
        auth = (self.jenkins_username, self.jenkins_token) if self.jenkins_username else None

        async with httpx.AsyncClient(auth=auth, timeout=30) as client:
            try:
                resp = await client.post(url)
                if resp.status_code in [200, 201]:
                    return {
                        "success": True,
                        "message": f"Jenkins job {job_name} build triggered",
                    }
                else:
                    return {"error": f"Failed to trigger build: {resp.status_code}"}
            except Exception as e:
                return {"error": str(e)}

    # ─── Bamboo ───────────────────────────────────────────────────────────────

    async def increment_bamboo_version(
        self,
        plan_key: str,
        variable_name: Optional[str] = None,
        current_version: Optional[str] = None,
        queue_build: bool = True,
    ) -> dict:
        """Bump a Bamboo plan version: PlanResource variable + latest ResultResource build number."""
        if not self.bamboo_url:
            return {"error": "BAMBOO_URL not configured"}
        variable_name = variable_name or os.getenv("BAMBOO_VERSION_VARIABLE") or "version"

        version = current_version
        if not version:
            fetched = await self._get_bamboo_variable(plan_key, variable_name)
            if fetched.get("error"):
                return fetched
            version = fetched.get("value")
        bumped = bump_patch_version(version)
        if not bumped:
            return {
                "error": f"Cannot increment Bamboo version {version!r} — expected a numeric or semver value",
                "alerted": True,
            }

        updated = await self._set_bamboo_variable(plan_key, variable_name, bumped)
        if updated.get("error"):
            return updated

        queued = None
        if queue_build:
            queued = await self._retry_bamboo_build(
                plan_key, extra_variables={variable_name: bumped}
            )
        return {
            "success": True,
            "plan_key": plan_key,
            "variable": variable_name,
            "previous_version": version,
            "new_version": bumped,
            "queued": queued,
            "message": f"Bamboo {plan_key} {variable_name} {version} → {bumped}",
        }

    async def patch_bamboo_plan(
        self,
        plan_key: str,
        increment_version: bool = True,
        variable_name: Optional[str] = None,
        current_version: Optional[str] = None,
    ) -> dict:
        """Re-queue a Bamboo plan, optionally incrementing its version first (patch release)."""
        if increment_version:
            return await self.increment_bamboo_version(
                plan_key,
                variable_name=variable_name,
                current_version=current_version,
                queue_build=True,
            )
        return await self._retry_bamboo_build(plan_key)

    async def check_bamboo_version(
        self,
        plan_key: str,
        variable_name: Optional[str] = None,
        expected_version: Optional[str] = None,
    ) -> dict:
        """Read plan variable + latest build result (ResultResource).

        GET /rest/api/latest/plan/{key}/variables/{name}
        GET /rest/api/latest/result/{key}-latest
        """
        if not self.bamboo_url:
            return {"error": "BAMBOO_URL not configured"}
        variable_name = variable_name or os.getenv("BAMBOO_VERSION_VARIABLE") or "version"
        fetched = await self._get_bamboo_variable(plan_key, variable_name)
        latest = await self._get_bamboo_latest_result(plan_key)
        plan_version = None if fetched.get("error") else fetched.get("value")
        expected = expected_version
        matches = None
        if expected is not None and plan_version is not None:
            matches = str(plan_version) == str(expected)
        return {
            "success": not fetched.get("error") or not latest.get("error"),
            "plan_key": plan_key,
            "variable": variable_name,
            "plan_version": plan_version,
            "variable_error": fetched.get("error"),
            "latest_build_number": latest.get("buildNumber") or latest.get("number"),
            "latest_state": latest.get("state") or latest.get("lifeCycleState"),
            "latest_result_key": latest.get("key"),
            "latest_error": latest.get("error"),
            "expected_version": expected,
            "matches_expected": matches,
            "message": (
                f"Bamboo {plan_key} {variable_name}={plan_version} "
                f"latest build {latest.get('buildNumber') or latest.get('number')}"
            ),
        }

    async def _get_bamboo_latest_result(self, plan_key: str) -> dict:
        auth = (self.bamboo_username, self.bamboo_password) if self.bamboo_username else None
        headers = {"Accept": "application/json"}
        base = f"{self.bamboo_url.rstrip('/')}/rest/api/latest/result"
        async with httpx.AsyncClient(auth=auth, timeout=30, headers=headers) as client:
            try:
                resp = await client.get(f"{base}/{plan_key}-latest")
            except Exception as e:
                return {"error": str(e)}
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, dict) else {"error": "Unexpected latest result payload"}
            try:
                resp = await client.get(f"{base}/{plan_key}", params={"max-results": 1})
            except Exception as e:
                return {"error": str(e)}
        if resp.status_code != 200:
            return {"error": f"Could not fetch Bamboo latest result: {resp.status_code}"}
        data = resp.json()
        results = (data.get("results") or {}).get("result") or []
        if isinstance(results, dict):
            results = [results]
        if results:
            return results[0]
        return {"error": f"No Bamboo results for {plan_key}"}

    def _bamboo_plan_url(self, plan_key: str) -> str:
        return f"{self.bamboo_url.rstrip('/')}/rest/api/latest/plan/{plan_key}"

    async def _get_bamboo_variable(self, plan_key: str, variable_name: str) -> dict:
        """Read a plan variable via PlanResource.

        Primary: GET /rest/api/latest/plan/{projectKey}-{buildKey}/variables/{variableName}
        (getPlanVariable). Fallback: GET .../plan/{key}?expand=variableContext (getPlan).
        """
        auth = (self.bamboo_username, self.bamboo_password) if self.bamboo_username else None
        headers = {"Accept": "application/json"}
        plan_url = self._bamboo_plan_url(plan_key)
        async with httpx.AsyncClient(auth=auth, timeout=30, headers=headers) as client:
            try:
                resp = await client.get(f"{plan_url}/variables/{variable_name}")
            except Exception as e:
                return {"error": str(e)}
            if resp.status_code == 200:
                value = _bamboo_variable_value(resp.json(), variable_name)
                if value is not None:
                    return {"value": value}
            try:
                resp = await client.get(plan_url, params={"expand": "variableContext"})
            except Exception as e:
                return {"error": str(e)}
        if resp.status_code != 200:
            return {"error": f"Could not fetch Bamboo plan variables: {resp.status_code}"}
        value = _bamboo_variable_value(resp.json(), variable_name)
        if value is not None:
            return {"value": value}
        return {"error": f"Bamboo variable {variable_name!r} not found on plan {plan_key}"}

    async def _set_bamboo_variable(self, plan_key: str, variable_name: str, value: str) -> dict:
        """Update a plan variable via PlanResource.editPlanVariable.

        PUT /rest/api/latest/plan/{projectKey}-{buildKey}/variables/{variableName}
        with RestVariable body {name, value}.
        """
        auth = (self.bamboo_username, self.bamboo_password) if self.bamboo_username else None
        url = f"{self._bamboo_plan_url(plan_key)}/variables/{variable_name}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        async with httpx.AsyncClient(auth=auth, timeout=30, headers=headers) as client:
            try:
                resp = await client.put(url, json={"name": variable_name, "value": value})
            except Exception as e:
                return {"error": str(e)}
        if resp.status_code not in (200, 201, 204):
            return {"error": f"Failed to set Bamboo variable: {resp.status_code}"}
        return {"success": True, "variable": variable_name, "value": value}

    async def _retry_bamboo_build(self, plan_key: str, extra_variables: Optional[dict] = None) -> dict:
        """Trigger a new Bamboo build via QueueResource.

        POST /rest/api/latest/queue/{projectKey}-{buildKey}
        with optional bamboo.variable.<name>=value query params.
        """
        if not self.bamboo_url:
            return {"error": "BAMBOO_URL not configured"}

        url = f"{self.bamboo_url.rstrip('/')}/rest/api/latest/queue/{plan_key}"
        auth = (self.bamboo_username, self.bamboo_password) if self.bamboo_username else None
        params = {}
        for key, value in (extra_variables or {}).items():
            params[f"bamboo.variable.{key}"] = value

        async with httpx.AsyncClient(auth=auth, timeout=30) as client:
            try:
                resp = await client.post(url, params=params or None)
                if resp.status_code in [200, 201]:
                    return {
                        "success": True,
                        "message": f"Bamboo plan {plan_key} build queued",
                    }
                else:
                    return {"error": f"Failed to queue build: {resp.status_code}"}
            except Exception as e:
                return {"error": str(e)}

    # ─── Azure DevOps ─────────────────────────────────────────────────────────

    async def _retry_azure_pipeline(self, project: str, pipeline_id: int, run_id: int) -> dict:
        """Retry a failed Azure DevOps pipeline."""
        if not self.azure_org or not self.azure_pat:
            return {"error": "AZURE_DEVOPS_ORG and AZURE_DEVOPS_PAT not configured"}

        import base64
        auth_string = f":{self.azure_pat}"
        auth_b64 = base64.b64encode(auth_string.encode()).decode()
        
        headers = {
            "Authorization": f"Basic {auth_b64}",
            "Content-Type": "application/json",
        }

        url = f"https://dev.azure.com/{self.azure_org}/{project}/_apis/pipelines/{pipeline_id}/runs?api-version=7.0"

        async with httpx.AsyncClient(headers=headers, timeout=30) as client:
            try:
                # Trigger a new run
                resp = await client.post(url, json={})
                if resp.status_code in [200, 201]:
                    run_data = resp.json()
                    return {
                        "success": True,
                        "message": f"Azure pipeline {pipeline_id} run triggered",
                        "run_id": run_data.get("id"),
                        "url": run_data.get("url"),
                    }
                else:
                    return {"error": f"Failed to trigger pipeline: {resp.status_code}"}
            except Exception as e:
                return {"error": str(e)}

    def _azure_headers(self) -> dict:
        import base64

        auth_b64 = base64.b64encode(f":{self.azure_pat}".encode()).decode()
        return {
            "Authorization": f"Basic {auth_b64}",
            "Content-Type": "application/json",
        }

    async def _create_azure_pr(
        self, project: str, repo: str, file_path: str, new_content: str, title: str, description: str
    ) -> dict:
        """Create a branch, commit, and pull request via Azure DevOps Git API 7.1."""
        if not self.azure_org or not self.azure_pat:
            return {"error": "AZURE_DEVOPS_ORG and AZURE_DEVOPS_PAT not configured"}
        if not project:
            return {"error": "Azure DevOps project is required (additional_params.project or AZURE_DEVOPS_PROJECT)"}
        if not repo:
            return {"error": "Azure DevOps repository name is required"}

        from datetime import datetime, timezone

        headers = self._azure_headers()
        api = "api-version=7.1"
        base = f"https://dev.azure.com/{self.azure_org}/{project}/_apis/git/repositories/{repo}"
        path = file_path if file_path.startswith("/") else f"/{file_path}"
        branch_name = f"devops-ai-fix/{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        async with httpx.AsyncClient(headers=headers, timeout=60) as client:
            repo_resp = await client.get(f"{base}?{api}")
            if repo_resp.status_code != 200:
                return {"error": f"Azure repo not found: {repo_resp.status_code} {repo_resp.text}"}
            default_branch = (repo_resp.json().get("defaultBranch") or "refs/heads/main").replace(
                "refs/heads/", ""
            )

            ref_resp = await client.get(
                f"{base}/refs?filter=heads/{default_branch}&{api}"
            )
            if ref_resp.status_code != 200:
                return {"error": f"Failed to read default branch: {ref_resp.status_code}"}
            refs = ref_resp.json().get("value") or []
            if not refs:
                return {"error": f"Default branch {default_branch} not found"}
            old_object_id = refs[0]["objectId"]

            item_resp = await client.get(
                f"{base}/items",
                params={"path": path, "versionDescriptor.version": default_branch, "api-version": "7.1"},
            )
            change_type = "edit" if item_resp.status_code == 200 else "add"

            push_resp = await client.post(
                f"{base}/pushes?{api}",
                json={
                    "refUpdates": [
                        {"name": f"refs/heads/{branch_name}", "oldObjectId": old_object_id}
                    ],
                    "commits": [
                        {
                            "comment": f"fix: {title}",
                            "changes": [
                                {
                                    "changeType": change_type,
                                    "item": {"path": path},
                                    "newContent": {
                                        "content": new_content,
                                        "contentType": "rawtext",
                                    },
                                }
                            ],
                        }
                    ],
                },
            )
            if push_resp.status_code not in (200, 201):
                return {"error": f"Failed to push Azure branch: {push_resp.status_code} {push_resp.text}"}

            pr_resp = await client.post(
                f"{base}/pullrequests?{api}",
                json={
                    "sourceRefName": f"refs/heads/{branch_name}",
                    "targetRefName": f"refs/heads/{default_branch}",
                    "title": f"[AI Fix] {title}",
                    "description": (
                        f"{description}\n\n"
                        "This PR was opened by the DevOps AI Agent. Review before merging."
                    ),
                },
            )
            if pr_resp.status_code not in (200, 201):
                return {"error": f"Failed to create Azure PR: {pr_resp.status_code} {pr_resp.text}"}
            pr = pr_resp.json()
            return {
                "success": True,
                "pr_id": pr.get("pullRequestId"),
                "pr_url": pr.get("url"),
                "branch": branch_name,
                "repository": repo,
                "message": f"Azure DevOps PR {pr.get('pullRequestId')} created",
            }


def _bamboo_variable_value(payload, variable_name: str) -> Optional[str]:
    """Extract a variable value from RestVariable or getPlan expand=variableContext."""
    if not isinstance(payload, dict):
        return None
    if payload.get("name") == variable_name or payload.get("key") == variable_name:
        value = payload.get("value")
        return str(value) if value is not None else None
    # getPlanVariable is already scoped to the name in the URL.
    if "variableContext" not in payload and "value" in payload:
        value = payload.get("value")
        return str(value) if value is not None else None
    variables = payload.get("variableContext", {}).get("variable", [])
    if isinstance(variables, dict):
        variables = [variables]
    for item in variables:
        if item.get("key") == variable_name or item.get("name") == variable_name:
            value = item.get("value")
            return str(value) if value is not None else None
    return None


_SEMVER_SUFFIX = re.compile(r"^(\d+(?:\.\d+)*)([.-]?[A-Za-z0-9-]*)?$")


def bump_patch_version(version: Optional[str]) -> Optional[str]:
    """Increment the last numeric component of a version (1.2.3 → 1.2.4, 14 → 15)."""
    if not version or not isinstance(version, str):
        return None
    raw = version.strip()
    match = _SEMVER_SUFFIX.match(raw)
    if not match:
        return None
    numeric, suffix = match.group(1), match.group(2) or ""
    parts = numeric.split(".")
    if not parts[-1].isdigit():
        return None
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts) + suffix
