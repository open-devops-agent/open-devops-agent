"""
GitHub CI Log Collector
Fetches failed workflow run logs from GitHub Actions API.
"""
import os
import zipfile
import io

import httpx
import structlog

log = structlog.get_logger()


class GitHubCollector:
    def __init__(self, base_url: str | None = None):
        self.token = os.getenv("GITHUB_TOKEN", "")
        self.headers = self._build_headers()
        self.base = (base_url or "https://api.github.com").rstrip("/")

    def _build_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN', '')}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def refresh_credentials(self) -> None:
        self.token = os.getenv("GITHUB_TOKEN", "")
        self.headers = self._build_headers()

    async def collect(self, repo: str, run_id: int) -> dict:
        """Fetch full logs for a failed workflow run."""
        async with httpx.AsyncClient(headers=self.headers, timeout=30) as client:
            # Get run details
            run_resp = await client.get(f"{self.base}/repos/{repo}/actions/runs/{run_id}")
            if run_resp.status_code != 200:
                return {"error": f"Could not fetch run: {run_resp.status_code}"}

            run = run_resp.json()

            # Get failed jobs
            jobs_resp = await client.get(f"{self.base}/repos/{repo}/actions/runs/{run_id}/jobs")
            jobs = jobs_resp.json().get("jobs", [])
            failed_jobs = [j for j in jobs if j.get("conclusion") == "failure"]

            result = {
                "run_id": run_id,
                "workflow": run.get("name"),
                "branch": run.get("head_branch"),
                "commit": run.get("head_sha", "")[:8],
                "trigger": run.get("event"),
                "url": run.get("html_url"),
                "failed_jobs": [],
            }

            # Fetch logs for each failed job
            for job in failed_jobs[:3]:
                job_info = {
                    "name": job["name"],
                    "steps": [
                        {
                            "name": s["name"],
                            "conclusion": s.get("conclusion"),
                            "number": s["number"],
                        }
                        for s in job.get("steps", [])
                        if s.get("conclusion") == "failure"
                    ],
                }

                # Get job logs
                try:
                    logs_resp = await client.get(
                        f"{self.base}/repos/{repo}/actions/jobs/{job['id']}/logs",
                        follow_redirects=True,
                    )
                    if logs_resp.status_code == 200:
                        # Truncate to last 6000 chars to focus on the error
                        log_text = logs_resp.text
                        job_info["logs"] = log_text[-6000:] if len(log_text) > 6000 else log_text
                except Exception as e:
                    job_info["logs_error"] = str(e)

                result["failed_jobs"].append(job_info)

            return result
