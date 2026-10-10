"""
Multi-platform code review: GitHub, GitLab, Bitbucket, Azure DevOps, or any local git repo.

Fetch PR/MR (or git) diffs, run lightweight heuristic checks (secrets, backdoors,
malware cradles, BAT/CMD/PowerShell, destructive ops), and post review comments.
Never merges. Default review event is COMMENT (not APPROVE).
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
from typing import Any, Optional
from urllib.parse import quote

import httpx
import structlog

from tools.safety import emergency_stop_block, is_emergency_stop_active

log = structlog.get_logger()

MAX_DIFF_CHARS = int(os.getenv("CODE_REVIEW_MAX_DIFF_CHARS", "80000"))
MAX_FILES = int(os.getenv("CODE_REVIEW_MAX_FILES", "40"))

_SECRET_PATTERNS = (
    (re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}"), "Possible hard-coded secret"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "Possible AWS access key id"),
    (re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"), "Private key material in diff"),
    (re.compile(r"(?i)ghp_[A-Za-z0-9]{20,}"), "Possible GitHub personal access token"),
    (re.compile(r"(?i)glpat-[A-Za-z0-9_\-]{20,}"), "Possible GitLab personal access token"),
)

_RISK_PATTERNS = (
    (re.compile(r"\brm\s+-rf\s+/"), "Destructive rm -rf / in change"),
    (re.compile(r"(?i)DROP\s+(TABLE|DATABASE)\b"), "Destructive SQL DROP"),
    (re.compile(r"(?i)kubectl\s+delete\s+(ns|namespace|pv)\b"), "Cluster-destructive kubectl delete"),
    (re.compile(r"(?i)--privileged\b"), "Privileged container flag"),
    (re.compile(r"(?i)ALLOW_HTTP|insecure.?skip.?verify\s*[:=]\s*true"), "TLS verification disabled"),
)

# Backdoors, malware cradles, suspicious BAT/CMD/PowerShell, reverse shells, web shells.
_MALWARE_PATTERNS = (
    # Reverse / bind shells
    (
        re.compile(
            r"(?i)(bash\s+-i\s+>&\s*/dev/tcp/|nc\s+(-e|--exec)|ncat\s+.*-e|"
            r"/dev/tcp/\d|/dev/udp/\d|socat\s+.*EXEC:|mkfifo\s+/tmp/.*nc\s)"
        ),
        "Possible reverse/bind shell (backdoor)",
    ),
    (
        re.compile(
            r"(?i)(socket\.socket\s*\(.*SOCK_STREAM|connect\s*\(\s*\([^)]+\d{1,3}"
            r"(?:\.\d{1,3}){3})"
        ),
        "Possible socket backdoor / C2 connect",
    ),
    # Encoded / obfuscated payloads
    (
        re.compile(
            r"(?i)(powershell[^\n]*(-enc|-e\s+|FromBase64String)|"
            r"IEX\s*\(\s*New-Object\s+Net\.WebClient|"
            r"Invoke-Expression\s*\(|DownloadString\s*\(|DownloadFile\s*\()"
        ),
        "PowerShell download/execute or encoded payload (malware cradle)",
    ),
    (
        re.compile(
            r"(?i)(base64\s+-d|base64\.b64decode|Buffer\.from\([^,]+,\s*['\"]base64['\"]|"
            r"eval\s*\(\s*(atob|Buffer|base64)|exec\s*\(\s*base64)"
        ),
        "Base64 decode + exec/eval (obfuscated malware)",
    ),
    (
        re.compile(
            r"(?i)(eval\s*\(\s*(request|req\.|params|query|body|input)|"
            r"exec\s*\(\s*(request|req\.|params|query|body)|"
            r"compile\s*\([^)]*['\"]exec['\"])"
        ),
        "Dynamic eval/exec of request input (webshell/backdoor)",
    ),
    # Windows BAT / CMD malware patterns
    (
        re.compile(
            r"(?i)(bitsadmin\s+/transfer|certutil\s+-urlcache|certutil\s+-decode|"
            r"curl\s+[^\n]*\|\s*(cmd|powershell|bash)|"
            r"wget\s+[^\n]*\|\s*(bash|sh|cmd)|"
            r"mshta\s+https?://|regsvr32\s+/s\s+/n\s+/u\s+/i:|"
            r"rundll32\s+javascript:|wmic\s+process\s+call\s+create)"
        ),
        "Suspicious Windows download/execute (BAT/CMD malware)",
    ),
    (
        re.compile(
            r"(?i)(reg\s+add\s+.*\\(Run|RunOnce)\\|schtasks\s+/create|"
            r"New-ScheduledTask|\\\\CurrentVersion\\\\Run)"
        ),
        "Persistence via registry Run key or scheduled task",
    ),
    # Unix persistence / crypto miners
    (
        re.compile(
            r"(?i)(curl\s+[^\n]*\|\s*(bash|sh)\b|wget\s+[^\n]*-O-?\s*\|\s*(bash|sh)\b|"
            r"xmrig|minerd\b|stratum\+tcp://|cryptonight)"
        ),
        "Pipe-to-shell download or crypto-miner indicator",
    ),
    (
        re.compile(
            r"(?i)(crontab\s+-e|@reboot\s+(curl|wget|nc|bash\s+-i)|"
            r"echo\s+[^|]+\|\s*crontab)"
        ),
        "Suspicious crontab persistence",
    ),
    # Classic webshells / remote code
    (
        re.compile(
            r"(?i)(c99shell|r57shell|FilesMan|WSO\s*shell|"
            r"assert\s*\(\s*\$_(GET|POST|REQUEST)|"
            r"system\s*\(\s*\$_(GET|POST|REQUEST)|"
            r"passthru\s*\(\s*\$_(GET|POST|REQUEST)|"
            r"shell_exec\s*\(\s*\$_(GET|POST|REQUEST)|"
            r"preg_replace\s*\(.*/e)"
        ),
        "Webshell / remote code execution pattern",
    ),
    (
        re.compile(
            r"(?i)(__import__\s*\(\s*['\"]os['\"]\s*\)\.system|"
            r"subprocess\.(call|Popen|run)\s*\([^)]*(/bin/(ba)?sh|cmd\.exe|powershell)|"
            r"os\.system\s*\(\s*(request|req\.|input\())"
        ),
        "Suspicious OS command execution from app code",
    ),
    # Dangerous file types added with executable payload hints in path
    (
        re.compile(
            r"(?i)\.(bat|cmd|ps1|vbs|hta|scr|pif)\b"
        ),
        "Windows script/executable-type path in change — inspect for malware",
    ),
)


class CodeReviewTools:
    """Fetch and post code reviews across git hosts."""

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self._client = client
        self.github_token = os.getenv("GITHUB_TOKEN", "")
        self.github_api = os.getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/")
        self.gitlab_token = os.getenv("GITLAB_TOKEN", "")
        self.gitlab_url = os.getenv("GITLAB_URL", "https://gitlab.com").rstrip("/")
        self.bitbucket_user = os.getenv("BITBUCKET_USERNAME", "")
        self.bitbucket_token = os.getenv("BITBUCKET_APP_PASSWORD", "") or os.getenv(
            "BITBUCKET_TOKEN", ""
        )
        self.bitbucket_api = os.getenv(
            "BITBUCKET_API_URL", "https://api.bitbucket.org/2.0"
        ).rstrip("/")
        self.azure_org = os.getenv("AZURE_DEVOPS_ORG", "")
        self.azure_pat = os.getenv("AZURE_DEVOPS_PAT", "")
        self.azure_project = os.getenv("AZURE_DEVOPS_PROJECT", "")

    async def fetch_change(
        self,
        platform: str,
        repo: str,
        change_id: str,
        project: Optional[str] = None,
        workspace_path: Optional[str] = None,
        base_ref: Optional[str] = None,
        head_ref: Optional[str] = None,
    ) -> dict:
        """Load PR/MR metadata + unified diff + heuristic findings."""
        platform = _normalize_platform(platform)
        if platform == "github":
            result = await self._github_fetch(repo, change_id)
        elif platform == "gitlab":
            result = await self._gitlab_fetch(repo, change_id)
        elif platform == "bitbucket":
            result = await self._bitbucket_fetch(repo, change_id)
        elif platform == "azure_devops":
            result = await self._azure_fetch(
                project or self.azure_project, repo, change_id
            )
        elif platform == "git":
            result = await self._local_git_fetch(workspace_path, base_ref, head_ref)
        else:
            return {
                "error": (
                    f"Unsupported platform {platform!r}. "
                    "Use github, gitlab, bitbucket, azure_devops, or git."
                )
            }

        if result.get("error"):
            return result

        diff = result.get("diff") or ""
        truncated = False
        if len(diff) > MAX_DIFF_CHARS:
            diff = diff[:MAX_DIFF_CHARS] + "\n\n… [diff truncated for review size]\n"
            truncated = True
            result["diff"] = diff

        files = result.get("files") or []
        if len(files) > MAX_FILES:
            result["files"] = files[:MAX_FILES]
            result["files_truncated"] = True

        findings = scan_diff_heuristics(diff)
        result["heuristic_findings"] = findings
        result["diff_truncated"] = truncated
        result["platform"] = platform
        result["success"] = True
        result["message"] = (
            f"Fetched {platform} change {change_id} "
            f"({len(result.get('files') or [])} files, {len(findings)} heuristic findings)"
        )
        return result

    async def post_review(
        self,
        platform: str,
        repo: str,
        change_id: str,
        summary: str,
        event: str = "COMMENT",
        comments: Optional[list] = None,
        project: Optional[str] = None,
        dry_run: bool = True,
    ) -> dict:
        """Post a review/comment on a PR/MR. Never merges. Never auto-approves by default."""
        if is_emergency_stop_active():
            return emergency_stop_block("Code review posting disabled during emergency stop.")

        platform = _normalize_platform(platform)
        event = (event or "COMMENT").upper()
        if event in ("APPROVE", "APPROVED"):
            if os.getenv("CODE_REVIEW_ALLOW_APPROVE", "false").lower() not in (
                "true",
                "1",
                "yes",
            ):
                event = "COMMENT"
                summary = (
                    f"{summary}\n\n_(Agent refused APPROVE — "
                    "set CODE_REVIEW_ALLOW_APPROVE=true to enable.)_"
                )

        if event in ("MERGE", "MERGE_PR"):
            return {
                "blocked": True,
                "success": False,
                "message": "Merging pull/merge requests is never allowed from the agent.",
            }

        body = _format_review_body(summary)
        comments = comments or []

        if dry_run or not _auto_post_enabled():
            return {
                "success": True,
                "dry_run": True,
                "platform": platform,
                "repo": repo,
                "change_id": change_id,
                "event": event,
                "summary": body,
                "comments": comments,
                "message": (
                    "Dry-run review prepared (not posted). "
                    "Set CODE_REVIEW_AUTO_POST=true or AUTO_APPLY=true, then dry_run=false."
                ),
            }

        if platform == "github":
            return await self._github_post(repo, change_id, body, event, comments)
        if platform == "gitlab":
            return await self._gitlab_post(repo, change_id, body, comments)
        if platform == "bitbucket":
            return await self._bitbucket_post(repo, change_id, body, comments)
        if platform == "azure_devops":
            return await self._azure_post(
                project or self.azure_project, repo, change_id, body, comments
            )
        if platform == "git":
            return {
                "success": True,
                "dry_run": True,
                "message": "Local git repos have nowhere to post — review returned as dry-run only.",
                "summary": body,
                "comments": comments,
            }
        return {"error": f"Unsupported platform {platform!r}"}

    async def list_open_changes(
        self,
        platform: str,
        repo: str,
        project: Optional[str] = None,
        limit: int = 10,
    ) -> dict:
        platform = _normalize_platform(platform)
        limit = max(1, min(int(limit or 10), 50))
        if platform == "github":
            return await self._github_list(repo, limit)
        if platform == "gitlab":
            return await self._gitlab_list(repo, limit)
        if platform == "bitbucket":
            return await self._bitbucket_list(repo, limit)
        if platform == "azure_devops":
            return await self._azure_list(project or self.azure_project, repo, limit)
        return {"error": f"list_open_changes not supported for {platform}"}

    # ─── GitHub ───────────────────────────────────────────────────────────────

    def _gh_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def _github_fetch(self, repo: str, change_id: str) -> dict:
        if not self.github_token:
            return {"error": "GITHUB_TOKEN not configured"}
        base = f"{self.github_api}/repos/{repo}/pulls/{change_id}"
        client = await self._http()
        owns = self._client is None
        try:
            meta = await client.get(base, headers=self._gh_headers())
            if meta.status_code != 200:
                return {"error": f"GitHub PR fetch failed: {meta.status_code} {meta.text[:300]}"}
            pr = meta.json()
            files_resp = await client.get(
                f"{base}/files", headers=self._gh_headers(), params={"per_page": MAX_FILES}
            )
            files = files_resp.json() if files_resp.status_code == 200 else []
            diff_headers = {**self._gh_headers(), "Accept": "application/vnd.github.v3.diff"}
            diff_resp = await client.get(base, headers=diff_headers)
            diff = diff_resp.text if diff_resp.status_code == 200 else ""
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()

        return {
            "repo": repo,
            "change_id": str(change_id),
            "title": pr.get("title"),
            "author": (pr.get("user") or {}).get("login"),
            "url": pr.get("html_url"),
            "base": (pr.get("base") or {}).get("ref"),
            "head": (pr.get("head") or {}).get("ref"),
            "state": pr.get("state"),
            "files": [
                {
                    "path": f.get("filename"),
                    "status": f.get("status"),
                    "additions": f.get("additions"),
                    "deletions": f.get("deletions"),
                }
                for f in files
                if isinstance(f, dict)
            ],
            "diff": diff,
        }

    async def _github_post(
        self, repo: str, change_id: str, body: str, event: str, comments: list
    ) -> dict:
        if not self.github_token:
            return {"error": "GITHUB_TOKEN not configured"}
        # Map to GitHub review events
        gh_event = {
            "COMMENT": "COMMENT",
            "REQUEST_CHANGES": "REQUEST_CHANGES",
            "CHANGES_REQUESTED": "REQUEST_CHANGES",
            "APPROVE": "APPROVE",
        }.get(event, "COMMENT")
        payload: dict[str, Any] = {"body": body, "event": gh_event}
        inline = []
        for c in comments:
            if not isinstance(c, dict):
                continue
            path = c.get("path") or c.get("file")
            line = c.get("line")
            if path and line:
                inline.append(
                    {
                        "path": path,
                        "line": int(line),
                        "side": c.get("side") or "RIGHT",
                        "body": c.get("body") or c.get("comment") or "",
                    }
                )
        if inline:
            payload["comments"] = inline

        url = f"{self.github_api}/repos/{repo}/pulls/{change_id}/reviews"
        client = await self._http()
        owns = self._client is None
        try:
            resp = await client.post(url, headers=self._gh_headers(), json=payload)
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()
        if resp.status_code not in (200, 201):
            return {"error": f"GitHub review post failed: {resp.status_code} {resp.text[:400]}"}
        data = resp.json()
        return {
            "success": True,
            "platform": "github",
            "review_id": data.get("id"),
            "html_url": data.get("html_url"),
            "event": gh_event,
            "message": f"Posted GitHub review on {repo}#{change_id}",
        }

    async def _github_list(self, repo: str, limit: int) -> dict:
        if not self.github_token:
            return {"error": "GITHUB_TOKEN not configured"}
        url = f"{self.github_api}/repos/{repo}/pulls"
        client = await self._http()
        owns = self._client is None
        try:
            resp = await client.get(
                url,
                headers=self._gh_headers(),
                params={"state": "open", "per_page": limit},
            )
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()
        if resp.status_code != 200:
            return {"error": f"GitHub list failed: {resp.status_code}"}
        items = [
            {
                "id": p.get("number"),
                "title": p.get("title"),
                "author": (p.get("user") or {}).get("login"),
                "url": p.get("html_url"),
            }
            for p in resp.json()
        ]
        return {"success": True, "platform": "github", "changes": items}

    # ─── GitLab ───────────────────────────────────────────────────────────────

    def _gl_headers(self) -> dict:
        return {"PRIVATE-TOKEN": self.gitlab_token}

    async def _gitlab_fetch(self, repo: str, change_id: str) -> dict:
        if not self.gitlab_token:
            return {"error": "GITLAB_TOKEN not configured"}
        project = quote(str(repo), safe="")
        base = f"{self.gitlab_url}/api/v4/projects/{project}/merge_requests/{change_id}"
        client = await self._http()
        owns = self._client is None
        try:
            meta = await client.get(base, headers=self._gl_headers())
            if meta.status_code != 200:
                return {"error": f"GitLab MR fetch failed: {meta.status_code} {meta.text[:300]}"}
            mr = meta.json()
            changes = await client.get(f"{base}/changes", headers=self._gl_headers())
            change_data = changes.json() if changes.status_code == 200 else {}
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()

        file_changes = change_data.get("changes") or []
        files = []
        diff_parts = []
        for ch in file_changes[:MAX_FILES]:
            path = ch.get("new_path") or ch.get("old_path")
            files.append(
                {
                    "path": path,
                    "status": "renamed"
                    if ch.get("renamed_file")
                    else ("deleted" if ch.get("deleted_file") else "modified"),
                }
            )
            if ch.get("diff"):
                diff_parts.append(f"--- a/{ch.get('old_path')}\n+++ b/{ch.get('new_path')}\n{ch['diff']}")
        return {
            "repo": repo,
            "change_id": str(change_id),
            "title": mr.get("title"),
            "author": (mr.get("author") or {}).get("username"),
            "url": mr.get("web_url"),
            "base": mr.get("target_branch"),
            "head": mr.get("source_branch"),
            "state": mr.get("state"),
            "files": files,
            "diff": "\n".join(diff_parts),
        }

    async def _gitlab_post(
        self, repo: str, change_id: str, body: str, comments: list
    ) -> dict:
        if not self.gitlab_token:
            return {"error": "GITLAB_TOKEN not configured"}
        project = quote(str(repo), safe="")
        note_url = (
            f"{self.gitlab_url}/api/v4/projects/{project}/merge_requests/{change_id}/notes"
        )
        client = await self._http()
        owns = self._client is None
        try:
            resp = await client.post(
                note_url, headers=self._gl_headers(), json={"body": body}
            )
            if resp.status_code not in (200, 201):
                return {
                    "error": f"GitLab note failed: {resp.status_code} {resp.text[:400]}"
                }
            note = resp.json()
            posted_inline = 0
            for c in comments:
                if not isinstance(c, dict) or not c.get("path"):
                    continue
                # Best-effort general note with file reference (positioned discussions need SHAs)
                line_note = (
                    f"**`{c.get('path')}`"
                    + (f":{c.get('line')}" if c.get("line") else "")
                    + f"**\n\n{c.get('body') or c.get('comment') or ''}"
                )
                inline = await client.post(
                    note_url, headers=self._gl_headers(), json={"body": line_note}
                )
                if inline.status_code in (200, 201):
                    posted_inline += 1
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()
        return {
            "success": True,
            "platform": "gitlab",
            "note_id": note.get("id"),
            "url": note.get("web_url"),
            "inline_notes": posted_inline,
            "message": f"Posted GitLab review note on {repo}!{change_id}",
        }

    async def _gitlab_list(self, repo: str, limit: int) -> dict:
        if not self.gitlab_token:
            return {"error": "GITLAB_TOKEN not configured"}
        project = quote(str(repo), safe="")
        url = f"{self.gitlab_url}/api/v4/projects/{project}/merge_requests"
        client = await self._http()
        owns = self._client is None
        try:
            resp = await client.get(
                url,
                headers=self._gl_headers(),
                params={"state": "opened", "per_page": limit},
            )
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()
        if resp.status_code != 200:
            return {"error": f"GitLab list failed: {resp.status_code}"}
        items = [
            {
                "id": m.get("iid"),
                "title": m.get("title"),
                "author": (m.get("author") or {}).get("username"),
                "url": m.get("web_url"),
            }
            for m in resp.json()
        ]
        return {"success": True, "platform": "gitlab", "changes": items}

    # ─── Bitbucket Cloud ──────────────────────────────────────────────────────

    def _bb_auth(self) -> Optional[tuple]:
        if self.bitbucket_user and self.bitbucket_token:
            return (self.bitbucket_user, self.bitbucket_token)
        return None

    def _bb_headers(self) -> dict:
        # Support bearer token (workspace access tokens) as well as app passwords
        if self.bitbucket_token and not self.bitbucket_user:
            return {"Authorization": f"Bearer {self.bitbucket_token}"}
        return {}

    async def _bitbucket_fetch(self, repo: str, change_id: str) -> dict:
        if not self.bitbucket_token:
            return {"error": "BITBUCKET_APP_PASSWORD or BITBUCKET_TOKEN not configured"}
        # repo = workspace/repo_slug
        base = f"{self.bitbucket_api}/repositories/{repo}/pullrequests/{change_id}"
        client = await self._http()
        owns = self._client is None
        try:
            meta = await client.get(base, auth=self._bb_auth(), headers=self._bb_headers())
            if meta.status_code != 200:
                return {
                    "error": f"Bitbucket PR fetch failed: {meta.status_code} {meta.text[:300]}"
                }
            pr = meta.json()
            diff_resp = await client.get(
                f"{base}/diff", auth=self._bb_auth(), headers=self._bb_headers()
            )
            diff = diff_resp.text if diff_resp.status_code == 200 else ""
            files_resp = await client.get(
                f"{base}/diffstat", auth=self._bb_auth(), headers=self._bb_headers()
            )
            files = []
            if files_resp.status_code == 200:
                for entry in (files_resp.json().get("values") or [])[:MAX_FILES]:
                    new_path = (entry.get("new") or {}).get("path")
                    old_path = (entry.get("old") or {}).get("path")
                    files.append(
                        {
                            "path": new_path or old_path,
                            "status": entry.get("status"),
                            "additions": entry.get("lines_added"),
                            "deletions": entry.get("lines_removed"),
                        }
                    )
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()

        author = pr.get("author") or {}
        return {
            "repo": repo,
            "change_id": str(change_id),
            "title": pr.get("title"),
            "author": author.get("display_name") or author.get("nickname"),
            "url": (pr.get("links") or {}).get("html", {}).get("href"),
            "base": ((pr.get("destination") or {}).get("branch") or {}).get("name"),
            "head": ((pr.get("source") or {}).get("branch") or {}).get("name"),
            "state": pr.get("state"),
            "files": files,
            "diff": diff,
        }

    async def _bitbucket_post(
        self, repo: str, change_id: str, body: str, comments: list
    ) -> dict:
        if not self.bitbucket_token:
            return {"error": "BITBUCKET_APP_PASSWORD or BITBUCKET_TOKEN not configured"}
        url = f"{self.bitbucket_api}/repositories/{repo}/pullrequests/{change_id}/comments"
        client = await self._http()
        owns = self._client is None
        try:
            resp = await client.post(
                url,
                auth=self._bb_auth(),
                headers={**self._bb_headers(), "Content-Type": "application/json"},
                json={"content": {"raw": body}},
            )
            if resp.status_code not in (200, 201):
                return {
                    "error": f"Bitbucket comment failed: {resp.status_code} {resp.text[:400]}"
                }
            data = resp.json()
            posted = 0
            for c in comments:
                if not isinstance(c, dict):
                    continue
                note = (
                    f"**`{c.get('path')}`"
                    + (f":{c.get('line')}" if c.get("line") else "")
                    + f"**\n\n{c.get('body') or c.get('comment') or ''}"
                )
                inline = await client.post(
                    url,
                    auth=self._bb_auth(),
                    headers={**self._bb_headers(), "Content-Type": "application/json"},
                    json={"content": {"raw": note}},
                )
                if inline.status_code in (200, 201):
                    posted += 1
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()
        return {
            "success": True,
            "platform": "bitbucket",
            "comment_id": data.get("id"),
            "inline_comments": posted,
            "message": f"Posted Bitbucket review on {repo} PR {change_id}",
        }

    async def _bitbucket_list(self, repo: str, limit: int) -> dict:
        if not self.bitbucket_token:
            return {"error": "BITBUCKET_APP_PASSWORD or BITBUCKET_TOKEN not configured"}
        url = f"{self.bitbucket_api}/repositories/{repo}/pullrequests"
        client = await self._http()
        owns = self._client is None
        try:
            resp = await client.get(
                url,
                auth=self._bb_auth(),
                headers=self._bb_headers(),
                params={"state": "OPEN", "pagelen": limit},
            )
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()
        if resp.status_code != 200:
            return {"error": f"Bitbucket list failed: {resp.status_code}"}
        items = []
        for p in resp.json().get("values") or []:
            author = p.get("author") or {}
            items.append(
                {
                    "id": p.get("id"),
                    "title": p.get("title"),
                    "author": author.get("display_name") or author.get("nickname"),
                    "url": (p.get("links") or {}).get("html", {}).get("href"),
                }
            )
        return {"success": True, "platform": "bitbucket", "changes": items}

    # ─── Azure DevOps ─────────────────────────────────────────────────────────

    def _azure_headers(self) -> dict:
        auth_b64 = base64.b64encode(f":{self.azure_pat}".encode()).decode()
        return {
            "Authorization": f"Basic {auth_b64}",
            "Content-Type": "application/json",
        }

    async def _azure_fetch(self, project: str, repo: str, change_id: str) -> dict:
        if not self.azure_org or not self.azure_pat:
            return {"error": "AZURE_DEVOPS_ORG and AZURE_DEVOPS_PAT not configured"}
        if not project:
            return {"error": "Azure DevOps project is required"}
        api = "api-version=7.1"
        base = (
            f"https://dev.azure.com/{self.azure_org}/{project}"
            f"/_apis/git/repositories/{repo}/pullrequests/{change_id}"
        )
        client = await self._http()
        owns = self._client is None
        try:
            meta = await client.get(f"{base}?{api}", headers=self._azure_headers())
            if meta.status_code != 200:
                return {
                    "error": f"Azure PR fetch failed: {meta.status_code} {meta.text[:300]}"
                }
            pr = meta.json()
            iters = await client.get(
                f"{base}/iterations?{api}", headers=self._azure_headers()
            )
            iteration_id = 1
            if iters.status_code == 200:
                values = iters.json().get("value") or []
                if values:
                    iteration_id = values[-1].get("id", 1)
            changes = await client.get(
                f"{base}/iterations/{iteration_id}/changes?{api}",
                headers=self._azure_headers(),
            )
            files = []
            if changes.status_code == 200:
                for ch in (changes.json().get("changeEntries") or [])[:MAX_FILES]:
                    item = ch.get("item") or {}
                    files.append(
                        {
                            "path": (item.get("path") or "").lstrip("/"),
                            "status": ch.get("changeType"),
                        }
                    )
            # Azure does not expose a single unified diff easily; synthesize from file list.
            diff = "\n".join(f"# {f.get('status')}: {f.get('path')}" for f in files)
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()

        return {
            "repo": repo,
            "change_id": str(change_id),
            "title": pr.get("title"),
            "author": (pr.get("createdBy") or {}).get("displayName"),
            "url": pr.get("url"),
            "base": (pr.get("targetRefName") or "").replace("refs/heads/", ""),
            "head": (pr.get("sourceRefName") or "").replace("refs/heads/", ""),
            "state": pr.get("status"),
            "files": files,
            "diff": diff,
            "note": "Azure DevOps returns change list; inline unified diff may be limited",
        }

    async def _azure_post(
        self, project: str, repo: str, change_id: str, body: str, comments: list
    ) -> dict:
        if not self.azure_org or not self.azure_pat:
            return {"error": "AZURE_DEVOPS_ORG and AZURE_DEVOPS_PAT not configured"}
        if not project:
            return {"error": "Azure DevOps project is required"}
        api = "api-version=7.1"
        url = (
            f"https://dev.azure.com/{self.azure_org}/{project}"
            f"/_apis/git/repositories/{repo}/pullRequests/{change_id}/threads?{api}"
        )
        client = await self._http()
        owns = self._client is None
        try:
            resp = await client.post(
                url,
                headers=self._azure_headers(),
                json={
                    "comments": [{"parentCommentId": 0, "content": body, "commentType": 1}],
                    "status": "active",
                },
            )
            if resp.status_code not in (200, 201):
                return {
                    "error": f"Azure thread failed: {resp.status_code} {resp.text[:400]}"
                }
            thread = resp.json()
            posted = 0
            for c in comments:
                if not isinstance(c, dict):
                    continue
                note = (
                    f"**`{c.get('path')}`"
                    + (f":{c.get('line')}" if c.get("line") else "")
                    + f"**\n\n{c.get('body') or c.get('comment') or ''}"
                )
                inline = await client.post(
                    url,
                    headers=self._azure_headers(),
                    json={
                        "comments": [
                            {"parentCommentId": 0, "content": note, "commentType": 1}
                        ],
                        "status": "active",
                    },
                )
                if inline.status_code in (200, 201):
                    posted += 1
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()
        return {
            "success": True,
            "platform": "azure_devops",
            "thread_id": thread.get("id"),
            "inline_threads": posted,
            "message": f"Posted Azure DevOps review on {repo} PR {change_id}",
        }

    async def _azure_list(self, project: str, repo: str, limit: int) -> dict:
        if not self.azure_org or not self.azure_pat:
            return {"error": "AZURE_DEVOPS_ORG and AZURE_DEVOPS_PAT not configured"}
        if not project:
            return {"error": "Azure DevOps project is required"}
        url = (
            f"https://dev.azure.com/{self.azure_org}/{project}"
            f"/_apis/git/repositories/{repo}/pullrequests"
        )
        client = await self._http()
        owns = self._client is None
        try:
            resp = await client.get(
                url,
                headers=self._azure_headers(),
                params={"searchCriteria.status": "active", "$top": limit, "api-version": "7.1"},
            )
        except Exception as e:
            return {"error": str(e)}
        finally:
            if owns:
                await client.aclose()
        if resp.status_code != 200:
            return {"error": f"Azure list failed: {resp.status_code}"}
        items = [
            {
                "id": p.get("pullRequestId"),
                "title": p.get("title"),
                "author": (p.get("createdBy") or {}).get("displayName"),
                "url": p.get("url"),
            }
            for p in resp.json().get("value") or []
        ]
        return {"success": True, "platform": "azure_devops", "changes": items}

    # ─── Local / any git repo ─────────────────────────────────────────────────

    async def _local_git_fetch(
        self,
        workspace_path: Optional[str],
        base_ref: Optional[str],
        head_ref: Optional[str],
    ) -> dict:
        path = (workspace_path or os.getenv("CODE_REVIEW_WORKSPACE") or "").strip()
        if not path or not os.path.isdir(path):
            return {
                "error": (
                    "Local git review needs workspace_path (or CODE_REVIEW_WORKSPACE) "
                    "pointing at a cloned repository"
                )
            }
        if ".." in path:
            return {"error": "Invalid workspace_path"}
        base = base_ref or "origin/main"
        head = head_ref or "HEAD"
        try:
            check = await asyncio.create_subprocess_exec(
                "git",
                "-C",
                path,
                "rev-parse",
                "--is-inside-work-tree",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _out, err = await check.communicate()
            if check.returncode != 0:
                return {"error": f"Not a git repo: {err.decode().strip()}"}

            diff_proc = await asyncio.create_subprocess_exec(
                "git",
                "-C",
                path,
                "diff",
                f"{base}...{head}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            diff_out, diff_err = await diff_proc.communicate()
            if diff_proc.returncode != 0:
                return {"error": f"git diff failed: {diff_err.decode().strip()}"}

            names_proc = await asyncio.create_subprocess_exec(
                "git",
                "-C",
                path,
                "diff",
                "--name-status",
                f"{base}...{head}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            names_out, _ = await names_proc.communicate()
        except Exception as e:
            return {"error": str(e)}

        files = []
        for line in names_out.decode().splitlines()[:MAX_FILES]:
            parts = line.split("\t", 1)
            if len(parts) == 2:
                files.append({"path": parts[1], "status": parts[0]})
        return {
            "repo": path,
            "change_id": f"{base}...{head}",
            "title": f"Local diff {base}...{head}",
            "base": base,
            "head": head,
            "files": files,
            "diff": diff_out.decode(errors="replace"),
        }

    async def _http(self) -> httpx.AsyncClient:
        if self._client:
            return self._client
        return httpx.AsyncClient(timeout=45)


def scan_diff_heuristics(diff: str) -> list[dict]:
    """Fast pattern scan for secrets and high-risk changes in a unified diff."""
    findings = []
    if not diff:
        return findings
    current_file = None
    line_no = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            current_file = raw[6:].strip()
            line_no = 0
            continue
        if raw.startswith("@@"):
            # @@ -a,b +c,d @@
            match = re.search(r"\+(\d+)", raw)
            line_no = int(match.group(1)) - 1 if match else 0
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            line_no += 1
            text = raw[1:]
            for pattern, message in (
                _SECRET_PATTERNS + _MALWARE_PATTERNS + _RISK_PATTERNS
            ):
                if pattern.search(text):
                    lower_msg = message.lower()
                    if any(
                        k in lower_msg
                        for k in (
                            "secret",
                            "key",
                            "backdoor",
                            "malware",
                            "webshell",
                            "reverse",
                            "persistence",
                            "crypto-miner",
                            "obfuscated",
                        )
                    ):
                        severity = "critical"
                    else:
                        severity = "high"
                    findings.append(
                        {
                            "severity": severity,
                            "path": current_file,
                            "line": line_no,
                            "message": message,
                            "snippet": text.strip()[:200],
                        }
                    )
                    break
        elif raw.startswith(" ") or (raw.startswith("-") and not raw.startswith("---")):
            if raw.startswith(" "):
                line_no += 1
    # Deduplicate by path+message+line
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("path"), f.get("line"), f.get("message"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique[:50]


def detect_platform_from_url(url: str) -> str:
    lowered = (url or "").lower()
    if "github.com" in lowered or "github." in lowered:
        return "github"
    if "gitlab." in lowered:
        return "gitlab"
    if "bitbucket.org" in lowered or "bitbucket." in lowered:
        return "bitbucket"
    if "dev.azure.com" in lowered or "visualstudio.com" in lowered:
        return "azure_devops"
    return "git"


def _normalize_platform(platform: str) -> str:
    p = (platform or "").lower().strip()
    aliases = {
        "github_actions": "github",
        "gh": "github",
        "gitlab_ci": "gitlab",
        "gl": "gitlab",
        "bitbucket_cloud": "bitbucket",
        "bb": "bitbucket",
        "azure": "azure_devops",
        "ado": "azure_devops",
        "local": "git",
        "generic": "git",
    }
    return aliases.get(p, p)


def _auto_post_enabled() -> bool:
    if os.getenv("CODE_REVIEW_AUTO_POST", "").lower() in ("true", "1", "yes"):
        return True
    return os.getenv("AUTO_APPLY", "false").lower() in ("true", "1", "yes")


def _format_review_body(summary: str) -> str:
    text = (summary or "").strip()
    footer = (
        "\n\n---\n"
        "_Automated review by the DevOps AI Agent. "
        "Please verify findings before merging._"
    )
    if "DevOps AI Agent" in text:
        return text
    return text + footer
