"""Nginx/certbot repair+renew, GitHub rerun, Azure/Jenkins PRs, Bamboo version check."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.cicd_tools import CICDTools, bump_patch_version
from tools.github_tools import GitHubTools
from tools.nginx_tools import NginxTools
from tools.security_updates import SecurityUpdates


class TestNginxTools:
    @pytest.mark.asyncio
    async def test_refuses_restart_when_config_is_invalid(self):
        async def runner(command, host):
            if command == "nginx -t":
                return {
                    "success": False,
                    "stderr": 'nginx: [emerg] unexpected "}" in /etc/nginx/sites-enabled/app:12',
                }
            if command.startswith("cat "):
                return {"success": True, "stdout": "server {"}
            return {"success": True, "stdout": "inactive"}

        result = await NginxTools(runner=runner).restart()
        assert result["success"] is False
        assert result["blocked"] is True
        assert "apply_nginx_config" in result["message"]
        assert result["diagnosis"]["broken_file"] == "/etc/nginx/sites-enabled/app"

    @pytest.mark.asyncio
    async def test_apply_config_then_restart(self):
        seen = []

        async def runner(command, host):
            seen.append(command)
            if command == "nginx -t":
                return {"success": True, "stdout": "syntax is ok"}
            if command.startswith("systemctl is-active"):
                return {"success": True, "stdout": "active"}
            if "certbot" in command:
                return {"success": True, "stdout": "Found the following certs"}
            return {"success": True, "stdout": ""}

        result = await NginxTools(runner=runner).restart(
            config_path="/etc/nginx/sites-enabled/app",
            config_content="server { listen 80; }\n",
            reload_only=True,
        )
        assert result["success"] is True
        assert any("write_bytes" in c for c in seen)
        assert any(c == "systemctl reload nginx" for c in seen)

    @pytest.mark.asyncio
    async def test_apply_restores_backup_when_test_fails(self):
        seen = []

        async def runner(command, host):
            seen.append(command)
            if command == "nginx -t":
                return {"success": False, "stderr": "nginx: [emerg] unexpected end of file"}
            return {"success": True, "stdout": ""}

        result = await NginxTools(runner=runner).apply_nginx_config(
            "/etc/nginx/nginx.conf", "broken {"
        )
        assert result["success"] is False
        assert result["restored"] is True
        assert any("mv /etc/nginx/nginx.conf.agent-bak" in c for c in seen)

    @pytest.mark.asyncio
    async def test_rejects_config_outside_etc_nginx(self):
        result = await NginxTools(runner=AsyncMock()).apply_nginx_config(
            "/opt/evil.conf", "x"
        )
        assert result["blocked"] is True

    @pytest.mark.asyncio
    async def test_wildcard_renew_uses_dns_plugin(self, monkeypatch):
        monkeypatch.setenv("CERTBOT_DNS_PLUGIN", "cloudflare")
        monkeypatch.setenv("CERTBOT_DNS_CREDENTIALS", "/etc/letsencrypt/cf.ini")
        seen = []

        async def runner(command, host):
            seen.append(command)
            if "certbot certificates" in command:
                return {
                    "success": True,
                    "stdout": "Certificate Name: example.com\n  Domains: *.example.com",
                }
            return {"success": True, "stdout": "The dry run was successful"}

        result = await NginxTools(runner=runner).renew_certificates(
            dry_run=True, domains=["*.example.com", "example.com"]
        )
        assert result["success"] is True
        assert any("--dns-cloudflare" in c and "-d *.example.com" in c for c in seen)

    @pytest.mark.asyncio
    async def test_wildcard_without_plugin_or_domains_still_tries_renew(self, monkeypatch):
        monkeypatch.delenv("CERTBOT_DNS_PLUGIN", raising=False)
        monkeypatch.delenv("CERTBOT_WILDCARD_DOMAINS", raising=False)
        seen = []

        async def runner(command, host):
            seen.append(command)
            if "certbot certificates" in command:
                return {
                    "success": True,
                    "stdout": "Wildcard certificate *.example.com",
                }
            return {"success": True, "stdout": "The dry run was successful"}

        result = await NginxTools(runner=runner).renew_certificates(dry_run=True)
        assert result["success"] is True
        assert any(c.startswith("certbot renew") for c in seen)


class TestSecurityUpdates:
    @pytest.mark.asyncio
    async def test_dry_run_uses_simulation(self):
        seen = []

        async def runner(command, host):
            seen.append(command)
            return {"success": True, "stdout": "No packages to upgrade"}

        result = await SecurityUpdates(runner=runner).apply(dry_run=True)
        assert result["dry_run"] is True
        assert "dry-run" in seen[0] or "-s" in seen[0]


class TestBambooVersion:
    def test_bump_patch_version(self):
        assert bump_patch_version("1.2.3") == "1.2.4"
        assert bump_patch_version("14") == "15"
        assert bump_patch_version("2.0.9-rc") == "2.0.10-rc"
        assert bump_patch_version("not-a-version") is None
        assert bump_patch_version("") is None

    @pytest.mark.asyncio
    async def test_increment_and_queue(self, monkeypatch):
        monkeypatch.setenv("BAMBOO_URL", "https://bamboo.example")
        monkeypatch.setenv("BAMBOO_USERNAME", "u")
        monkeypatch.setenv("BAMBOO_PASSWORD", "p")

        get_resp = MagicMock(status_code=200)
        get_resp.json.return_value = {"name": "version", "value": "1.4.0"}
        put_resp = MagicMock(status_code=204)
        post_resp = MagicMock(status_code=200)

        client = MagicMock()
        client.get = AsyncMock(return_value=get_resp)
        client.put = AsyncMock(return_value=put_resp)
        client.post = AsyncMock(return_value=post_resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("tools.cicd_tools.httpx.AsyncClient", return_value=client):
            result = await CICDTools().increment_bamboo_version("PROJ-PLAN")

        assert result["success"] is True
        assert result["previous_version"] == "1.4.0"
        assert result["new_version"] == "1.4.1"
        get_url = client.get.await_args.args[0]
        assert get_url.endswith("/rest/api/latest/plan/PROJ-PLAN/variables/version")
        put_url = client.put.await_args.args[0]
        assert put_url.endswith("/rest/api/latest/plan/PROJ-PLAN/variables/version")
        assert client.put.await_args.kwargs["json"] == {"name": "version", "value": "1.4.1"}
        client.post.assert_awaited()
        queued_url = client.post.await_args.args[0]
        assert queued_url.endswith("/rest/api/latest/queue/PROJ-PLAN")
        queued_params = client.post.await_args.kwargs.get("params") or {}
        assert queued_params.get("bamboo.variable.version") == "1.4.1"

    @pytest.mark.asyncio
    async def test_version_check_falls_back_to_variable_context(self, monkeypatch):
        monkeypatch.setenv("BAMBOO_URL", "https://bamboo.example")
        monkeypatch.setenv("BAMBOO_USERNAME", "u")
        monkeypatch.setenv("BAMBOO_PASSWORD", "p")

        missing = MagicMock(status_code=404)
        context = MagicMock(status_code=200)
        context.json.return_value = {
            "variableContext": {"variable": [{"key": "version", "value": "2.0.0"}]}
        }
        put_resp = MagicMock(status_code=204)

        client = MagicMock()
        client.get = AsyncMock(side_effect=[missing, context])
        client.put = AsyncMock(return_value=put_resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("tools.cicd_tools.httpx.AsyncClient", return_value=client):
            result = await CICDTools().increment_bamboo_version(
                "PROJ-PLAN", queue_build=False
            )

        assert result["success"] is True
        assert result["previous_version"] == "2.0.0"
        assert result["new_version"] == "2.0.1"
        fallback_url = client.get.await_args_list[1].args[0]
        fallback_params = client.get.await_args_list[1].kwargs.get("params") or {}
        assert fallback_url.endswith("/rest/api/latest/plan/PROJ-PLAN")
        assert fallback_params.get("expand") == "variableContext"

    @pytest.mark.asyncio
    async def test_check_version_reads_plan_and_latest_result(self, monkeypatch):
        monkeypatch.setenv("BAMBOO_URL", "https://bamboo.example")
        monkeypatch.setenv("BAMBOO_USERNAME", "u")
        monkeypatch.setenv("BAMBOO_PASSWORD", "p")

        var = MagicMock(status_code=200)
        var.json.return_value = {"name": "version", "value": "1.4.0"}
        latest = MagicMock(status_code=200)
        latest.json.return_value = {
            "buildNumber": 88,
            "state": "Successful",
            "key": "PROJ-PLAN-88",
        }

        client = MagicMock()
        client.get = AsyncMock(side_effect=[var, latest])
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("tools.cicd_tools.httpx.AsyncClient", return_value=client):
            result = await CICDTools().check_bamboo_version(
                "PROJ-PLAN", expected_version="1.4.0"
            )

        assert result["plan_version"] == "1.4.0"
        assert result["latest_build_number"] == 88
        assert result["matches_expected"] is True
        latest_url = client.get.await_args_list[1].args[0]
        assert latest_url.endswith("/rest/api/latest/result/PROJ-PLAN-latest")


def _http_client(post_resp=None):
    client = MagicMock()
    resp = post_resp or MagicMock(status_code=201)
    client.post = AsyncMock(return_value=resp)
    client.get = AsyncMock()
    client.put = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


class TestGitHubRerun:
    @pytest.mark.asyncio
    async def test_rerun_failed_jobs(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        client = _http_client()
        with patch("tools.github_tools.httpx.AsyncClient", return_value=client):
            result = await GitHubTools().rerun_workflow("acme/app", 99)

        assert result["success"] is True
        url = client.post.await_args.args[0]
        assert url.endswith("/repos/acme/app/actions/runs/99/rerun-failed-jobs")

    @pytest.mark.asyncio
    async def test_retry_pipeline_github(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        client = _http_client()
        with patch("tools.github_tools.httpx.AsyncClient", return_value=client):
            result = await CICDTools().retry_pipeline("github", "acme/app", "42")
        assert result["success"] is True
        assert result["run_id"] == 42


class TestAzureAndScmPr:
    @pytest.mark.asyncio
    async def test_azure_pr_push_and_create(self, monkeypatch):
        monkeypatch.setenv("AZURE_DEVOPS_ORG", "org")
        monkeypatch.setenv("AZURE_DEVOPS_PAT", "pat")

        repo = MagicMock(status_code=200)
        repo.json.return_value = {"defaultBranch": "refs/heads/main"}
        refs = MagicMock(status_code=200)
        refs.json.return_value = {"value": [{"objectId": "abc123"}]}
        missing_file = MagicMock(status_code=404)
        push = MagicMock(status_code=201)
        pr = MagicMock(status_code=201)
        pr.json.return_value = {"pullRequestId": 7, "url": "https://dev.azure.com/pr/7"}

        client = MagicMock()
        client.get = AsyncMock(side_effect=[repo, refs, missing_file])
        client.post = AsyncMock(side_effect=[push, pr])
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("tools.cicd_tools.httpx.AsyncClient", return_value=client):
            result = await CICDTools().create_fix_pr(
                "azure_devops",
                "app",
                "azure-pipelines.yml",
                "trigger: none\n",
                "fix pipeline",
                "timeout",
                project="proj",
            )

        assert result["success"] is True
        assert result["pr_id"] == 7
        push_body = client.post.await_args_list[0].kwargs["json"]
        assert push_body["commits"][0]["changes"][0]["changeType"] == "add"
        assert push_body["commits"][0]["changes"][0]["item"]["path"] == "/azure-pipelines.yml"

    @pytest.mark.asyncio
    async def test_jenkins_pr_uses_github_scm(self, monkeypatch):
        monkeypatch.setenv("JENKINS_SCM_PROVIDER", "github")
        monkeypatch.setenv("JENKINS_SCM_REPO", "acme/app")
        mocked = AsyncMock(return_value={"success": True, "pr_url": "https://github.com/acme/app/pull/1"})
        with patch.object(GitHubTools, "create_fix_pr", new=mocked):
            result = await CICDTools().create_fix_pr(
                "jenkins",
                "ignored-job",
                "Jenkinsfile",
                "pipeline {}\n",
                "fix",
                "body",
            )
        assert result["success"] is True
        mocked.assert_awaited()
        assert mocked.await_args.args[0] == "acme/app"
        assert mocked.await_args.args[1] == "Jenkinsfile"

    @pytest.mark.asyncio
    async def test_bamboo_specs_pr_on_bitbucket(self, monkeypatch):
        monkeypatch.setenv("BITBUCKET_USERNAME", "bot")
        monkeypatch.setenv("BITBUCKET_APP_PASSWORD", "secret")
        monkeypatch.setenv("BAMBOO_SCM_PROVIDER", "bitbucket")
        monkeypatch.setenv("BAMBOO_SPECS_REPO", "ws/specs")

        repo = MagicMock(status_code=200)
        repo.json.return_value = {"mainbranch": {"name": "main"}}
        tip = MagicMock(status_code=200)
        tip.json.return_value = {"target": {"hash": "abc123"}}
        branch = MagicMock(status_code=201)
        commit = MagicMock(status_code=201)
        pr = MagicMock(status_code=201)
        pr.json.return_value = {
            "id": 99,
            "links": {"html": {"href": "https://bitbucket.org/ws/specs/pull-requests/99"}},
        }

        client = MagicMock()
        client.get = AsyncMock(side_effect=[repo, tip])
        client.post = AsyncMock(side_effect=[branch, commit, pr])
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("tools.cicd_tools.httpx.AsyncClient", return_value=client):
            result = await CICDTools().create_fix_pr(
                "bamboo",
                "APP-PLAN",
                "bamboo-specs/build.yaml",
                "plan: fixed\n",
                "fix bamboo specs",
                "image tag wrong",
            )

        assert result["success"] is True
        assert result["pr_id"] == 99
        # branch create, commit src, pull request
        assert client.post.await_count == 3
        pr_body = client.post.await_args_list[2].kwargs["json"]
        assert pr_body["source"]["branch"]["name"].startswith("devops-ai-fix/")
        assert pr_body["destination"]["branch"]["name"] == "main"
