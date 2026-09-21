import asyncio

import httpx
import pytest

from collectors.github import GitHubCollector


@pytest.mark.parametrize(
    ("base_url", "expected_base"),
    [
        (None, "https://api.github.com"),
        ("https://github.example/api/v3/", "https://github.example/api/v3"),
    ],
)
def test_collect_uses_configured_api_base_without_credential_refresh(
    monkeypatch, base_url, expected_base
):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    requested_urls = []

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"jobs": []}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url, **kwargs):
            requested_urls.append(url)
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    collector = GitHubCollector(base_url=base_url)
    collector.refresh_credentials()

    result = asyncio.run(collector.collect("owner/repo", 42))

    assert result["run_id"] == 42
    assert requested_urls == [
        f"{expected_base}/repos/owner/repo/actions/runs/42",
        f"{expected_base}/repos/owner/repo/actions/runs/42/jobs",
    ]
