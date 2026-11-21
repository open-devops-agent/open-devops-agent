"""Multiple AI providers per org: Anthropic, OpenAI, Gemini, Azure OpenAI, Ollama, compatible (#181)."""
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import httpx
import pytest

from agent import llm
from agent.llm import (
    LLMConfigError,
    LLMTransientError,
    OpenAICompatibleProvider,
    TextBlock,
    ToolUseBlock,
    messages_to_openai,
    resolve_config,
    response_from_openai,
    tools_to_openai,
)

_PROVIDER_ENV = (
    "LLM_PROVIDER", "LLM_MODEL", "LLM_API_KEY", "LLM_BASE_URL", "OPENAI_API_KEY",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_VERSION", "CLAUDE_MODEL",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in _PROVIDER_ENV:
        monkeypatch.delenv(name, raising=False)


def fake_http(monkeypatch, responses):
    """Route agent.llm's httpx calls to a scripted handler; return the captured requests."""
    requests = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        status, body = item
        return httpx.Response(status, json=body)

    real_client = httpx.Client

    def client_factory(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(llm.httpx, "Client", client_factory)
    return requests


def chat_response(content=None, tool_calls=None, finish="stop", usage=(11, 7)):
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]},
    }


def tool_call(name, args, call_id="call_1"):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


# ── configuration ──────────────────────────────────────────────────────────

class TestConfig:
    def test_default_is_anthropic_with_claude_model(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
        monkeypatch.setenv("CLAUDE_MODEL", "claude-test")
        cfg = resolve_config()
        assert (cfg.provider, cfg.model, cfg.api_key) == ("anthropic", "claude-test", "sk-ant-x")

    @pytest.mark.parametrize(
        "provider, key_env, url",
        [
            ("openai", "OPENAI_API_KEY", "https://api.openai.com/v1"),
            ("gemini", "GEMINI_API_KEY", "https://generativelanguage.googleapis.com/v1beta/openai"),
            ("gemini", "GOOGLE_API_KEY", "https://generativelanguage.googleapis.com/v1beta/openai"),
        ],
    )
    def test_hosted_providers(self, monkeypatch, provider, key_env, url):
        monkeypatch.setenv("LLM_PROVIDER", provider)
        monkeypatch.setenv("LLM_MODEL", "m-1")
        monkeypatch.setenv(key_env, "k-123")
        cfg = resolve_config()
        assert (cfg.provider, cfg.model, cfg.api_key, cfg.base_url) == (provider, "m-1", "k-123", url)

    def test_ollama_needs_no_key(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "ollama")
        monkeypatch.setenv("LLM_MODEL", "llama3.1")
        cfg = resolve_config()
        assert cfg.api_key == "" and cfg.base_url == "http://localhost:11434/v1"

    def test_azure(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "azure_openai")
        monkeypatch.setenv("LLM_MODEL", "prod-gpt")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://acme.openai.azure.com/")
        cfg = resolve_config()
        assert cfg.base_url == "https://acme.openai.azure.com"
        assert cfg.azure_api_version == "2024-10-21"

    def test_generic_key_and_base_url_override(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setenv("LLM_MODEL", "m")
        monkeypatch.setenv("OPENAI_API_KEY", "specific")
        monkeypatch.setenv("LLM_API_KEY", "generic")
        monkeypatch.setenv("LLM_BASE_URL", "https://proxy.internal/v1/")
        cfg = resolve_config()
        assert cfg.api_key == "generic" and cfg.base_url == "https://proxy.internal/v1"

    @pytest.mark.parametrize(
        "env, message",
        [
            ({"LLM_PROVIDER": "watson"}, "Unknown LLM_PROVIDER"),
            ({"LLM_PROVIDER": "openai", "OPENAI_API_KEY": "k"}, "LLM_MODEL is required"),
            ({"LLM_PROVIDER": "gemini", "LLM_MODEL": "m"}, "GEMINI_API_KEY or GOOGLE_API_KEY"),
            ({"LLM_PROVIDER": "azure_openai", "LLM_MODEL": "d", "AZURE_OPENAI_API_KEY": "k"}, "AZURE_OPENAI_ENDPOINT"),
            ({"LLM_PROVIDER": "openai_compatible", "LLM_MODEL": "m"}, "LLM_BASE_URL is required"),
            ({"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": ""}, "ANTHROPIC_API_KEY"),
        ],
    )
    def test_clear_errors(self, monkeypatch, env, message):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        with pytest.raises(LLMConfigError, match=message):
            resolve_config()


# ── translation ────────────────────────────────────────────────────────────

class TestTranslation:
    def test_tools(self):
        tools = [{"name": "query_logs", "description": "d", "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}]
        assert tools_to_openai(tools) == [
            {"type": "function", "function": {"name": "query_logs", "description": "d",
                                              "parameters": tools[0]["input_schema"]}}
        ]

    def test_history_with_objects_and_checkpoint_dicts(self):
        history = [
            {"role": "user", "content": "Diagnose this"},
            {"role": "assistant", "content": [TextBlock("Checking pods"), ToolUseBlock("c1", "get_k8s_context", {"namespace": "prod"})]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": '{"pods": []}'}]},
            # resumed from a checkpoint: blocks are plain dicts
            {"role": "assistant", "content": [{"type": "tool_use", "id": "c2", "name": "query_logs", "input": {"query": "app-logs"}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "c2", "content": [{"type": "text", "text": "line 1"}]},
                {"type": "text", "text": "extra note"},
            ]},
        ]
        out = messages_to_openai("SYSTEM PROMPT", history)
        assert out[0] == {"role": "system", "content": "SYSTEM PROMPT"}
        assert out[1] == {"role": "user", "content": "Diagnose this"}
        assert out[2]["role"] == "assistant" and out[2]["content"] == "Checking pods"
        assert out[2]["tool_calls"][0] == {
            "id": "c1", "type": "function",
            "function": {"name": "get_k8s_context", "arguments": json.dumps({"namespace": "prod"})},
        }
        assert out[3] == {"role": "tool", "tool_call_id": "c1", "content": '{"pods": []}'}
        assert out[4]["content"] is None and out[4]["tool_calls"][0]["id"] == "c2"
        assert out[5] == {"role": "tool", "tool_call_id": "c2", "content": "line 1"}
        assert out[6] == {"role": "user", "content": "extra note"}

    def test_response_with_tool_calls(self):
        r = response_from_openai(chat_response("Looking", [tool_call("get_k8s_context", {"namespace": "prod"})], finish="tool_calls"))
        assert r.stop_reason == "tool_use"
        assert isinstance(r.content[0], TextBlock) and r.content[0].text == "Looking"
        block = r.content[1]
        assert (block.type, block.id, block.name, block.input) == ("tool_use", "call_1", "get_k8s_context", {"namespace": "prod"})
        assert not hasattr(block, "text")  # the loop extracts final text via hasattr(b, "text")
        assert (r.usage.input_tokens, r.usage.output_tokens) == (11, 7)

    def test_tool_calls_with_stop_finish_reason_and_missing_id(self):
        call = {"type": "function", "function": {"name": "query_logs", "arguments": {"query": "x"}}}
        r = response_from_openai(chat_response(None, [call], finish="stop"))
        assert r.stop_reason == "tool_use"
        assert r.content[0].id.startswith("call_") and r.content[0].input == {"query": "x"}

    @pytest.mark.parametrize("finish, expected", [("stop", "end_turn"), ("length", "max_tokens"), (None, "end_turn")])
    def test_stop_reasons(self, finish, expected):
        assert response_from_openai(chat_response("done", finish=finish)).stop_reason == expected

    def test_malformed_arguments_are_kept_not_crashing(self):
        r = response_from_openai(chat_response(None, [{"id": "c", "function": {"name": "t", "arguments": "{not json"}}]))
        assert r.content[0].input == {"_unparsed_arguments": "{not json"}

    def test_no_choices(self):
        with pytest.raises(RuntimeError, match="no choices"):
            response_from_openai({"choices": []})

    def test_blocks_serialize_for_checkpoints(self):
        assert ToolUseBlock("i", "n", {"a": 1}).model_dump() == {"type": "tool_use", "id": "i", "name": "n", "input": {"a": 1}}
        assert TextBlock("t").model_dump() == {"type": "text", "text": "t"}


# ── HTTP ───────────────────────────────────────────────────────────────────

def provider(monkeypatch, name="openai", **env):
    monkeypatch.setenv("LLM_PROVIDER", name)
    monkeypatch.setenv("LLM_MODEL", env.pop("model", "model-x"))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return OpenAICompatibleProvider(resolve_config())


TOOLS = [{"name": "query_logs", "description": "", "input_schema": {"type": "object", "properties": {}}}]


class TestHttp:
    def test_openai_request(self, monkeypatch):
        requests = fake_http(monkeypatch, [(200, chat_response("hi"))])
        p = provider(monkeypatch, "openai", OPENAI_API_KEY="sk-openai-test")
        p.create(system="S", messages=[{"role": "user", "content": "u"}], tools=TOOLS, max_tokens=50)
        req = requests[0]
        body = json.loads(req.content)
        assert str(req.url) == "https://api.openai.com/v1/chat/completions"
        assert req.headers["authorization"] == "Bearer sk-openai-test"
        assert body["model"] == "model-x" and body["max_tokens"] == 50 and body["tool_choice"] == "auto"
        assert body["tools"][0]["function"]["name"] == "query_logs"
        assert body["messages"][0] == {"role": "system", "content": "S"}

    def test_gemini_request(self, monkeypatch):
        requests = fake_http(monkeypatch, [(200, chat_response("hi"))])
        provider(monkeypatch, "gemini", GEMINI_API_KEY="AIza-test", model="gemini-pro").create(
            system="S", messages=[], tools=TOOLS, max_tokens=10
        )
        assert str(requests[0].url) == "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        assert requests[0].headers["authorization"] == "Bearer AIza-test"

    def test_azure_request(self, monkeypatch):
        requests = fake_http(monkeypatch, [(200, chat_response("hi"))])
        provider(
            monkeypatch, "azure_openai", model="prod-gpt",
            AZURE_OPENAI_API_KEY="az-key", AZURE_OPENAI_ENDPOINT="https://acme.openai.azure.com",
        ).create(system="S", messages=[], tools=TOOLS, max_tokens=10)
        req = requests[0]
        assert str(req.url) == "https://acme.openai.azure.com/openai/deployments/prod-gpt/chat/completions?api-version=2024-10-21"
        assert req.headers["api-key"] == "az-key" and "authorization" not in req.headers
        assert "model" not in json.loads(req.content)

    def test_ollama_sends_no_auth(self, monkeypatch):
        requests = fake_http(monkeypatch, [(200, chat_response("hi"))])
        provider(monkeypatch, "ollama", model="llama3.1").create(system="S", messages=[], tools=TOOLS, max_tokens=10)
        assert str(requests[0].url) == "http://localhost:11434/v1/chat/completions"
        assert "authorization" not in requests[0].headers

    @pytest.mark.parametrize("status", [429, 500, 503])
    def test_transient_statuses(self, monkeypatch, status):
        fake_http(monkeypatch, [(status, {"error": "busy"})])
        with pytest.raises(LLMTransientError):
            provider(monkeypatch, OPENAI_API_KEY="k").create(system="", messages=[], tools=TOOLS, max_tokens=1)

    def test_network_error_is_transient(self, monkeypatch):
        fake_http(monkeypatch, [httpx.ConnectError("refused")])
        with pytest.raises(LLMTransientError):
            provider(monkeypatch, OPENAI_API_KEY="k").create(system="", messages=[], tools=TOOLS, max_tokens=1)

    def test_client_error_never_contains_key(self, monkeypatch):
        fake_http(monkeypatch, [(401, {"error": {"message": "Incorrect API key provided"}})])
        with pytest.raises(RuntimeError) as excinfo:
            provider(monkeypatch, OPENAI_API_KEY="sk-supersecret-value").create(system="", messages=[], tools=TOOLS, max_tokens=1)
        assert "401" in str(excinfo.value) and "sk-supersecret-value" not in str(excinfo.value)


# ── agent integration ──────────────────────────────────────────────────────

def _agent():
    from agent.core import DevOpsAgent
    from services.incident_store import IncidentStore
    from services.org_docs import OrgDocs
    from storage.memory_storage import MemoryStorage

    agent = DevOpsAgent()
    agent.k8s_collector.collect = AsyncMock(return_value={"pods": [{"name": "api", "status": "CrashLoopBackOff"}]})
    agent.notifier.send_message = AsyncMock()
    agent.notifier.send_fix_suggestion = AsyncMock()
    agent.incident_store = IncidentStore(MemoryStorage())
    agent.org_docs = OrgDocs(MemoryStorage())
    return agent


SUGGEST_ARGS = {"title": "Fix env var", "description": "Evidence shows a missing env var", "commands": ["kubectl set env deploy/api X=1"]}


class TestAgentWithGemini:
    @pytest.mark.asyncio
    async def test_full_incident_runs_on_gemini(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "gemini")
        monkeypatch.setenv("LLM_MODEL", "gemini-test")
        monkeypatch.setenv("GEMINI_API_KEY", "AIza-gemini-test")
        requests = fake_http(monkeypatch, [
            (200, chat_response(None, [tool_call("get_k8s_context", {"namespace": "prod"}, "g1")], finish="tool_calls")),
            (200, chat_response(None, [tool_call("suggest_fix", SUGGEST_ARGS, "g2")], finish="tool_calls")),
            (200, chat_response("Evidence: get_k8s_context shows CrashLoopBackOff from a missing env var.", usage=(300, 40))),
        ])
        agent = _agent()
        result = await agent.run({"type": "k8s", "namespace": "prod", "org_id": "acme"}, incident_id="INC-G-1", resume=False)

        assert [a["tool"] for a in result["actions"]] == ["get_k8s_context", "suggest_fix"]
        assert "CrashLoopBackOff" in result["diagnosis"]
        agent.k8s_collector.collect.assert_awaited()
        # the tool result went back to Gemini as an OpenAI `tool` message tied to the call id
        second = json.loads(requests[1].content)
        tool_msgs = [m for m in second["messages"] if m["role"] == "tool"]
        assert tool_msgs[0]["tool_call_id"] == "g1" and "CrashLoopBackOff" in tool_msgs[0]["content"]
        assert second["model"] == "gemini-test"
        assert all(str(r.url).startswith("https://generativelanguage.googleapis.com/") for r in requests)

    @pytest.mark.asyncio
    async def test_transient_error_is_retried(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setenv("LLM_MODEL", "m")
        monkeypatch.setenv("OPENAI_API_KEY", "k")
        fake_http(monkeypatch, [
            (503, {"error": "overloaded"}),
            (200, chat_response(None, [tool_call("get_k8s_context", {})], finish="tool_calls")),
            (200, chat_response(None, [tool_call("suggest_fix", SUGGEST_ARGS, "c2")], finish="tool_calls")),
            (200, chat_response("Evidence: checked pods.")),
        ])
        agent = _agent()
        agent.claude_retry_delay = 0
        result = await agent.run({"type": "k8s", "namespace": "prod", "org_id": "acme"}, incident_id="INC-R", resume=False)
        assert result["actions"][0]["tool"] == "get_k8s_context"

    @pytest.mark.asyncio
    async def test_token_usage_metric_uses_provider_model(self, monkeypatch):
        from services import metrics

        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setenv("LLM_MODEL", "metric-model")
        monkeypatch.setenv("OPENAI_API_KEY", "k")
        fake_http(monkeypatch, [(200, chat_response("Evidence: nothing to do.", usage=(123, 4)))])
        labels = {"model": "metric-model", "kind": "input"}
        before = metrics.REGISTRY.get_sample_value("devops_agent_llm_tokens_total", labels) or 0
        agent = _agent()
        await agent.run({"type": "unknown_type", "org_id": "acme"}, incident_id="INC-M", resume=False)
        assert metrics.REGISTRY.get_sample_value("devops_agent_llm_tokens_total", labels) == before + 123


class TestPerOrgProvider:
    @pytest.mark.asyncio
    async def test_each_org_uses_its_own_provider(self, monkeypatch):
        from services.org_config import OrgConfig
        from storage.memory_storage import MemoryStorage

        config = OrgConfig(storage=MemoryStorage())
        config.save("gemini-org", {"LLM_PROVIDER": "gemini", "LLM_MODEL": "gemini-x", "GEMINI_API_KEY": "AIza-org"})
        monkeypatch.setattr("services.org_context.OrgConfig", lambda: config)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-default")

        requests = fake_http(monkeypatch, [(200, chat_response("Evidence: fine."))])
        agent = _agent()
        await agent.run({"type": "unknown_type", "org_id": "gemini-org"}, incident_id="INC-O1", resume=False)
        assert str(requests[0].url).startswith("https://generativelanguage.googleapis.com/")
        assert requests[0].headers["authorization"] == "Bearer AIza-org"

        # the default org still uses Anthropic: the provider cache is reset per org
        with patch("anthropic.Anthropic") as mock_anthropic:
            end = MagicMock(stop_reason="end_turn")
            end.content = [MagicMock(type="text", text="Evidence: fine.")]
            mock_anthropic.return_value.messages.create.return_value = end
            await agent.run({"type": "unknown_type", "org_id": "default"}, incident_id="INC-O2", resume=False)
            mock_anthropic.assert_called_with(api_key="sk-ant-default")
        assert len(requests) == 1

    def test_provider_keys_are_storable_org_credentials(self):
        from services.org_config import ORG_CREDENTIAL_KEYS

        for key in ("LLM_PROVIDER", "LLM_MODEL", "OPENAI_API_KEY", "GEMINI_API_KEY", "AZURE_OPENAI_API_KEY", "LLM_BASE_URL"):
            assert key in ORG_CREDENTIAL_KEYS


def test_google_and_azure_keys_are_scrubbed():
    from services.pii_scrubber import scrub_text

    google_key = "AIza" + "S" * 35
    assert google_key not in scrub_text(f"key={google_key} used")
    assert "az-secret-value" not in scrub_text("api-key: az-secret-value")
