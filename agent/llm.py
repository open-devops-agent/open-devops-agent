"""
AI model providers for the agent loop (#181).

The agent loop speaks one format internally (Anthropic Messages: assistant
``tool_use`` blocks, user ``tool_result`` blocks, ``stop_reason``). Providers
translate to and from their own APIs, so the loop, tools and safety rules are
identical whichever model an organization uses.

Configuration (per org via PUT /orgs/{org}/config, or globally in the env):

    LLM_PROVIDER   anthropic (default) | openai | gemini | azure_openai | ollama | openai_compatible
    LLM_MODEL      model / deployment name (Anthropic falls back to CLAUDE_MODEL)
    LLM_API_KEY    overrides the provider-specific key below
    LLM_BASE_URL   overrides the provider's default endpoint

Provider keys: ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY (or
GOOGLE_API_KEY), AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT
(+ AZURE_OPENAI_API_VERSION). Ollama needs no key.

Non-Anthropic providers use the OpenAI Chat Completions wire format over
httpx (Gemini and Ollama both serve it), so no extra SDK is required.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-20250514"

PROVIDERS = ("anthropic", "openai", "gemini", "azure_openai", "ollama", "openai_compatible")

_DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "ollama": "http://localhost:11434/v1",
}

_KEY_ENV = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "azure_openai": ("AZURE_OPENAI_API_KEY",),
    "ollama": (),
    "openai_compatible": (),
}


class LLMConfigError(RuntimeError):
    """The provider is not configured correctly for this org."""


class LLMTransientError(RuntimeError):
    """Rate limit, server error or timeout; safe to retry."""


# ── Provider-neutral response (Anthropic-shaped, as the loop expects) ────────


@dataclass
class TextBlock:
    text: str
    type: str = "text"

    def model_dump(self) -> dict:
        return {"type": "text", "text": self.text}


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict
    type: str = "tool_use"

    def model_dump(self) -> dict:
        return {"type": "tool_use", "id": self.id, "name": self.name, "input": self.input}


@dataclass
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class LLMResponse:
    stop_reason: str
    content: List[Any] = field(default_factory=list)
    usage: Optional[LLMUsage] = None


# ── Configuration ───────────────────────────────────────────────────────────


@dataclass
class ProviderConfig:
    provider: str
    model: str
    api_key: str
    base_url: str = ""
    azure_api_version: str = ""


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def resolve_config(default_claude_model: Optional[str] = None) -> ProviderConfig:
    """Read the provider settings from the environment (org overlay applied)."""
    provider = (_env("LLM_PROVIDER") or "anthropic").lower()
    if provider not in PROVIDERS:
        raise LLMConfigError(
            f"Unknown LLM_PROVIDER {provider!r}. Use one of: {', '.join(PROVIDERS)}."
        )

    model = _env("LLM_MODEL")
    if provider == "anthropic":
        model = model or _env("CLAUDE_MODEL") or default_claude_model or DEFAULT_CLAUDE_MODEL
    elif not model:
        raise LLMConfigError(
            f"LLM_MODEL is required for LLM_PROVIDER={provider} "
            "(for Azure OpenAI, the deployment name)."
        )

    api_key = _env("LLM_API_KEY") or next((_env(n) for n in _KEY_ENV[provider] if _env(n)), "")
    if not api_key and provider not in ("ollama", "openai_compatible"):
        names = " or ".join(_KEY_ENV[provider] + ("LLM_API_KEY",))
        raise LLMConfigError(
            f"No API key for LLM_PROVIDER={provider}. Set {names} for this org "
            "(MCP env, PUT /orgs/{org}/config, or configure_org_credentials)."
        )

    base_url = _env("LLM_BASE_URL")
    azure_api_version = ""
    if provider == "azure_openai":
        base_url = base_url or _env("AZURE_OPENAI_ENDPOINT")
        if not base_url:
            raise LLMConfigError("AZURE_OPENAI_ENDPOINT is required for LLM_PROVIDER=azure_openai.")
        azure_api_version = _env("AZURE_OPENAI_API_VERSION") or "2024-10-21"
    elif provider == "openai_compatible":
        if not base_url:
            raise LLMConfigError("LLM_BASE_URL is required for LLM_PROVIDER=openai_compatible.")
    elif provider != "anthropic":
        base_url = base_url or _DEFAULT_BASE_URLS[provider]

    return ProviderConfig(provider, model, api_key, base_url.rstrip("/"), azure_api_version)


# ── Anthropic ───────────────────────────────────────────────────────────────


class AnthropicProvider:
    def __init__(self, config: ProviderConfig):
        import anthropic  # resolved at call time so tests can patch anthropic.Anthropic

        self.config = config
        self.model = config.model
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=config.api_key)

    def create(self, *, system: str, messages: list, tools: list, max_tokens: int):
        anthropic = self._anthropic
        try:
            return self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                tools=tools,
                messages=messages,
            )
        except (
            anthropic.APIConnectionError,
            anthropic.RateLimitError,
            anthropic.InternalServerError,
            anthropic.APITimeoutError,
        ) as exc:
            raise LLMTransientError(str(exc)) from exc


# ── OpenAI Chat Completions (OpenAI, Gemini, Azure OpenAI, Ollama, compatible) ─


def _get(block: Any, key: str, default: Any = None) -> Any:
    if isinstance(block, dict):
        return block.get(key, default)
    return getattr(block, key, default)


def tools_to_openai(tools: List[dict]) -> List[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
            },
        }
        for tool in tools
    ]


def _tool_result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(_get(part, "text", part)) for part in content)
    return json.dumps(content, default=str)


def messages_to_openai(system: str, messages: List[dict]) -> List[dict]:
    """Translate the loop's Anthropic-format history into Chat Completions messages."""
    out: List[dict] = [{"role": "system", "content": system}] if system else []
    for message in messages:
        role = message.get("role")
        content = message.get("content")
        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue

        blocks = list(content or [])
        if role == "assistant":
            texts = [_get(b, "text") for b in blocks if _get(b, "type") == "text" and _get(b, "text")]
            calls = [
                {
                    "id": _get(b, "id"),
                    "type": "function",
                    "function": {
                        "name": _get(b, "name"),
                        "arguments": json.dumps(_get(b, "input") or {}),
                    },
                }
                for b in blocks
                if _get(b, "type") == "tool_use"
            ]
            entry: Dict[str, Any] = {"role": "assistant", "content": "\n".join(texts) or None}
            if calls:
                entry["tool_calls"] = calls
            out.append(entry)
            continue

        # user turn: tool results become `tool` messages, any text stays a user message
        texts = []
        for block in blocks:
            if _get(block, "type") == "tool_result":
                out.append(
                    {
                        "role": "tool",
                        "tool_call_id": _get(block, "tool_use_id"),
                        "content": _tool_result_text(_get(block, "content", "")),
                    }
                )
            elif _get(block, "type") == "text":
                texts.append(_get(block, "text", ""))
        if texts:
            out.append({"role": "user", "content": "\n".join(texts)})
    return out


def _parse_arguments(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {"_unparsed_arguments": str(raw)[:2000]}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def response_from_openai(data: dict) -> LLMResponse:
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"Model returned no choices: {str(data)[:300]}")
    choice = choices[0]
    message = choice.get("message") or {}

    content: List[Any] = []
    if message.get("content"):
        content.append(TextBlock(text=str(message["content"])))
    for call in message.get("tool_calls") or []:
        function = call.get("function") or {}
        content.append(
            ToolUseBlock(
                id=call.get("id") or f"call_{uuid.uuid4().hex[:12]}",
                name=function.get("name") or "",
                input=_parse_arguments(function.get("arguments")),
            )
        )

    finish = choice.get("finish_reason")
    # Some compatible servers report "stop" even when they return tool calls.
    if any(isinstance(b, ToolUseBlock) for b in content):
        stop_reason = "tool_use"
    elif finish == "length":
        stop_reason = "max_tokens"
    else:
        stop_reason = "end_turn"

    usage = data.get("usage") or {}
    return LLMResponse(
        stop_reason=stop_reason,
        content=content,
        usage=LLMUsage(
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
        ),
    )


class OpenAICompatibleProvider:
    def __init__(self, config: ProviderConfig):
        self.config = config
        self.model = config.model
        self.timeout = float(_env("LLM_TIMEOUT_SEC") or 120)

    def _endpoint(self) -> tuple[str, dict]:
        cfg = self.config
        if cfg.provider == "azure_openai":
            url = (
                f"{cfg.base_url}/openai/deployments/{cfg.model}/chat/completions"
                f"?api-version={cfg.azure_api_version}"
            )
            return url, {"api-key": cfg.api_key}
        headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
        return f"{cfg.base_url}/chat/completions", headers

    def create(self, *, system: str, messages: list, tools: list, max_tokens: int) -> LLMResponse:
        url, headers = self._endpoint()
        payload: Dict[str, Any] = {
            "messages": messages_to_openai(system, messages),
            "tools": tools_to_openai(tools),
            "tool_choice": "auto",
            "max_tokens": max_tokens,
        }
        if self.config.provider != "azure_openai":
            payload["model"] = self.model
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload, headers={**headers, "Content-Type": "application/json"})
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise LLMTransientError(f"{self.config.provider} request failed: {exc}") from exc

        if resp.status_code == 429 or resp.status_code >= 500:
            raise LLMTransientError(f"{self.config.provider} returned HTTP {resp.status_code}")
        if resp.status_code >= 400:
            # Body may echo request details; never the API key (sent only as a header).
            raise RuntimeError(
                f"{self.config.provider} returned HTTP {resp.status_code}: {resp.text[:500]}"
            )
        return response_from_openai(resp.json())


def build_provider(default_claude_model: Optional[str] = None):
    config = resolve_config(default_claude_model)
    if config.provider == "anthropic":
        return AnthropicProvider(config)
    return OpenAICompatibleProvider(config)
