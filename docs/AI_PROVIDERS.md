# AI providers

The agent runs on **Anthropic Claude by default**, and also works with **OpenAI, Google Gemini, Azure
OpenAI, local models through Ollama, and any OpenAI-compatible endpoint** (vLLM, OpenRouter, Groq,
LM Studio, …). Each organization chooses its own provider, model and key, so one server can run org A
on Claude and org B on Gemini.

The agent loop, tools, safety rules, approval gates, threat detection and prompt-injection protection
are identical whichever model you use. Only the API call changes.

## Configure a provider

Set these in `.env` for the whole server, or per org (see [Per-organization](#per-organization)):

| Provider | `LLM_PROVIDER` | Key | `LLM_MODEL` | Notes |
|---|---|---|---|---|
| Anthropic Claude | `anthropic` (default) | `ANTHROPIC_API_KEY` | optional (`CLAUDE_MODEL` still works) | unchanged default |
| OpenAI | `openai` | `OPENAI_API_KEY` | required, e.g. your chosen GPT model | `https://api.openai.com/v1` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) | required, e.g. a Gemini Pro model | Google's OpenAI-compatible endpoint |
| Azure OpenAI | `azure_openai` | `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_ENDPOINT` | required: your **deployment name** | `AZURE_OPENAI_API_VERSION` defaults to `2024-10-21` |
| Ollama (local) | `ollama` | none | required, e.g. `llama3.1` | `http://localhost:11434/v1`; pick a model with tool calling |
| Any OpenAI-compatible | `openai_compatible` | `LLM_API_KEY` (if needed) | required | set `LLM_BASE_URL` |

Example: Google Gemini.

```bash
LLM_PROVIDER=gemini
LLM_MODEL=<gemini model name from Google AI Studio>
GEMINI_API_KEY=AIza...
```

Other settings:

- `LLM_API_KEY` overrides the provider-specific key.
- `LLM_BASE_URL` overrides the endpoint, for a proxy or a self-hosted gateway.
- `LLM_TIMEOUT_SEC` (default 120) is the request timeout for non-Anthropic providers.
- `CLAUDE_API_RETRIES` and `CLAUDE_RETRY_DELAY_SEC` set the retries with backoff on 429, 5xx and network errors, for every provider.

**Model choice matters.** The agent drives investigations through tool calls, so use a model with
reliable function/tool calling. Small local models often call tools poorly; try a capable one before
judging the agent.

## Per-organization

Every setting above is an org credential, so each tenant brings its own:

```bash
curl -X PUT http://localhost:8000/orgs/globex/config \
  -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"credentials": {"LLM_PROVIDER": "gemini", "LLM_MODEL": "<model>", "GEMINI_API_KEY": "AIza..."}}'
```

For MCP clients, put the same variables in the server's `env` block. Orgs without their own settings
use the server's defaults.

## How it works

The agent keeps its conversation in one internal format. For non-Anthropic providers,
`agent/llm.py` translates:

- tool definitions into OpenAI `tools` / `function` schemas
- the agent's tool calls into `tool_calls`, and tool results into `role: "tool"` messages
- responses back into tool-call and text blocks, with finish reasons mapped (`tool_calls` → keep
  going, `length` → max tokens) and token usage reported to `devops_agent_llm_tokens_total`

Gemini, Azure OpenAI and Ollama all accept this OpenAI Chat Completions format, so no extra SDK is
installed. Keys are sent only as request headers and are never included in errors or logs. Google
`AIza…` keys and `api-key:` headers are also scrubbed from incident data.

## Troubleshooting

| Error | Fix |
|---|---|
| `LLM_MODEL is required for LLM_PROVIDER=…` | Set the model (for Azure, the deployment name). |
| `No API key for LLM_PROVIDER=…` | Set the provider's key for that org (or `LLM_API_KEY`). |
| `… returned HTTP 401/403` | Wrong key, or the key lacks access to that model. |
| `… returned HTTP 400` mentioning tools | The model doesn't support tool calling; choose one that does. |
| The agent stops after one step | The model answered without calling tools. Use a stronger tool-calling model. |
