"""
PII and secrets scrubber — applied before Claude, Slack, audit, and cloud storage.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Union

# Ordered patterns: (compiled_regex, replacement_label)
_PATTERNS: List[tuple] = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:sk-ant-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|glpat-|xox[baprs]-)[A-Za-z0-9_-]{10,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"\b(?:aws_secret_access_key|secret_key|api_key|apikey|password|passwd|pwd)\s*[:=]\s*['\"]?(?!\[REDACTED)[^\s'\"]{4,}", re.I), "[REDACTED_CREDENTIAL]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"\b(?:Bearer\s+)[A-Za-z0-9._-]{20,}\b", re.I), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "[REDACTED_CARD]"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED_PHONE]"),
    (re.compile(r"(?i)(?:authorization|x-api-key|api-key|cookie)\s*:\s*[^\s,;]+"), "[REDACTED_HEADER]"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


# Secret material in tool output (#191): Kubernetes Secret data, and env vars whose
# names say they hold a secret (docker inspect, kubectl get pod -o yaml, printenv).
_SECRET_NAME = r"[A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[A-Za-z0-9_]*"
_SECRET_ENV_ASSIGN = re.compile(rf"\b({_SECRET_NAME})=([^\s\"',\]]+)")
_SECRET_ENV_YAML = re.compile(
    rf"(name:\s*['\"]?{_SECRET_NAME}['\"]?[ \t]*\r?\n[ \t]*value:[ \t]*)(?!\[REDACTED)([^\r\n]+)", re.I
)
_SECRET_ENV_JSON = re.compile(
    rf"(\"name\"\s*:\s*\"{_SECRET_NAME}\"\s*,\s*\"value\"\s*:\s*\")([^\"]*)", re.I
)
_YAML_KIND_SECRET = re.compile(r"^\s*kind:\s*['\"]?Secret['\"]?\s*$", re.M)
_JSON_KIND_SECRET = re.compile(r"\"kind\"\s*:\s*\"Secret\"")
_YAML_DATA_HEADER = re.compile(r"^([ \t]*)(data|stringData):[ \t]*$")
_JSON_DATA_BLOCK = re.compile(r"(\"(?:data|stringData)\"\s*:\s*\{)([^{}]*)(\})")
_JSON_STRING_VALUE = re.compile(r"(\"[^\"]+\"\s*:\s*)\"[^\"]*\"")
REDACTED_SECRET = "[REDACTED_SECRET]"


def _redact_yaml_secret_data(text: str) -> str:
    lines = text.split("\n")
    out = []
    block_indent = None
    for line in lines:
        if block_indent is not None:
            indent = len(line) - len(line.lstrip())
            if line.strip() and indent > block_indent:
                key, sep, _value = line.partition(":")
                out.append(f"{key}{sep} {REDACTED_SECRET}" if sep else line)
                continue
            block_indent = None
        header = _YAML_DATA_HEADER.match(line)
        if header:
            block_indent = len(header.group(1))
        out.append(line)
    return "\n".join(out)


def redact_secret_material(text: str) -> str:
    """Remove Secret values and secret-named env values; keep key names for diagnosis."""
    if _YAML_KIND_SECRET.search(text):
        text = _redact_yaml_secret_data(text)
    if _JSON_KIND_SECRET.search(text):
        text = _JSON_DATA_BLOCK.sub(
            lambda m: m.group(1) + _JSON_STRING_VALUE.sub(rf'\1"{REDACTED_SECRET}"', m.group(2)) + m.group(3),
            text,
        )
    text = _SECRET_ENV_JSON.sub(rf"\1{REDACTED_SECRET}", text)
    text = _SECRET_ENV_YAML.sub(rf"\1{REDACTED_SECRET}", text)
    text = _SECRET_ENV_ASSIGN.sub(rf"\1={REDACTED_SECRET}", text)
    return text


def scrub_text(text: str) -> str:
    if not text or not isinstance(text, str):
        return text
    result = redact_secret_material(text)
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def scrub_value(value: Any) -> Any:
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return scrub_dict(value)
    if isinstance(value, list):
        return [scrub_value(v) for v in value]
    return value


def scrub_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return data
    return {k: scrub_value(v) for k, v in data.items()}


def scrub_messages(messages: List[Dict]) -> List[Dict]:
    """Scrub PII from Claude message history."""
    scrubbed = []
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            scrubbed.append({**msg, "content": scrub_text(content)})
        elif isinstance(content, list):
            new_blocks = []
            for block in content:
                if isinstance(block, dict):
                    b = dict(block)
                    if "text" in b:
                        b["text"] = scrub_text(b["text"])
                    if "content" in b and isinstance(b["content"], str):
                        b["content"] = scrub_text(b["content"])
                    new_blocks.append(b)
                elif hasattr(block, "text"):
                    new_blocks.append(block)
                else:
                    new_blocks.append(block)
            scrubbed.append({**msg, "content": new_blocks})
        else:
            scrubbed.append(msg)
    return scrubbed
