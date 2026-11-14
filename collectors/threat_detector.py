"""
Deterministic threat detection over alert text and logs (#166).

Scans the evidence the agent already has (alert name and annotations, raw
logs, Loki ``alert_logs``, CI and pod logs) for signs of an active attack, with
no LLM involved, so a prompt-injected log line cannot talk it out of a finding.

Each finding carries a MITRE ATT&CK technique, a severity, up to a few
evidence lines (PII-scrubbed, truncated) and extracted indicators. All patterns
are bounded (no nested or unbounded repetition) and lines are length-capped.
"""
from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import unquote_plus

from services.pii_scrubber import scrub_text

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

MAX_LINE_CHARS = 2000
MAX_LINES = 20000
MAX_EVIDENCE_LINES = 5
MAX_EVIDENCE_CHARS = 300
MAX_INDICATORS = 10

# Context keys never scanned: our own analysis output, and code-review diffs
# (code review has its own malware heuristics and must not be re-typed).
_SKIP_KEYS = {"threat_findings", "security_scan", "code_change", "heuristic_findings"}

_IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


# (rule id, title, technique, tactic, severity, pattern)
_LINE_RULES: List[Tuple[str, str, str, str, str, re.Pattern]] = [
    (
        "crypto_mining",
        "Cryptocurrency miner activity",
        "T1496",
        "Impact",
        "critical",
        _rx(
            r"\bxmrig\b|stratum\+(?:tcp|ssl|tls)://|\bcryptonight\b|\bminerd\b|\bcpuminer\b"
            r"|\bethminer\b|nicehash|minexmr|supportxmr|nanopool\.org|--donate-level"
            r"|\bkdevtmpfsi\b|\bkinsing\b"
        ),
    ),
    (
        "reverse_shell",
        "Reverse shell",
        "T1059",
        "Execution",
        "critical",
        _rx(
            r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,5}"
            r"|\bbash\s{1,5}-i\s{0,5}>&"
            r"|\bnc(?:at)?\s[^\n|;]{0,80}\s-(?:e|c)\s{1,5}/bin/(?:ba)?sh"
            r"|\bsocat\s[^\n]{0,120}exec:[^\n]{0,40}sh\b"
            r"|\bmkfifo\s{1,5}/tmp/\S{1,60}[^\n]{0,120}\|\s{0,5}(?:/bin/)?(?:ba)?sh\b"
            r"|\bpython[23]?(?:\.\d{1,2})?\s{1,5}-c\s{1,5}['\"][^\n]{0,200}socket[^\n]{0,200}subprocess"
            r"|\bperl\s{1,5}-e\s{1,5}['\"][^\n]{0,200}socket"
        ),
    ),
    (
        "container_shell",
        "Interactive shell or exec inside a container",
        "T1609",
        "Execution",
        "high",
        _rx(
            r"terminal shell in container|a shell was spawned in a container"
            r"|shell spawned by untrusted binary|\bpods/exec\b|\bpods/attach\b"
            r"|\bkubectl\s{1,5}exec\s[^\n]{0,120}(?:\s|^)-(?:it|ti)\b"
        ),
    ),
    (
        "privileged_workload",
        "Privileged or host-namespace workload started",
        "T1611",
        "Privilege Escalation",
        "high",
        _rx(
            r"launch privileged container|create privileged pod|create hostnetwork pod"
            r"|create sensitive mount pod|privileged container (?:started|launched)"
            r"|container escape|nsenter\s{1,5}--target\s{1,5}1\b"
        ),
    ),
    (
        "credential_access",
        "Access to credential files or tokens",
        "T1552",
        "Credential Access",
        "high",
        _rx(
            r"read sensitive file|search private keys or passwords"
            r"|\b(?:cat|less|more|head|tail|cp|scp|base64|strings|tar)\s[^\n]{0,120}"
            r"(?:/etc/shadow\b|\.aws/credentials\b|serviceaccount/token\b|\.ssh/id_(?:rsa|ed25519|ecdsa)\b"
            r"|\.kube/config\b|\.docker/config\.json\b)"
        ),
    ),
    (
        "download_execute",
        "Download piped straight into a shell",
        "T1105",
        "Command and Control",
        "high",
        _rx(r"\b(?:curl|wget)\s[^|\n]{0,300}\|\s{0,5}(?:sudo\s{1,5})?(?:ba|z|da)?sh\b"),
    ),
    (
        "defense_evasion",
        "Shell history or log tampering",
        "T1070",
        "Defense Evasion",
        "high",
        _rx(
            r"\bhistory\s{1,5}-c\b|\bunset\s{1,5}HISTFILE\b|HISTFILE=/dev/null"
            r"|\bshred\s[^\n]{0,80}(?:/var/log/|bash_history)"
            r"|\brm\s{1,5}-(?:rf|fr|f)\s{1,5}[^\n]{0,40}\.bash_history"
            r"|clear log activities|delete or rename shell history"
        ),
    ),
    (
        "cloud_threat_finding",
        "Cloud provider threat finding",
        "T1078",
        "Initial Access",
        "high",
        _rx(
            r"\b(?:UnauthorizedAccess|CryptoCurrency|Backdoor|Trojan|PenTest|Recon|Exfiltration"
            r"|Impact|Persistence|PrivilegeEscalation|DefenseEvasion|CredentialAccess|Discovery"
            r"|Execution|InitialAccess|Stealth|Policy|Behavior):[A-Za-z0-9]{1,40}/[A-Za-z0-9.!_\-]{1,80}"
        ),
    ),
]

# ── Injection attacks against applications (#166 follow-up) ─────────────────
# Matched on the URL-decoded line (twice, for double encoding). A single probe
# is "medium" (internet scanners send these constantly); repeated attempts from
# one source become "high", which makes the incident a security incident.
_HTTP_REQUEST = _rx(r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s{1,5}\S|\bHTTP/\d|[?&][A-Za-z0-9_.\-]{1,40}=")

# (rule id, title, technique, tactic, pattern, requires an HTTP request line)
_INJECTION_RULES: List[Tuple[str, str, str, str, re.Pattern, bool]] = [
    (
        "sql_injection",
        "SQL injection attempt",
        "T1190",
        "Initial Access",
        _rx(
            r"\bunion(?:\s|/\*[^*]{0,20}\*/){1,5}(?:all\s{1,5})?select\b"
            r"|'\s{0,5}(?:or|and)\s{1,5}['\"]?\w{1,20}['\"]?\s{0,5}=\s{0,5}['\"]?\w{1,20}"
            r"|\b(?:sleep|pg_sleep|benchmark)\s{0,5}\(\s{0,5}\d"
            r"|\bwaitfor\s{1,5}delay\s{1,5}'"
            r"|\bxp_cmdshell\b|\binformation_schema\.(?:tables|columns)\b"
            r"|;\s{0,5}drop\s{1,5}table\b"
        ),
        True,
    ),
    (
        "command_injection",
        "OS command injection attempt",
        "T1190",
        "Initial Access",
        _rx(
            r"(?:;|\||&&|\$\(|`)\s{0,5}(?:cat\s{1,5}/etc/|id\b|whoami\b|uname\s{1,5}-a\b"
            r"|wget\s|curl\s|nc\s|/bin/(?:ba)?sh\b|ping\s{1,5}-c\s)"
        ),
        True,
    ),
    (
        "log4shell",
        "JNDI lookup injection (Log4Shell)",
        "T1190",
        "Initial Access",
        _rx(
            r"\$\{jndi:(?:ldaps?|rmi|dns|iiop|nis|nds|corba|https?)://"
            r"|\$\{\$\{(?:lower|upper|::-|env:[a-z_]{0,30}:-)[^}]{0,10}\}"
        ),
        False,
    ),
    (
        "path_traversal",
        "Path traversal attempt",
        "T1190",
        "Initial Access",
        _rx(
            r"(?:\.\./|\.\.\\){2,8}(?:etc/(?:passwd|shadow|hosts)\b|windows/win\.ini|proc/self/environ|boot\.ini)"
            r"|[?&][A-Za-z0-9_.\-]{1,40}=[^&\s]{0,100}/etc/passwd\b"
        ),
        True,
    ),
    (
        "ssrf_metadata",
        "Server-side request forgery to cloud metadata",
        "T1552",
        "Credential Access",
        _rx(
            r"[?&=][^\s]{0,200}(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200"
            r"|fd00:ec2::254)"
        ),
        True,
    ),
    (
        "xss",
        "Cross-site scripting attempt",
        "T1059.007",
        "Execution",
        _rx(
            r"<script\b|\bjavascript:|\bon(?:error|load|mouseover|focus)\s{0,5}="
            r"|<svg[^>]{0,40}\bon[a-z]{1,15}\s{0,5}="
        ),
        True,
    ),
    (
        "template_injection",
        "Server-side template injection attempt",
        "T1190",
        "Initial Access",
        _rx(
            r"\{\{\s{0,3}\d{1,3}\s{0,3}\*\s{0,3}\d{1,3}\s{0,3}\}\}|\$\{\d{1,3}\*\d{1,3}\}"
            r"|__globals__|__subclasses__|__builtins__"
        ),
        True,
    ),
]

# ── Prompt injection aimed at this agent (#118) ─────────────────────────────
_PROMPT_INJECTION = _rx(
    r"\b(?:ignore|disregard|forget|override)\s{1,5}(?:all\s{1,5}|any\s{1,5})?(?:of\s{1,5})?(?:the\s{1,5}|your\s{1,5})?"
    r"(?:previous|prior|above|earlier|preceding|system|original)\s{1,5}(?:instructions|prompts?|rules|directions|context)"
    r"|\byou\s{1,5}are\s{1,5}now\s{1,5}(?:a|an)\s{1,5}(?:different|new|unrestricted|helpful|ai|assistant|agent|developer)"
    r"|\bnew\s{1,5}(?:system\s{1,5})?instructions?\s{0,3}:"
    r"|<\|(?:im_start|im_end|system|endoftext)\|>|</?(?:system|assistant|instructions?)>"
    r"|\b(?:system|assistant)\s{0,3}:\s{0,3}(?:you\s|ignore\b|run\b|call\b|execute\b|approve\b)"
    r"|\b(?:call|use|invoke|run|execute)\s{1,5}(?:the\s{1,5})?(?:run_shell_command|run_kubectl|apply_k8s_manifest"
    r"|rollback_deployment|post_code_review|create_cicd_pr|create_github_pr|restart_nginx|apply_nginx_config"
    r"|helm_upgrade|helm_rollback|sync_argocd_app|cleanup_stale_logs|update_status_page)\b"
    r"|\b(?:approve|merge)\s{1,5}this\s{1,5}(?:pr|pull\s{1,5}request|merge\s{1,5}request|change)\b[^\n]{0,40}"
    r"\b(?:ai|agent|bot|reviewer|assistant|llm)\b"
    r"|\b(?:ai|agent|bot|assistant|llm)\b[^\n]{0,40}\b(?:must|should|please)\s{1,5}(?:approve|merge|ignore|run|execute)\b"
    r"|\bdo\s{1,5}not\s{1,5}(?:tell|inform|notify|alert|mention\s{1,5}this\s{1,5}to)\s{1,5}(?:the\s{1,5})?"
    r"(?:user|team|human|operator|anyone|security)"
)
# Zero-width, bidi-override and Unicode tag characters used to hide instructions.
# (ZWJ U+200D and BOM U+FEFF are excluded: emoji and file headers use them.)
_HIDDEN_UNICODE = re.compile("[\u200b\u200c\u200e\u200f\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")

# GuardDuty-style finding types whose category implies critical severity.
_CRITICAL_CLOUD_CATEGORIES = ("cryptocurrency:", "backdoor:", "trojan:")

_AUTH_FAILURE = _rx(
    r"failed password|invalid user|authentication failure|failed publickey"
    r"|maximum authentication attempts|connection closed by authenticating user"
    r"|login failed|failed login"
)
_AUTH_SUCCESS = _rx(r"accepted (?:password|publickey|keyboard-interactive)")


def injection_threshold() -> int:
    try:
        return max(2, int(os.getenv("THREAT_INJECTION_THRESHOLD", "5")))
    except ValueError:
        return 5


def brute_force_threshold() -> int:
    try:
        return max(2, int(os.getenv("THREAT_BRUTE_FORCE_THRESHOLD", "10")))
    except ValueError:
        return 10


def _iter_strings(value: Any, key: str = "", depth: int = 0) -> Iterator[str]:
    if depth > 6 or key in _SKIP_KEYS:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _iter_strings(v, str(k), depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item, key, depth + 1)


def _iter_lines(texts: Iterable[str]) -> Iterator[str]:
    emitted = 0
    for text in texts:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            yield line[:MAX_LINE_CHARS]
            emitted += 1
            if emitted >= MAX_LINES:
                return


def _visible(text: str) -> str:
    """Show hidden characters as \\uXXXX so reviewers can see them."""
    return _HIDDEN_UNICODE.sub(lambda m: "\\u%04x" % ord(m.group(0)), text)


def _evidence(lines: List[str]) -> List[str]:
    out = []
    for line in lines[:MAX_EVIDENCE_LINES]:
        cleaned = _visible(scrub_text(line))
        out.append(cleaned if len(cleaned) <= MAX_EVIDENCE_CHARS else cleaned[:MAX_EVIDENCE_CHARS] + "…")
    return out


def _ips(lines: List[str]) -> List[str]:
    found: List[str] = []
    for line in lines:
        for ip in _IPV4.findall(line):
            if ip not in found and not ip.startswith(("127.", "0.")):
                found.append(ip)
            if len(found) >= MAX_INDICATORS:
                return found
    return found


def _finding(rule_id, title, technique, tactic, severity, lines, extra=None) -> Dict[str, Any]:
    finding = {
        "rule": rule_id,
        "title": title,
        "mitre_technique": technique,
        "mitre_tactic": tactic,
        "severity": severity,
        "count": len(lines),
        "evidence": _evidence(lines),
        "indicators": {"ips": _ips(lines)},
    }
    if extra:
        finding.update(extra)
    return finding


def _brute_force(lines: List[str]) -> List[Dict[str, Any]]:
    threshold = brute_force_threshold()
    failures_by_ip: Dict[str, List[str]] = defaultdict(list)
    successes_by_ip: Dict[str, List[str]] = defaultdict(list)
    for line in lines:
        is_failure = bool(_AUTH_FAILURE.search(line))
        is_success = not is_failure and bool(_AUTH_SUCCESS.search(line))
        if not (is_failure or is_success):
            continue
        ips = _IPV4.findall(line) or ["unknown"]
        target = failures_by_ip if is_failure else successes_by_ip
        target[ips[0]].append(line)

    findings = []
    for ip, failures in failures_by_ip.items():
        if len(failures) < threshold:
            continue
        compromised = ip != "unknown" and successes_by_ip.get(ip)
        if compromised:
            findings.append(
                _finding(
                    "brute_force_success",
                    "Brute force followed by a successful login",
                    "T1110",
                    "Credential Access",
                    "critical",
                    failures[-2:] + successes_by_ip[ip][:3],
                    {"failed_attempts": len(failures), "source_ip": ip},
                )
            )
        else:
            findings.append(
                _finding(
                    "brute_force",
                    "Authentication brute force",
                    "T1110",
                    "Credential Access",
                    "high",
                    failures,
                    {"failed_attempts": len(failures), "source_ip": ip},
                )
            )
    return findings


def _decoded(line: str) -> str:
    try:
        return unquote_plus(unquote_plus(line))
    except Exception:
        return line


def _injection_findings(lines: List[str]) -> List[Dict[str, Any]]:
    threshold = injection_threshold()
    hits: Dict[str, List[str]] = defaultdict(list)
    per_source: Dict[str, Counter] = defaultdict(Counter)
    for line in lines:
        decoded = _decoded(line)
        is_request = bool(_HTTP_REQUEST.search(line) or _HTTP_REQUEST.search(decoded))
        for rule_id, _title, _technique, _tactic, pattern, needs_request in _INJECTION_RULES:
            if needs_request and not is_request:
                continue
            if pattern.search(decoded):
                hits[rule_id].append(line)
                source = (_IPV4.findall(line) or ["unknown"])[0]
                per_source[rule_id][source] += 1

    findings = []
    for rule_id, title, technique, tactic, _pattern, _needs in _INJECTION_RULES:
        if rule_id not in hits:
            continue
        top_source, top_count = per_source[rule_id].most_common(1)[0]
        sustained = top_count >= threshold
        findings.append(
            _finding(
                rule_id,
                title + (" (sustained)" if sustained else ""),
                technique,
                tactic,
                "high" if sustained else "medium",
                hits[rule_id],
                {"attempts": len(hits[rule_id]), "top_source": top_source, "top_source_attempts": top_count},
            )
        )
    return findings


def _prompt_injection_findings(lines: List[str]) -> List[Dict[str, Any]]:
    instructions = [line for line in lines if _PROMPT_INJECTION.search(line)]
    hidden = [line for line in lines if _HIDDEN_UNICODE.search(line)]
    findings = []
    if instructions:
        findings.append(
            _finding(
                "prompt_injection",
                "Instructions aimed at the AI agent embedded in incident data",
                "AML.T0051",
                "LLM Prompt Injection",
                "high",
                instructions,
            )
        )
    if hidden:
        findings.append(
            _finding(
                "hidden_unicode",
                "Invisible or bidi-override characters in incident data",
                "AML.T0051",
                "LLM Prompt Injection",
                "high",
                hidden,
            )
        )
    return findings


def detect_threats_in_lines(lines: List[str]) -> List[Dict[str, Any]]:
    matches: Dict[str, List[str]] = defaultdict(list)
    for line in lines:
        for rule_id, *_rest, pattern in _LINE_RULES:
            if pattern.search(line):
                matches[rule_id].append(line)

    findings = []
    for rule_id, title, technique, tactic, severity, _pattern in _LINE_RULES:
        hits = matches.get(rule_id)
        if not hits:
            continue
        if rule_id == "cloud_threat_finding" and any(
            category in hit.lower() for hit in hits for category in _CRITICAL_CLOUD_CATEGORIES
        ):
            severity = "critical"
        findings.append(_finding(rule_id, title, technique, tactic, severity, hits))
    findings.extend(_brute_force(lines))
    findings.extend(_injection_findings(lines))
    findings.extend(_prompt_injection_findings(lines))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["rule"]))
    return findings


def summarize(findings: List[Dict[str, Any]], scanned_lines: int) -> Dict[str, Any]:
    highest: Optional[str] = None
    for finding in findings:
        if highest is None or SEVERITY_ORDER[finding["severity"]] > SEVERITY_ORDER[highest]:
            highest = finding["severity"]
    return {
        "findings": findings,
        "total": len(findings),
        "highest_severity": highest,
        "techniques": sorted({f["mitre_technique"] for f in findings}),
        "scanned_lines": scanned_lines,
    }


def detect_threats(context: Dict[str, Any]) -> Dict[str, Any]:
    """Scan every string in an incident context (minus our own analysis output)."""
    lines = list(_iter_lines(_iter_strings(context)))
    return summarize(detect_threats_in_lines(lines), len(lines))


def detect_threats_in_text(text: str) -> Dict[str, Any]:
    """Scan arbitrary log text, e.g. output the model fetched with query_logs."""
    lines = list(_iter_lines([text or ""]))
    return summarize(detect_threats_in_lines(lines), len(lines))


PROMPT_INJECTION_RULES = ("prompt_injection", "hidden_unicode")

# Our own analysis output; never rescanned for prompt injection.
_OWN_OUTPUT_KEYS = {"threat_findings", "security_scan", "heuristic_findings", "prompt_injection"}


def _iter_all_strings(value: Any, key: str = "", depth: int = 0) -> Iterator[str]:
    if depth > 8 or key in _OWN_OUTPUT_KEYS:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _iter_all_strings(v, str(k), depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_all_strings(item, key, depth + 1)


def detect_prompt_injection(value: Any) -> List[Dict[str, Any]]:
    """Prompt-injection findings in any value, including code-review diffs and tool output."""
    lines = list(_iter_lines(_iter_all_strings(value)))
    return _prompt_injection_findings(lines)


def sanitize_untrusted(value: Any) -> Any:
    """Remove invisible and bidi-override characters before text reaches the model."""
    if isinstance(value, str):
        return _HIDDEN_UNICODE.sub("", value)
    if isinstance(value, dict):
        return {k: sanitize_untrusted(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_untrusted(v) for v in value]
    if isinstance(value, tuple):
        return tuple(sanitize_untrusted(v) for v in value)
    return value


def is_actionable(summary: Optional[Dict[str, Any]]) -> bool:
    """True when findings are severe enough to treat the incident as a security incident."""
    return bool(summary) and summary.get("highest_severity") in ("high", "critical")


def technique_counts(findings: List[Dict[str, Any]]) -> Counter:
    return Counter((f["mitre_technique"], f["severity"]) for f in findings)
