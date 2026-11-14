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

# GuardDuty-style finding types whose category implies critical severity.
_CRITICAL_CLOUD_CATEGORIES = ("cryptocurrency:", "backdoor:", "trojan:")

_AUTH_FAILURE = _rx(
    r"failed password|invalid user|authentication failure|failed publickey"
    r"|maximum authentication attempts|connection closed by authenticating user"
    r"|login failed|failed login"
)
_AUTH_SUCCESS = _rx(r"accepted (?:password|publickey|keyboard-interactive)")


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


def _evidence(lines: List[str]) -> List[str]:
    out = []
    for line in lines[:MAX_EVIDENCE_LINES]:
        cleaned = scrub_text(line)
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


def is_actionable(summary: Optional[Dict[str, Any]]) -> bool:
    """True when findings are severe enough to treat the incident as a security incident."""
    return bool(summary) and summary.get("highest_severity") in ("high", "critical")


def technique_counts(findings: List[Dict[str, Any]]) -> Counter:
    return Counter((f["mitre_technique"], f["severity"]) for f in findings)
