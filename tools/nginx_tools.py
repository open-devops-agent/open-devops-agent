"""
Nginx, wildcard TLS, and certbot helpers.

nginx -t must pass before reload/restart. A failed test is repaired by writing
a proposed config (under /etc/nginx only), re-testing, then reloading.
Wildcard / DNS-01 renews run when a certbot DNS plugin is configured.
"""
from __future__ import annotations

import base64
import os
import re
from typing import Callable, Optional

import structlog

from tools.safety import emergency_stop_block, is_emergency_stop_active

log = structlog.get_logger()

_NGINX_FILE_RE = re.compile(r"in\s+(/[^\s:]+):(\d+)")
_ALLOWED_CONFIG_PREFIXES = ("/etc/nginx/",)
_DNS_PLUGINS = {
    "cloudflare": ("--dns-cloudflare", "--dns-cloudflare-credentials"),
    "route53": ("--dns-route53", None),
    "google": ("--dns-google", "--dns-google-credentials"),
    "digitalocean": ("--dns-digitalocean", "--dns-digitalocean-credentials"),
    "azure": ("--dns-azure", "--dns-azure-config"),
    "rfc2136": ("--dns-rfc2136", "--dns-rfc2136-credentials"),
    "linode": ("--dns-linode", "--dns-linode-credentials"),
}


class NginxTools:
    def __init__(self, runner: Optional[Callable] = None):
        self._runner = runner

    async def _run(self, command: str, host: Optional[str] = None) -> dict:
        if self._runner:
            return await self._runner(command, host)
        from tools.executor import SafeExecutor

        return await SafeExecutor().run(command, host=host)

    async def diagnose(self, host: Optional[str] = None) -> dict:
        config = await self._run("nginx -t", host)
        status = await self._run("systemctl is-active nginx 2>/dev/null || true", host)
        unit = await self._run("systemctl status nginx --no-pager -l | tail -40", host)
        journal = await self._run("journalctl -u nginx -n 40 --no-pager", host)
        certs = await self._run("certbot certificates 2>/dev/null || echo 'certbot not available'", host)

        config_ok = bool(config.get("success"))
        stderr = (config.get("stderr") or "") + "\n" + (config.get("stdout") or "")
        broken_file, broken_line = _nginx_error_location(stderr)
        file_content = None
        if broken_file:
            read = await self._run(f"cat {broken_file}", host)
            if read.get("success"):
                file_content = read.get("stdout")

        wildcard_issue = _looks_like_wildcard_or_dns_issue(stderr + "\n" + (certs.get("stdout") or ""))
        cert_issue = _looks_like_cert_issue(stderr + "\n" + (journal.get("stdout") or ""))
        dns_ready = bool(os.getenv("CERTBOT_DNS_PLUGIN", "").strip())

        alerts = []
        if not config_ok:
            alerts.append(
                "nginx -t failed — apply a config fix with apply_nginx_config, then restart"
            )
        if wildcard_issue and not dns_ready:
            alerts.append(
                "Wildcard/DNS-01 certificate detected and CERTBOT_DNS_PLUGIN is unset. "
                "Set CERTBOT_DNS_PLUGIN (and credentials) so renew_certificates can issue/renew."
            )
        if cert_issue:
            alerts.append("TLS/certificate error in nginx or certbot output — try renew_certificates")

        return {
            "host": host or "localhost",
            "config_ok": config_ok,
            "nginx_active": (status.get("stdout") or "").strip() == "active",
            "config": config,
            "broken_file": broken_file,
            "broken_line": broken_line,
            "broken_file_content": file_content,
            "status": unit.get("stdout"),
            "journal": journal.get("stdout"),
            "certificates": certs.get("stdout"),
            "dns_plugin_configured": dns_ready,
            "alerts": alerts,
            "alerted": bool(alerts),
            "passed": config_ok and not alerts,
        }

    async def apply_nginx_config(
        self,
        file_path: str,
        new_content: str,
        host: Optional[str] = None,
        reload_after: bool = True,
    ) -> dict:
        """Write a proposed nginx file, nginx -t, restore on failure, reload on success."""
        if is_emergency_stop_active():
            return emergency_stop_block("Agent emergency stop is active. Nginx config apply is disabled.")
        path = (file_path or "").strip()
        if not _allowed_nginx_path(path):
            return {
                "success": False,
                "blocked": True,
                "alerted": True,
                "message": f"Refusing to write {path!r} — only files under /etc/nginx/ are allowed.",
            }

        bak = f"{path}.agent-bak"
        await self._run(f"cp {path} {bak} 2>/dev/null || true", host)
        write = await self._run(_write_file_command(path, new_content), host)
        if not write.get("success"):
            await self._run(f"test -f {bak} && mv {bak} {path} || true", host)
            return {
                "success": False,
                "blocked": True,
                "alerted": True,
                "message": f"Failed to write {path}: {write.get('stderr') or write.get('error')}",
                "write": write,
            }

        test = await self._run("nginx -t", host)
        if not test.get("success"):
            await self._run(f"test -f {bak} && mv {bak} {path} || true", host)
            return {
                "success": False,
                "blocked": True,
                "alerted": True,
                "restored": True,
                "config": test,
                "message": "Proposed nginx config failed nginx -t; previous file restored.",
            }

        reload = None
        if reload_after:
            reload = await self._run("systemctl reload nginx", host)
            if not reload.get("success"):
                return {
                    "success": False,
                    "alerted": True,
                    "config_ok": True,
                    "reload": reload,
                    "message": "Config passed nginx -t but reload failed.",
                }
        return {
            "success": True,
            "path": path,
            "config_ok": True,
            "reloaded": bool(reload and reload.get("success")),
            "message": f"Applied {path} and nginx -t passed",
        }

    async def restart(
        self,
        host: Optional[str] = None,
        reload_only: bool = False,
        config_path: Optional[str] = None,
        config_content: Optional[str] = None,
    ) -> dict:
        if is_emergency_stop_active():
            return emergency_stop_block("Agent emergency stop is active. Nginx restart is disabled.")

        applied = None
        if config_path and config_content:
            applied = await self.apply_nginx_config(
                config_path, config_content, host=host, reload_after=False
            )
            if not applied.get("success"):
                return applied

        diagnosis = await self.diagnose(host)
        if not diagnosis["config_ok"]:
            return {
                "success": False,
                "blocked": True,
                "alerted": True,
                "alerts": diagnosis["alerts"],
                "diagnosis": diagnosis,
                "applied": applied,
                "message": (
                    "nginx -t failed. Use apply_nginx_config with a repaired file "
                    f"(broken file: {diagnosis.get('broken_file') or 'unknown'}), then restart."
                ),
            }

        command = "systemctl reload nginx" if reload_only else "systemctl restart nginx"
        result = await self._run(command, host)
        return {
            "success": bool(result.get("success")),
            "command": command,
            "result": result,
            "diagnosis": diagnosis,
            "applied": applied,
            "message": f"nginx {'reloaded' if reload_only else 'restarted'}"
            if result.get("success")
            else "nginx restart/reload failed",
        }

    async def renew_certificates(
        self,
        host: Optional[str] = None,
        dry_run: bool = True,
        domains: Optional[list] = None,
    ) -> dict:
        if is_emergency_stop_active() and not dry_run:
            return emergency_stop_block("Agent emergency stop is active. Certificate renew is disabled.")
        probe = await self._run("certbot certificates 2>/dev/null || echo 'certbot not available'", host)
        text = probe.get("stdout") or ""
        if "certbot not available" in text:
            return {
                "success": False,
                "alerted": True,
                "alerts": ["certbot is not installed on this host"],
                "message": "Cannot renew certificates. Alert a human to install/configure certbot.",
            }

        command, command_notes = _certbot_command(dry_run, domains, text)
        if command is None:
            return {
                "success": False,
                "alerted": True,
                "alerts": command_notes,
                "certificates": text,
                "message": command_notes[0] if command_notes else "Cannot renew certificates.",
            }

        result = await self._run(command, host)
        ok = bool(result.get("success"))
        combined = (result.get("stderr") or "") + "\n" + (result.get("stdout") or "")
        if not ok and _looks_like_wildcard_or_dns_issue(combined):
            return {
                "success": False,
                "alerted": True,
                "dry_run": dry_run,
                "command": command,
                "result": result,
                "alerts": [
                    "DNS-01 / wildcard renew failed. Check CERTBOT_DNS_PLUGIN, "
                    "CERTBOT_DNS_CREDENTIALS, and DNS API permissions."
                ],
                "certificates": text,
                "message": "certbot DNS-01 renew failed — see certbot output.",
            }

        reload = None
        if ok and not dry_run:
            test = await self._run("nginx -t", host)
            if test.get("success"):
                reload = await self._run("systemctl reload nginx", host)
            else:
                return {
                    "success": False,
                    "alerted": True,
                    "dry_run": dry_run,
                    "command": command,
                    "result": result,
                    "config": test,
                    "message": "Certificates renewed but nginx -t failed — config not reloaded.",
                }
        return {
            "success": ok,
            "dry_run": dry_run,
            "command": command,
            "result": result,
            "reload": reload,
            "certificates": text,
            "notes": command_notes,
            "message": "certbot dry-run passed"
            if dry_run and ok
            else ("certificates renewed and nginx reloaded" if ok else "certbot renew failed — alert on-call"),
            "alerted": not ok,
        }


def _allowed_nginx_path(path: str) -> bool:
    if not path.startswith("/") or ".." in path:
        return False
    return any(path.startswith(prefix) for prefix in _ALLOWED_CONFIG_PREFIXES)


def _nginx_error_location(text: str) -> tuple[Optional[str], Optional[int]]:
    match = _NGINX_FILE_RE.search(text or "")
    if not match:
        return None, None
    line = int(match.group(2)) if match.group(2).isdigit() else None
    return match.group(1), line


def _write_file_command(path: str, content: str) -> str:
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    return (
        "python3 -c \"import base64,pathlib; "
        f"pathlib.Path({path!r}).write_bytes(base64.b64decode({encoded!r}))\""
    )


def _certbot_command(
    dry_run: bool, domains: Optional[list], certificates_text: str
) -> tuple[Optional[str], list]:
    plugin = os.getenv("CERTBOT_DNS_PLUGIN", "").strip().lower()
    creds = os.getenv("CERTBOT_DNS_CREDENTIALS", "").strip()
    env_domains = [d.strip() for d in os.getenv("CERTBOT_WILDCARD_DOMAINS", "").split(",") if d.strip()]
    names = [d.strip() for d in (domains or []) if d] or env_domains
    notes = []
    dry = " --dry-run" if dry_run else ""
    extra = " --non-interactive --agree-tos"

    if plugin:
        flags = _DNS_PLUGINS.get(plugin)
        if not flags:
            return None, [f"Unknown CERTBOT_DNS_PLUGIN={plugin!r}. Use: {', '.join(sorted(_DNS_PLUGINS))}"]
        plugin_flag, cred_flag = flags
        cred_part = f" {cred_flag} {creds}" if cred_flag and creds else ""
        if cred_flag and not creds and plugin != "route53":
            return None, [
                f"CERTBOT_DNS_PLUGIN={plugin} needs CERTBOT_DNS_CREDENTIALS (path to the DNS API file)."
            ]
        if names:
            domain_flags = " ".join(f"-d {d}" for d in names)
            notes.append(f"DNS-01 via certbot {plugin_flag} for {', '.join(names)}")
            return f"certbot certonly{extra}{dry} {plugin_flag}{cred_part} {domain_flags}", notes
        notes.append(f"DNS-01 plugin {plugin} configured; using certbot renew (existing lineages)")
        return f"certbot renew{dry}{extra}", notes

    if _looks_like_wildcard_or_dns_issue(certificates_text) and names:
        return None, [
            "Wildcard/DNS-01 certificate needs CERTBOT_DNS_PLUGIN "
            "(cloudflare, route53, google, digitalocean, azure, rfc2136, linode)."
        ]

    notes.append("Using certbot renew (HTTP-01 or the authenticator stored in the renewal config)")
    return f"certbot renew{dry}{extra}", notes


def _looks_like_wildcard_or_dns_issue(text: str) -> bool:
    lowered = (text or "").lower()
    markers = (
        "wildcard",
        "dns-01",
        "dns challenge",
        "nxdomain",
        "could not find a challenge",
        "dns problem",
        "incorrect txt record",
    )
    return any(marker in lowered for marker in markers)


def _looks_like_cert_issue(text: str) -> bool:
    lowered = (text or "").lower()
    markers = (
        "ssl_error",
        "certificate expired",
        "certificate is expired",
        "no ssl certificate",
        "cannot load certificate",
        "pem_read",
        "key values mismatch",
        "ssl: error",
    )
    return any(marker in lowered for marker in markers)
