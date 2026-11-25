"""
Approval-gated containment for confirmed security incidents (#168).

Every action follows the same steps:

1. Validate the target strictly (names, key IDs, IP ranges) so nothing an
   attacker wrote into an alert can smuggle extra shell.
2. Capture evidence first with fixed read-only commands and store it with the
   incident (logs, describe output, key usage), before anything changes.
3. Build the exact change and its reverse, retain the change behind an approval
   reference and post it to Slack. Nothing runs until an allow-listed approver
   clicks Approve, whatever AUTO_APPLY says, and the emergency stop blocks it.
4. Record the action, its reverse and (for IP blocks) its expiry.

Nothing here deletes anything. Undoing an isolation or an IP block removes a
rule, which the executor never does, so the reverse command is recorded for a
human to run. Expired IP blocks produce a Slack reminder with that command.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import shlex
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog

from services.approval_store import CommandApprovalStore
from services.org_context import current_org_id
from tools.safety import emergency_stop_block, is_emergency_stop_active

log = structlog.get_logger()

_K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_AWS_USER = re.compile(r"^[\w+=,.@-]{1,64}$")
_AWS_KEY_ID = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
_GCP_SA = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z0-9-]+\.iam\.gserviceaccount\.com$")
_GCP_KEY_ID = re.compile(r"^[a-f0-9]{40}$")
_RESOURCE_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")
_LABEL = "devops-agent/quarantine"

MAX_BLOCK_HOURS = 24 * 30


class ContainmentError(ValueError):
    pass


def _check(pattern: re.Pattern, value: Any, what: str) -> str:
    value = str(value or "").strip()
    if not pattern.match(value):
        raise ContainmentError(f"invalid {what}")
    return value


def _protected_networks() -> List[ipaddress._BaseNetwork]:
    nets = []
    for item in os.getenv("CONTAINMENT_PROTECTED_CIDRS", "").split(","):
        item = item.strip()
        if item:
            try:
                nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                log.warning("invalid_protected_cidr", value=item)
    return nets


def _check_block_target(ip: str) -> ipaddress._BaseNetwork:
    try:
        net = ipaddress.ip_network(str(ip).strip(), strict=False)
    except ValueError:
        raise ContainmentError("invalid IP address or CIDR") from None
    min_prefix = 24 if net.version == 4 else 64
    if net.prefixlen < min_prefix:
        raise ContainmentError(f"range too broad: block at most a /{min_prefix}")
    if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
        raise ContainmentError("refusing to block a loopback, link-local, multicast or unspecified address")
    for protected in _protected_networks():
        if net.version == protected.version and net.overlaps(protected):
            raise ContainmentError(f"{net} overlaps protected range {protected} (CONTAINMENT_PROTECTED_CIDRS)")
    return net


def _isolation_policy(name: str, quarantine_id: str) -> str:
    return json.dumps({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "labels": {"app.kubernetes.io/managed-by": "devops-ai-agent"}},
        "spec": {
            "podSelector": {"matchLabels": {_LABEL: quarantine_id}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    })


class ContainmentTools:
    def __init__(self, executor, notifier=None, incident_store=None):
        self.executor = executor
        self.notifier = notifier
        self.incident_store = incident_store

    # ── shared steps ─────────────────────────────────────────────────────────

    async def _evidence(self, incident_id: str, action_id: str, commands: Dict[str, str]) -> dict:
        """Run fixed read-only commands and store their output with the incident."""
        evidence: Dict[str, Any] = {"captured_at": datetime.now(timezone.utc).isoformat()}
        for label, cmd in commands.items():
            try:
                result = await self.executor.run(cmd)
                evidence[label] = {
                    "command": cmd,
                    "success": result.get("success"),
                    "stdout": result.get("stdout"),
                    "stderr": result.get("stderr") or result.get("error"),
                }
            except Exception as exc:  # evidence is best effort, but recorded
                evidence[label] = {"command": cmd, "success": False, "error": str(exc)}
        key = None
        if self.incident_store is not None:
            key = self.incident_store.save_log(
                current_org_id(), incident_id, f"evidence-{action_id}.json", evidence
            )
        return {"key": key, "items": {k: v.get("success") for k, v in evidence.items() if isinstance(v, dict)}}

    async def _propose(
        self,
        *,
        action: str,
        incident_id: str,
        description: str,
        commands: List[str],
        reverse: List[str],
        evidence_commands: Dict[str, str],
        dry_run: bool,
        extra: Optional[dict] = None,
        expires_at: Optional[str] = None,
    ) -> dict:
        if is_emergency_stop_active():
            return emergency_stop_block(f"Agent emergency stop is active. `{action}` is disabled.")
        action_id = f"{action}-{uuid4().hex[:8]}"
        change = " && ".join(commands)
        proposal = {
            "action": action,
            "action_id": action_id,
            "description": description,
            "change": commands,
            "reverse": reverse,
            "reverse_note": "Run by a human: the agent never removes rules or deletes resources.",
            **(extra or {}),
        }
        if expires_at:
            proposal["expires_at"] = expires_at
        if dry_run:
            return {"dry_run": True, "requires_approval": True, **proposal}

        proposal["evidence"] = await self._evidence(incident_id, action_id, evidence_commands)
        try:
            reference = CommandApprovalStore().retain(change)
        except (RuntimeError, ValueError) as exc:
            return {"success": False, "blocked": True, "error": f"Could not request approval: {exc}", **proposal}
        encoded = base64.b64encode(reference.encode()).decode()
        if self.notifier is not None:
            text = (
                f"🛡️ Containment for `{incident_id}`: {description}\n"
                f"Change:\n```{chr(10).join(commands)}```\n"
                f"Reverse (manual):\n```{chr(10).join(reverse)}```"
            )
            if expires_at:
                text += f"\nExpires: {expires_at} (you'll get a reminder)"
            await self.notifier.send_approval_request(text, reference, encoded)

        record = {
            **proposal,
            "incident_id": incident_id,
            "org_id": current_org_id(),
            "approval_reference": reference,
            "status": "pending_approval",
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }
        if self.incident_store is not None:
            self.incident_store.save_log(current_org_id(), incident_id, f"containment-{action_id}.json", record)
            if expires_at:
                storage = self.incident_store.storage
                storage.put_json(
                    storage.org_prefix(current_org_id(), "containment_expiry", f"{action_id}.json"), record
                )
        log.info("containment_requested", action=action, action_id=action_id, incident_id=incident_id)
        return {
            "blocked": True,
            "requires_approval": True,
            "command": reference,
            "approval_payload": encoded,
            "message": f"Evidence saved. Containment approval sent to Slack: {description}. Nothing has changed yet.",
            **proposal,
        }

    # ── actions ──────────────────────────────────────────────────────────────

    async def isolate_pod(self, incident_id: str, namespace: str, pod: str, dry_run: bool = False) -> dict:
        try:
            ns = _check(_K8S_NAME, namespace, "namespace")
            name = _check(_K8S_NAME, pod, "pod name")
        except ContainmentError as exc:
            return {"success": False, "error": str(exc)}
        quarantine_id = uuid4().hex[:12]
        policy_name = f"agent-isolate-{quarantine_id}"
        manifest = base64.b64encode(_isolation_policy(policy_name, quarantine_id).encode()).decode()
        q_ns, q_pod = shlex.quote(ns), shlex.quote(name)
        commands = [
            f"kubectl label pod {q_pod} -n {q_ns} {_LABEL}={quarantine_id} --overwrite",
            f"printf %s {manifest} | base64 --decode | kubectl apply -n {q_ns} -f -",
        ]
        reverse = [
            f"kubectl delete networkpolicy {policy_name} -n {q_ns}",
            f"kubectl label pod {q_pod} -n {q_ns} {_LABEL}-",
        ]
        return await self._propose(
            action="isolate_pod",
            incident_id=incident_id,
            description=f"isolate pod `{ns}/{name}` with a deny-all NetworkPolicy (pod keeps running for forensics)",
            commands=commands,
            reverse=reverse,
            evidence_commands={
                "pod_yaml": f"kubectl get pod {q_pod} -n {q_ns} -o yaml",
                "describe": f"kubectl describe pod {q_pod} -n {q_ns}",
                "logs": f"kubectl logs {q_pod} -n {q_ns} --all-containers --timestamps --tail=2000",
                "previous_logs": f"kubectl logs {q_pod} -n {q_ns} --all-containers --previous --tail=500",
                "events": f"kubectl get events -n {q_ns} --field-selector involvedObject.name={q_pod}",
            },
            dry_run=dry_run,
            extra={
                "target": {"namespace": ns, "pod": name},
                "network_policy": policy_name,
                "note": "Needs a CNI that enforces NetworkPolicy (Calico, Cilium, …).",
            },
        )

    async def cordon_node(self, incident_id: str, node: str, dry_run: bool = False) -> dict:
        try:
            name = _check(_K8S_NAME, node, "node name")
        except ContainmentError as exc:
            return {"success": False, "error": str(exc)}
        q = shlex.quote(name)
        return await self._propose(
            action="cordon_node",
            incident_id=incident_id,
            description=f"cordon node `{name}` (no new pods; running pods are not drained)",
            commands=[f"kubectl cordon {q}"],
            reverse=[f"kubectl uncordon {q}"],
            evidence_commands={
                "describe": f"kubectl describe node {q}",
                "pods": f"kubectl get pods -A -o wide --field-selector spec.nodeName={q}",
            },
            dry_run=dry_run,
            extra={"target": {"node": name}},
        )

    async def disable_access_key(
        self,
        incident_id: str,
        provider: str,
        key_id: str,
        principal: str,
        dry_run: bool = False,
    ) -> dict:
        provider = (provider or "").lower()
        try:
            if provider == "aws":
                key = _check(_AWS_KEY_ID, key_id, "AWS access key ID")
                user = _check(_AWS_USER, principal, "IAM user name")
                issued_before = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                deny_sessions = base64.b64encode(json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Deny", "Action": "*", "Resource": "*",
                        "Condition": {"DateLessThan": {"aws:TokenIssueTime": issued_before}},
                    }],
                }).encode()).decode()
                q_user, q_key = shlex.quote(user), shlex.quote(key)
                commands = [
                    f"aws iam update-access-key --user-name {q_user} --access-key-id {q_key} --status Inactive",
                    # Revoke temporary credentials already issued from this user.
                    f"aws iam put-user-policy --user-name {q_user} --policy-name AgentRevokeOlderSessions "
                    f"--policy-document \"$(printf %s {deny_sessions} | base64 --decode)\"",
                ]
                reverse = [
                    f"aws iam update-access-key --user-name {q_user} --access-key-id {q_key} --status Active",
                    f"aws iam delete-user-policy --user-name {q_user} --policy-name AgentRevokeOlderSessions",
                ]
                evidence = {
                    "keys": f"aws iam list-access-keys --user-name {q_user}",
                    "last_used": f"aws iam get-access-key-last-used --access-key-id {q_key}",
                    "user_policies": f"aws iam list-user-policies --user-name {q_user}",
                }
                target = {"provider": "aws", "user": user, "access_key_id": key}
            elif provider == "gcp":
                key = _check(_GCP_KEY_ID, key_id, "GCP service account key ID")
                sa = _check(_GCP_SA, principal, "service account email")
                q_sa, q_key = shlex.quote(sa), shlex.quote(key)
                commands = [f"gcloud iam service-accounts keys disable {q_key} --iam-account {q_sa}"]
                reverse = [f"gcloud iam service-accounts keys enable {q_key} --iam-account {q_sa}"]
                evidence = {"keys": f"gcloud iam service-accounts keys list --iam-account {q_sa}"}
                target = {"provider": "gcp", "service_account": sa, "key_id": key}
            else:
                return {
                    "success": False,
                    "error": "provider must be aws or gcp (Azure secrets can only be deleted: rotate them manually)",
                }
        except ContainmentError as exc:
            return {"success": False, "error": str(exc)}
        return await self._propose(
            action="disable_access_key",
            incident_id=incident_id,
            description=f"disable {provider.upper()} key `{key}` of `{principal}`",
            commands=commands,
            reverse=reverse,
            evidence_commands=evidence,
            dry_run=dry_run,
            extra={"target": target},
        )

    async def block_ip(
        self,
        incident_id: str,
        ip: str,
        provider: str,
        resource_id: str,
        expires_hours: float = 24,
        rule_number: Optional[int] = None,
        dry_run: bool = False,
    ) -> dict:
        provider = (provider or "").lower()
        try:
            net = _check_block_target(ip)
            resource = _check(_RESOURCE_ID, resource_id, "resource ID")
            hours = float(expires_hours)
            if not 0 < hours <= MAX_BLOCK_HOURS:
                raise ContainmentError(f"expires_hours must be between 0 and {MAX_BLOCK_HOURS}")
        except (ContainmentError, TypeError, ValueError) as exc:
            return {"success": False, "error": str(exc)}
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
        cidr = str(net)
        tag = uuid4().hex[:8]
        q_res = shlex.quote(resource)
        if provider == "aws":
            # NACLs evaluate the lowest rule number first; keep deny rules early.
            number = int(rule_number) if rule_number else 10 + int(tag, 16) % 80
            flag = "--ipv6-cidr-block" if net.version == 6 else "--cidr-block"
            commands = [
                f"aws ec2 create-network-acl-entry --network-acl-id {q_res} --ingress --rule-number {number} "
                f"--protocol -1 --rule-action deny {flag} {cidr}"
            ]
            reverse = [f"aws ec2 delete-network-acl-entry --network-acl-id {q_res} --ingress --rule-number {number}"]
            evidence = {"acl": f"aws ec2 describe-network-acls --network-acl-ids {q_res}"}
        elif provider == "gcp":
            name = f"agent-block-{tag}"
            commands = [
                f"gcloud compute firewall-rules create {name} --network {q_res} --direction INGRESS "
                f"--action DENY --rules all --priority 100 --source-ranges {cidr} "
                f"--description {shlex.quote(f'devops-ai-agent {incident_id} expires {expires_at}')}"
            ]
            reverse = [f"gcloud compute firewall-rules update {name} --disabled"]
            evidence = {"rules": f"gcloud compute firewall-rules list --filter network~{q_res}"}
        elif provider == "azure":
            if "/" not in resource:
                return {"success": False, "error": "azure resource_id must be <resource-group>/<nsg-name>"}
            group, nsg = (shlex.quote(p) for p in resource.split("/", 1))
            name = f"agent-block-{tag}"
            priority = int(rule_number) if rule_number else 100 + int(tag, 16) % 100
            commands = [
                f"az network nsg rule create -g {group} --nsg-name {nsg} -n {name} --priority {priority} "
                f"--direction Inbound --access Deny --protocol '*' --source-address-prefixes {cidr} "
                f"--destination-port-ranges '*'"
            ]
            reverse = [f"az network nsg rule delete -g {group} --nsg-name {nsg} -n {name}"]
            evidence = {"rules": f"az network nsg rule list -g {group} --nsg-name {nsg} -o table"}
        else:
            return {"success": False, "error": "provider must be aws (network ACL), gcp (VPC network) or azure (rg/nsg)"}
        return await self._propose(
            action="block_ip",
            incident_id=incident_id,
            description=f"block `{cidr}` on {provider.upper()} `{resource}` for {hours:g}h",
            commands=commands,
            reverse=reverse,
            evidence_commands=evidence,
            dry_run=dry_run,
            extra={"target": {"provider": provider, "cidr": cidr, "resource": resource}},
            expires_at=expires_at,
        )


async def remind_expired_blocks(storage, notifier, org_id: str, now: Optional[datetime] = None) -> int:
    """Post a Slack reminder (with the reverse command) for each expired IP block, once."""
    now = now or datetime.now(timezone.utc)
    sent = 0
    for key in storage.list_keys(storage.org_prefix(org_id, "containment_expiry")):
        record = storage.get_json(key)
        if not isinstance(record, dict) or record.get("reminded"):
            continue
        try:
            expires = datetime.fromisoformat(record["expires_at"])
        except (KeyError, ValueError, TypeError):
            continue
        if expires > now:
            continue
        reverse = "\n".join(record.get("reverse") or [])
        await notifier.send_message(
            f"⏰ IP block `{record.get('action_id')}` for incident `{record.get('incident_id')}` expired at "
            f"{record['expires_at']}. If it was approved and is still wanted, extend it; otherwise remove it:\n"
            f"```{reverse}```"
        )
        record["reminded"] = now.isoformat()
        storage.put_json(key, record)
        sent += 1
    return sent
